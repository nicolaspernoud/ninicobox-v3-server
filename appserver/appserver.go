/*

This package is based upon https://github.com/nf/webfront (Copyright 2011 Google Inc.)

*/

package appserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"../security"
	"../types"
)

var port int
var frameSource string
var mainHostName string

// Server implements an http.Handler that acts as either a reverse proxy or a simple file server, as determined by a rule set.
type Server struct {
	mu   sync.RWMutex // guards the fields below
	last time.Time
	apps []*app
}

type app struct {
	types.App
	handler http.Handler
}

// NewServer constructs a Server that reads apps from file
func NewServer(file string, portFromMain int, frameSourceFromMain string, mainHostNameFromMain string) (*Server, error) {
	port = portFromMain
	frameSource = frameSourceFromMain
	mainHostName = mainHostNameFromMain
	s := new(Server)
	if err := s.LoadApps(file); err != nil {
		return nil, err
	}
	return s, nil
}

// ServeHTTP matches the Request with a app and, if found, serves the request with the app's handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h := s.handler(r); h != nil {
		h.ServeHTTP(w, r)
		return
	}
	http.Error(w, "Not found.", http.StatusNotFound)
}

// handler returns the appropriate Handler for the given Request,
// or nil if none found.
func (s *Server) handler(req *http.Request) http.Handler {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h := req.Host
	// Some clients include a port in the request host; strip it.
	if i := strings.Index(h, ":"); i >= 0 {
		h = h[:i]
	}
	for _, r := range s.apps {
		if h == r.Host || strings.HasSuffix(h, "."+r.Host) {
			return r.handler
		}
	}
	return nil
}

// LoadApps tests whether file has been modified since its last invocation and, if so, loads the app set from file.
func (s *Server) LoadApps(file string) error {
	fi, err := os.Stat(file)
	if err != nil {
		return err
	}
	mtime := fi.ModTime()
	if !mtime.After(s.last) && s.apps != nil {
		return nil // no change
	}
	apps, err := parseApps(file)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.last = mtime
	s.apps = apps
	s.mu.Unlock()
	return nil
}

// HostPolicy implements autocert.HostPolicy by consulting
// the apps list for a matching host name.
func (s *Server) HostPolicy(ctx context.Context, host string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check if host is main host
	if host == mainHostName {
		return nil
	}

	// If not check if the host is in allowed apps
	for _, app := range s.apps {
		if host == app.Host {
			return nil
		}
	}
	return fmt.Errorf("unrecognized host %q", host)
}

// parseApps reads app definitions from file, constructs the app handlers,and returns the resultant apps.
func parseApps(file string) ([]*app, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var apps []*app
	if err := json.NewDecoder(f).Decode(&apps); err != nil {
		return nil, err
	}
	for _, r := range apps {
		r.handler = makeHandler(r)
		if r.handler == nil {
			log.Printf("bad app: %#v", r)
		}
	}
	return apps, nil
}

// makeHandler constructs the appropriate Handler for the given app.
func makeHandler(r *app) http.Handler {
	var handler http.Handler
	if fwdTo := r.ForwardTo; r.IsProxy && fwdTo != "" {
		handler = &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				// Set the correct scheme to the request
				if !strings.HasPrefix(fwdTo, "http") {
					req.URL.Scheme = "http"
					req.URL.Host = fwdTo
				} else {
					fwdToSplit := strings.Split(fwdTo, "://")
					req.URL.Scheme = fwdToSplit[0]
					req.URL.Host = fwdToSplit[1]
				}
				if r.Login != "" && r.Password != "" {
					req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(r.Login+":"+r.Password)))
				}
				req.Host = fwdTo
				// Remove all jwt tokens from forwarded request
				q := req.URL.Query()
				q.Del("token") // Delete from query
				req.URL.RawQuery = q.Encode()
				var JWTCookie string
				for _, b := range req.Cookies() {
					if b.Name == "jwt_token" {
						JWTCookie = b.Value
						break
					}
				}
				if JWTCookie != "" {
					req.Header.Set("Cookie", strings.Replace(req.Header.Get("Cookie"), "jwt_token="+JWTCookie, "", 1)) // Delete from Cookie
				}
			},
			ModifyResponse: func(res *http.Response) error {
				// Alter the redirect location
				u, err := res.Location()
				if err == nil {
					u.Scheme = "https"
					if strings.HasSuffix(u.Host, r.ForwardTo) { // Then the redirect is global
						u.Host = strings.Replace(u.Host, r.ForwardTo, r.Host, 1)
					} else { // Or is local
						u.Host = r.Host + ":" + strconv.Itoa(port)
					}
					res.Header.Set("Location", u.String())
				}
				res.Header.Set("Content-Security-Policy", "frame-ancestors "+frameSource)
				res.Header.Set("X-Frame-Options", "DENY")
				return nil
			},
		}
	} else if d := r.Serve; !r.IsProxy && d != "" {
		handler = http.FileServer(http.Dir(d))
	}
	if !r.Secured || handler == nil {
		return handler
	}
	return security.ValidateJWTMiddleware(handler, r.Roles)
}
