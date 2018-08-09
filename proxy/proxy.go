/*

This package is based upon https://github.com/nf/webfront (Copyright 2011 Google Inc.)

*/

package proxy

import (
	"context"
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

	"github.com/nicolaspernoud/ninicobox-v3-server/security"
)

var httpPort int

// Server implements an http.Handler that acts as either a reverse proxy or
// a simple file server, as determined by a rule set.
type Server struct {
	mu    sync.RWMutex // guards the fields below
	last  time.Time
	rules []*Rule
}

// Rule represents a rule in a configuration file.
type Rule struct {
	FromURL string // to match against request Host header
	ToURL   string // non-empty if reverse proxy
	Secured bool   // true if the handler is JWT secured

	handler http.Handler
}

// NewServer constructs a Server that reads rules from file with a period
// specified by poll.
func NewServer(file string, httpPortFromMain int) (*Server, error) {
	httpPort = httpPortFromMain
	s := new(Server)
	if err := s.LoadRules(file); err != nil {
		return nil, err
	}
	return s, nil
}

// ServeHTTP matches the Request with a Rule and, if found, serves the
// request with the Rule's handler.
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
	for _, r := range s.rules {
		if h == r.FromURL || strings.HasSuffix(h, "."+r.FromURL) {
			return r.handler
		}
	}
	return nil
}

// LoadRules tests whether file has been modified since its last invocation
// and, if so, loads the rule set from file.
func (s *Server) LoadRules(file string) error {
	fi, err := os.Stat(file)
	if err != nil {
		return err
	}
	mtime := fi.ModTime()
	if !mtime.After(s.last) && s.rules != nil {
		return nil // no change
	}
	rules, err := parseRules(file)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.last = mtime
	s.rules = rules
	s.mu.Unlock()
	return nil
}

// hostPolicy implements autocert.HostPolicy by consulting
// the rules list for a matching host name.
func (s *Server) hostPolicy(ctx context.Context, host string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, rule := range s.rules {
		if host == rule.FromURL || host == "www."+rule.FromURL {
			return nil
		}
	}
	return fmt.Errorf("unrecognized host %q", host)
}

// parseRules reads rule definitions from file, constructs the Rule handlers,
// and returns the resultant Rules.
func parseRules(file string) ([]*Rule, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rules []*Rule
	if err := json.NewDecoder(f).Decode(&rules); err != nil {
		return nil, err
	}
	for _, r := range rules {
		r.handler = makeHandler(r)
		if r.handler == nil {
			log.Printf("bad rule: %#v", r)
		}
	}
	return rules, nil
}

// makeHandler constructs the appropriate Handler for the given Rule.
func makeHandler(r *Rule) http.Handler {
	if h := r.ToURL; h != "" {
		reverseProxy := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				// Set the correct scheme to the request
				if !strings.HasPrefix(h, "http") {
					req.URL.Scheme = "http"
					req.URL.Host = h
					req.Host = h
				} else {
					hSplit := strings.Split(h, "://")
					req.URL.Scheme = hSplit[0]
					req.URL.Host = hSplit[1]
					req.Host = hSplit[1]
				}
			},
			ModifyResponse: func(res *http.Response) error {
				// Alter the redirect location
				u, err := res.Location()
				if err == nil {
					if httpPort == 443 {
						u.Scheme = "https"
					}
					u.Host = r.FromURL + ":" + strconv.Itoa(httpPort)
					res.Header.Set("Location", u.String())
				}
				res.Header.Set("Content-Security-Policy", "frame-ancestors https://*.ninico.fr")
				res.Header.Set("X-Frame-Options", "DENY")
				return nil
			},
		}
		if !r.Secured {
			return reverseProxy
		}
		return security.ValidateJWTMiddleware(reverseProxy, []string{"admin"})
	}
	return nil
}
