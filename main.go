package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strconv"
	"time"

	"./packages/appserver"
	"./packages/log"
	"./packages/security"
	"./packages/types"
	"./packages/webdavaug"
	"golang.org/x/crypto/acme/autocert"
)

var (
	letsCacheDir = flag.String("letsencrypt_cache", "./letsencrypt_cache", "let's encrypt cache `directory`")
	mainHostName = flag.String("hostname", "localhost", "Main hostname, default to localhost")
	frameSource  = flag.String("framesource", "localhost", "Location from where iframes are allowed, default to localhost")
	debugMode    = flag.Bool("debug", false, "Debug mode, disable let's encrypt, enable CORS and more logging")
	httpsPort    = flag.Int("https_port", 443, "HTTPS port to serve on (default to 443)")
	httpPort     = flag.Int("http_port", 80, "HTTP port to serve on (default to 80), only used to get let's encrypt certificates")

	adminAuth = security.AuthenticationMiddleware{
		AllowedRoles: []string{"admin"},
	}
)

func main() {

	// Parse the flags
	flag.Parse()

	// Initialize logger
	log.Logger.Println("Server is starting...")
	log.Logger.Printf("Main hostname is %v\n", *mainHostName)

	// Create the server
	rootMux, hostPolicy := createRootMux(*httpsPort, *frameSource, *mainHostName)

	// Serve locally with https on debug mode or with let's encrypt on production mode
	if *debugMode {
		log.Logger.Fatal(http.ListenAndServeTLS(":"+strconv.Itoa(*httpsPort), "./dev_certificates/localhost.crt", "./dev_certificates/localhost.key", corsMiddleware(logMiddleware(rootMux))))
	} else {
		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(*letsCacheDir),
			HostPolicy: hostPolicy,
		}

		server := &http.Server{
			Addr:    ":" + strconv.Itoa(*httpsPort),
			Handler: rootMux,
			TLSConfig: &tls.Config{
				GetCertificate: certManager.GetCertificate,
			},
			ReadTimeout:  30 * time.Minute, // in case of upload
			WriteTimeout: 5 * time.Hour,    // in case of download
			IdleTimeout:  120 * time.Second,
		}

		go http.ListenAndServe(":"+strconv.Itoa(*httpPort), certManager.HTTPHandler(nil))
		server.ListenAndServeTLS("", "")
	}

}

func createRootMux(port int, frameSource string, mainHostName string) (http.Handler, func(ctx context.Context, host string) error) {
	// Create the app handler
	appServer, err := appserver.NewServer("./config/apps.json", port, frameSource, mainHostName)
	if err != nil {
		log.Logger.Fatal(err)
	}
	var appHandler http.Handler = appServer

	// Create the main handler
	mainMux := createMainMux(appServer)

	// Put it together into the main handler
	rootMux := http.NewServeMux()
	rootMux.Handle(mainHostName+"/", webSecurityMiddleware(mainMux))
	rootMux.Handle("/", appHandler)
	return rootMux, appServer.HostPolicy
}

func createMainMux(appServer *appserver.Server) http.Handler {

	mainMux := http.NewServeMux()

	// Create login unsecured routes
	mainMux.HandleFunc("/api/login", security.Authenticate)
	mainMux.HandleFunc("/api/infos", types.SendInfos)

	// Create routes secured for all authenticated users
	commonMux := http.NewServeMux()
	commonMux.HandleFunc("/filesacls", types.SendFilesACLs)
	commonMux.HandleFunc("/getsharetoken", security.GetShareToken)
	commonMux.HandleFunc("/apps", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet {
			types.SendApps(w, req)
			return
		}
		http.Error(w, "method not allowed", 405)
	})
	commonAuth := security.AuthenticationMiddleware{
		AllowedRoles: []string{"all"},
	}
	mainMux.Handle("/api/common/", http.StripPrefix("/api/common", commonAuth.ValidateJWTMiddleware(commonMux)))

	// Create admin routes, all admin secured
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/users", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost {
			types.SetUsers(w, req)
			return
		}
		if req.Method == http.MethodGet {
			types.SendUsers(w, req)
			return
		}
		http.Error(w, "method not allowed", 405)
	})
	adminMux.HandleFunc("/apps", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost {
			types.SetApps(w, req)
			if err := appServer.LoadApps("./config/apps.json"); err != nil {
				http.Error(w, "error loading apps", 400)
			}
			return
		}
		http.Error(w, "method not allowed", 405)
	})
	mainMux.Handle("/api/admin/", http.StripPrefix("/api/admin", adminAuth.ValidateJWTMiddleware(adminMux)))

	// Create webdav routes according to filesacl.json
	// For each ACL, create a route with a webdav handler that match the route, with the ACL permissions and methods
	var filesACLs []types.FilesACL
	err := types.Load("./config/filesacls.json", &filesACLs)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		for _, acl := range filesACLs {
			webdavPath := "/api/files/" + acl.Path + "/"
			webdavHandler := webdavaug.New(webdavPath, acl.Directory, acl.Roles, acl.Permissions == "rw", acl.BasicAuth)
			mainMux.Handle(webdavPath, webdavHandler)
		}
	}

	// Serve static files falling back to serving index.html
	mainMux.Handle("/", http.FileServer(&fallBackWrapper{http.Dir("client")}))

	return mainMux
}

type fallBackWrapper struct {
	assets http.FileSystem
}

func (i *fallBackWrapper) Open(name string) (http.File, error) {
	file, err := i.assets.Open(name)
	// If the file is found but there is another error or the asked for file has an extension : return the file or error
	if !os.IsNotExist(err) || path.Ext(name) != "" {
		return file, err
	}
	// Else fall back to index.html
	return i.assets.Open("index.html")
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		readBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Logger.Print("Body error : ", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		newBody := ioutil.NopCloser(bytes.NewBuffer(readBody))
		r.Body = newBody
		log.Logger.Println(r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent())
		if string(readBody) != "" {
			log.Logger.Printf("BODY : %q", readBody)
		}
		next.ServeHTTP(w, r)
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, PROPFIND, MKCOL, MOVE, COPY")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, Depth, Destination")
		if req.Method == "OPTIONS" {
			return
		}
		next.ServeHTTP(w, req)
	})
}

func webSecurityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com https://raw.githubusercontent.com; style-src * 'unsafe-inline'; script-src 'self'; font-src *; frame-src "+*frameSource+"; frame-ancestors "+*frameSource)
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, req)
	})
}
