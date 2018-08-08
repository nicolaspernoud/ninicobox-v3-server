package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"strconv"

	"github.com/nicolaspernoud/ninicobox-v3-server/log"
	"github.com/nicolaspernoud/ninicobox-v3-server/proxy"
	"github.com/nicolaspernoud/ninicobox-v3-server/security"
	"github.com/nicolaspernoud/ninicobox-v3-server/types"
	"github.com/nicolaspernoud/ninicobox-v3-server/webdavaug"
	"golang.org/x/crypto/acme/autocert"
)

var (
	letsCacheDir  = flag.String("letsencrypt_cache", "./letsencrypt_cache", "letsencrypt cache `directory`")
	mainHostName  = flag.String("hostname", "localhost", "Main hostname, default to localhost")
	debugMode     = flag.Bool("debug", false, "Debug mode, allows CORS and debug JWT")
	debugModePort = flag.Int("debug_mode_port", 2080, "HTTP port to serve on (on debug mode)")

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

	// Initialize security with debug flag
	security.Init(*debugMode)

	// Create the proxy handler
	var proxyPort int
	if !*debugMode {
		proxyPort = 443
	} else {
		proxyPort = *debugModePort
	}
	proxyServer, err := proxy.NewServer("./config/proxys.json", proxyPort)
	if err != nil {
		log.Logger.Fatal(err)
	}
	var proxyHandler http.Handler = proxyServer

	// Create the main handler
	mainMux := createMainMux(proxyServer)

	// Put it together into the main handler
	rootMux := http.NewServeMux()
	rootMux.Handle(*mainHostName+"/", mainMux)
	rootMux.Handle("/", proxyHandler)

	// Serve locally with http on debug mode or with let's encrypt on production mode
	if *debugMode {
		log.Logger.Fatal(http.ListenAndServe(":"+strconv.Itoa(*debugModePort), corsMiddleware(logMiddleware(rootMux))))
	} else {
		certManager := autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(*letsCacheDir),
		}

		server := &http.Server{
			Addr:    ":443",
			Handler: webSecurityMiddleware(rootMux),
			TLSConfig: &tls.Config{
				GetCertificate: certManager.GetCertificate,
			},
		}

		go http.ListenAndServe(":80", certManager.HTTPHandler(nil))
		server.ListenAndServeTLS("", "")
	}

}

func createMainMux(proxyServer *proxy.Server) http.Handler {

	mainMux := http.NewServeMux()
	// Serve static files
	fs := http.FileServer(http.Dir("client"))
	mainMux.Handle("/", fs)
	// Create login unsecured routes
	mainMux.HandleFunc("/api/login", security.Authenticate)
	mainMux.HandleFunc("/api/infos", types.SendInfos)

	// Create routes secured for all authenticated users
	commonMux := http.NewServeMux()
	commonMux.HandleFunc("/filesacls", types.SendFilesACLs)
	commonMux.HandleFunc("/getsharetoken", security.GetShareToken)
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
	adminMux.HandleFunc("/proxys", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost {
			types.SetProxys(w, req)
			if err := proxyServer.LoadRules("./config/proxys.json"); err != nil {
				http.Error(w, "error loading proxy rules", 400)
			}
			return
		}
		if req.Method == http.MethodGet {
			types.SendProxys(w, req)
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
	return mainMux
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			log.Logger.Println(r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent())
		}()
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
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", " default-src https: 'unsafe-eval' 'unsafe-inline'; object-src 'none'; frame-ancestors https://box.ninico.fr")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, req)
	})
}
