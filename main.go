package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/nicolaspernoud/ninicobox-v3-server/security"
	"github.com/nicolaspernoud/ninicobox-v3-server/types"
	"github.com/nicolaspernoud/ninicobox-v3-server/webdavaug"
	"github.com/nicolaspernoud/ninicobox-v3-server/webfront"
)

var (
	letsCacheDir = flag.String("letsencrypt_cache", "", "letsencrypt cache `directory` (default is to disable HTTPS)")
	ruleFile     = flag.String("rules", "./config/proxys.json", "rule definition `file`")
	pollInterval = flag.Duration("poll", time.Second*10, "rule file poll `interval`")
	mainHostName = flag.String("hostname", "localhost", "Main hostname, default to localhost")
	debugMode    = flag.Bool("debug", false, "Debug mode, allows CORS and debug JWT")
)

func main() {

	// Parse the flags
	flag.Parse()

	// Initialize logger
	logger := log.New(os.Stdout, "", log.LstdFlags)
	logger.Println("Server is starting...")
	logger.Printf("Main hostname is %v\n", *mainHostName)

	// Initialize security with debug flag
	security.Init(*debugMode, logger)

	// Create the webfront handler
	webFrontServer, err := webfront.NewServer(*ruleFile, *pollInterval)
	if err != nil {
		log.Fatal(err)
	}
	//httpFD, _ := strconv.Atoi(os.Getenv("RUNSIT_PORTFD_http"))
	//httpsFD, _ := strconv.Atoi(os.Getenv("RUNSIT_PORTFD_https"))
	var webFrontHandler http.Handler = webFrontServer

	// Create the main handler
	mainMux := createMainMux()

	// Put it together into the main handler
	rootMux := http.NewServeMux()
	rootMux.Handle(*mainHostName+"/", mainMux)
	rootMux.Handle("/", webFrontHandler)

	/* 		if *letsCacheDir != "" {
		m := &autocert.Manager{
			Cache:      autocert.DirCache(*letsCacheDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: s.hostPolicy,
		}
		c := tls.Config{GetCertificate: m.GetCertificate}
		l := tls.NewListener(listen(httpsFD, ":https"), &c)
		go func() {
			log.Fatal(http.Serve(l, h))
		}()
		h = m.HTTPHandler(h)
	} */
	//log.Fatal(http.Serve(listen(httpFD, *httpAddr), h))

	if *debugMode {
		log.Fatal(http.ListenAndServe(":2080", corsMiddleware(logMiddleware(logger)(rootMux))))
	} else {
		log.Fatal(http.ListenAndServe(":2080", logMiddleware(logger)(rootMux)))
	}

}

func createMainMux() http.Handler {

	mainMux := http.NewServeMux()
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
	adminAuth := security.AuthenticationMiddleware{
		AllowedRoles: []string{"admin"},
	}
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
			webdavHandler := webdavaug.New(webdavPath, acl.Directory, acl.Roles, acl.Permissions == "rw")
			mainMux.Handle(webdavPath, webdavHandler)
		}
	}
	return mainMux
}

func logMiddleware(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				userLogin, ok := r.Context().Value(0).(string)
				if !ok {
					userLogin = "unknown"
				}
				logger.Println(userLogin, r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent())
			}()
			next.ServeHTTP(w, r)
		})
	}
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
