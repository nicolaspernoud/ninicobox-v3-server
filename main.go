package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/handlers"
	"github.com/nicolaspernoud/ninicobox-v3-server/security"
	"github.com/nicolaspernoud/ninicobox-v3-server/types"
	"github.com/nicolaspernoud/ninicobox-v3-server/webdavaug"
	"github.com/nicolaspernoud/ninicobox-v3-server/webfront"
)

var (
	letsCacheDir      = flag.String("letsencrypt_cache", "", "letsencrypt cache `directory` (default is to disable HTTPS)")
	ruleFile          = flag.String("rules", "./config/proxys.json", "rule definition `file`")
	pollInterval      = flag.Duration("poll", time.Second*10, "rule file poll `interval`")
	principalHostName = flag.String("hostname", "localhost", "Principal hostname, default to localhost")
)

func main() {
	fmt.Println("Starting the application...")

	// Parse the flags
	flag.Parse()

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
	rootMux.Handle(*principalHostName, mainMux)
	rootMux.Handle("/", webFrontHandler)

	loggedRootMux := handlers.LoggingHandler(os.Stdout, rootMux)
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

	originsOk := handlers.AllowedOrigins([]string{"*"})
	headersOk := handlers.AllowedHeaders([]string{"Content-Type", "Authorization", "Depth", "Destination"})
	methodsOk := handlers.AllowedMethods([]string{"POST", "GET", "OPTIONS", "PUT", "DELETE", "PROPFIND", "MKCOL", "MOVE", "COPY"})

	log.Fatal(http.ListenAndServe(":2080", handlers.CORS(originsOk, headersOk, methodsOk)(loggedRootMux)))
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
