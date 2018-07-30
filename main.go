package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/nicolaspernoud/ninicobox-v3-server/security"
	"github.com/nicolaspernoud/ninicobox-v3-server/types"
	"github.com/nicolaspernoud/ninicobox-v3-server/webfront"
	"golang.org/x/net/webdav"
)

var (
	letsCacheDir = flag.String("letsencrypt_cache", "", "letsencrypt cache `directory` (default is to disable HTTPS)")
	ruleFile     = flag.String("rules", "./config/proxys.json", "rule definition `file`")
	pollInterval = flag.Duration("poll", time.Second*10, "rule file poll `interval`")
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

	// Put it together into the main handler
	mainRouter := mux.NewRouter()
	businessSubRouter := mainRouter.Host("www.ninicobox.com").Subrouter()
	setBusinessSubRouter(businessSubRouter)

	mainRouter.PathPrefix("/").Handler(webFrontHandler)
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

	log.Fatal(http.ListenAndServe(":2080", mainRouter))
}

func setBusinessSubRouter(router *mux.Router) {
	// Create login unsecured routes
	router.HandleFunc("/api/login", security.Authenticate).Methods("POST")
	router.HandleFunc("/api/infos", types.SendInfos).Methods("GET")

	// Create routes secured for all authenticated users
	commonRouter := router.PathPrefix("/api/common").Subrouter()
	commonAuth := security.AuthenticationMiddleware{
		AllowedRoles: []string{"all"},
	}
	commonRouter.Use(commonAuth.ValidateJWTMiddleware)
	commonRouter.HandleFunc("/fileacls", types.SendFilesACLs).Methods("GET")
	commonRouter.HandleFunc("/getsharetoken", security.GetShareToken).Methods("POST")

	// Create admin routes, all admin secured
	adminRouter := router.PathPrefix("/api/admin").Subrouter()
	adminAuth := security.AuthenticationMiddleware{
		AllowedRoles: []string{"admin"},
	}
	adminRouter.Use(adminAuth.ValidateJWTMiddleware)
	adminRouter.HandleFunc("/users", types.SendUsers).Methods("GET")
	adminRouter.HandleFunc("/users", types.SetUsers).Methods("POST")

	// Create webdav routes according to filesacl.json
	// For each ACL, create a route with a webdav handler that match the route, with the ACL permissions and methods
	var filesACLs []types.FilesACL
	err := types.Load("./config/filesacls.json", &filesACLs)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		for _, acl := range filesACLs {
			webdavPath := "/api/files/" + acl.Path
			webdavHandler := &webdav.Handler{
				Prefix:     webdavPath,
				FileSystem: webdav.Dir(acl.Directory),
				LockSystem: webdav.NewMemLS(),
				Logger:     webdavLogger,
			}
			if acl.Permissions == "rw" {
				router.PathPrefix(webdavPath).Handler(security.ValidateJWTMiddleware(webdavHandler, acl.Roles))
			} else {
				router.PathPrefix(webdavPath).Handler(security.ValidateJWTMiddleware(webdavHandler, acl.Roles)).Methods("PROPFIND", "GET")
			}
		}
	}
}

func webdavLogger(r *http.Request, err error) {
	if err != nil {
		log.Printf("WEBDAV [%s]: %s, ERROR: %s\n", r.Method, r.URL, err)
	} else {
		log.Printf("WEBDAV [%s]: %s \n", r.Method, r.URL)
	}
}
