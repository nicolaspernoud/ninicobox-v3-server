package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/nicolaspernoud/ninicobox-v3-server/internal/types"
	"github.com/nicolaspernoud/ninicobox-v3-server/pkg/appserver"

	"github.com/nicolaspernoud/ninicobox-v3-server/pkg/common"
	"github.com/nicolaspernoud/ninicobox-v3-server/pkg/log"
	"github.com/nicolaspernoud/ninicobox-v3-server/pkg/onlyoffice"
	"github.com/nicolaspernoud/ninicobox-v3-server/pkg/security"
	"github.com/nicolaspernoud/ninicobox-v3-server/pkg/webdavaug"

	"golang.org/x/crypto/acme/autocert"
)

var (
	letsCacheDir = flag.String("letsencrypt_cache", "./letsencrypt_cache", "let's encrypt cache `directory`")
	mainHostName = flag.String("hostname", "localhost", "Main hostname, defaults to localhost")
	frameSource  = flag.String("framesource", "localhost", "Location from where iframes are allowed, defaults to localhost")
	logFile      = flag.String("log_file", "", "Optional file to log to, defaults to no file logging")
	officeServer = flag.String("office_server", "office.domain.com", "Editing document server url")
	debugMode    = flag.Bool("debug", false, "Debug mode, disable let's encrypt, enable CORS and more logging")
	httpsPort    = flag.Int("https_port", 443, "HTTPS port to serve on (defaults to 443)")
	httpPort     = flag.Int("http_port", 80, "HTTP port to serve on (defaults to 80), only used to get let's encrypt certificates")

	adminAuth = security.AuthenticationMiddleware{
		AllowedRoles: []string{"admin"},
	}
)

func main() {

	// Parse the flags
	flag.Parse()

	// Initialize logger
	if *logFile != "" {
		log.SetFile(*logFile)
		// Properly close the log on exit
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigs
			log.Logger.Println("--- Closing log ---")
			log.CloseFile()
			os.Exit(0)
		}()
	}
	log.Logger.Println("--- Server is starting ---")
	log.Logger.Printf("Main hostname is %v\n", *mainHostName)

	// Create the server
	rootMux, hostPolicy := createRootMux(*httpsPort)

	// Serve locally with https on debug mode or with let's encrypt on production mode
	if *debugMode {
		log.Logger.Fatal(http.ListenAndServeTLS(":"+strconv.Itoa(*httpsPort), "./dev_certificates/localhost.crt", "./dev_certificates/localhost.key", security.CorsMiddleware(log.Middleware(rootMux), frameSource)))
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

func createRootMux(port int) (http.Handler, func(ctx context.Context, host string) error) {
	// Create the app handler
	appServer, err := appserver.NewServer("./configs/apps.json", port, *frameSource, *mainHostName, security.ValidateJWTMiddleware)
	if err != nil {
		log.Logger.Fatal(err)
	}
	var appHandler http.Handler = appServer

	// Create the main handler
	mainMux := createMainMux(appServer)

	// Put it together into the main handler
	rootMux := http.NewServeMux()
	rootMux.Handle(*mainHostName+"/", security.WebSecurityMiddleware(mainMux, frameSource))
	rootMux.Handle("/", appHandler)
	return rootMux, appServer.HostPolicy
}

func createMainMux(appServer *appserver.Server) http.Handler {

	mainMux := http.NewServeMux()

	// Create unsecured routes
	mainMux.HandleFunc("/api/login", security.Authenticate)
	mainMux.HandleFunc("/api/infos", func(w http.ResponseWriter, req *http.Request) {
		types.SendInfos(w, req, *officeServer)
	})
	mainMux.HandleFunc("/api/onlyoffice/save", onlyoffice.HandleSaveCallback)

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
			security.SetUsers(w, req)
			return
		}
		if req.Method == http.MethodGet {
			security.SendUsers(w, req)
			return
		}
		http.Error(w, "method not allowed", 405)
	})
	adminMux.HandleFunc("/apps", func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost {
			types.SetApps(w, req)
			if err := appServer.LoadApps("./configs/apps.json"); err != nil {
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
	err := common.Load("./configs/filesacls.json", &filesACLs)
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
	mainMux.Handle("/", http.FileServer(&common.FallBackWrapper{Assets: http.Dir("web")}))

	return mainMux
}
