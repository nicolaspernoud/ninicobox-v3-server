package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/nicolaspernoud/ninicobox-v3-server/security"
	"github.com/nicolaspernoud/ninicobox-v3-server/types"
	"golang.org/x/net/webdav"
)

func main() {
	fmt.Println("Starting the application...")
	log.Fatal(http.ListenAndServe(":2080", createMainRouter()))
}

func createMainRouter() http.Handler {
	router := mux.NewRouter()

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
	fileACLs, err := types.ACLsFromJSONFile("./config/filesacls.json")
	if err != nil {
		fmt.Println(err.Error())
	} else {
		for _, acl := range fileACLs {
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
	return router
}

func webdavLogger(r *http.Request, err error) {
	if err != nil {
		log.Printf("WEBDAV [%s]: %s, ERROR: %s\n", r.Method, r.URL, err)
	} else {
		log.Printf("WEBDAV [%s]: %s \n", r.Method, r.URL)
	}
}
