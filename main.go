package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/nicolaspernoud/ninicobox-v3-server/security"
	"github.com/nicolaspernoud/ninicobox-v3-server/types"
	"golang.org/x/net/webdav"
)

func TestEndpoint(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "User is %v, and has role %v", req.Context().Value("login"), req.Context().Value("role"))
}

func main() {
	fmt.Println("Starting the application...")
	router := mux.NewRouter()

	// Create common unsecured routes
	router.HandleFunc("/api/login", security.Authenticate).Methods("POST")

	// Create admin routes, all admin secured
	adminRouter := router.PathPrefix("/api/admin").Subrouter()
	adminAuth := security.AuthenticationMiddleware{
		AllowedRoles: []string{"admin"},
	}
	adminRouter.Use(adminAuth.ValidateJWTMiddleware)
	adminRouter.HandleFunc("/testadmin", TestEndpoint)

	// Create webdav routes according to filesacl.json
	// For each ACL, create a route with a webdav handler that match the route, with the ACL permissions and methods
	fileACLs, err := getFileACLs()
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

	log.Fatal(http.ListenAndServe(":2080", router))
}

func getFileACLs() ([]types.FileACL, error) {
	var fileACLs []types.FileACL
	aclFile, err := os.Open("./config/filesacl.json")
	defer aclFile.Close()
	if err != nil {
		fmt.Println(err.Error())
		return fileACLs, err
	}
	err = json.NewDecoder(aclFile).Decode(&fileACLs)
	return fileACLs, err
}

func webdavLogger(r *http.Request, err error) {
	if err != nil {
		log.Printf("WEBDAV [%s]: %s, ERROR: %s\n", r.Method, r.URL, err)
	} else {
		log.Printf("WEBDAV [%s]: %s \n", r.Method, r.URL)
	}
}
