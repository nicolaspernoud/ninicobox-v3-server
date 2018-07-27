package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/nicolaspernoud/ninicobox-v3-server/security"
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
	//router.HandleFunc("/api/files/route name", security.ValidateJWTMiddleware(webdavhandler, []string{"admin"})).Methods("GET", or more)
	webdavHandler := &webdav.Handler{
		Prefix:     "/api/files",
		FileSystem: webdav.Dir("/home/nicolas/Images"),
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			if err != nil {
				log.Printf("WEBDAV [%s]: %s, ERROR: %s\n", r.Method, r.URL, err)
			} else {
				log.Printf("WEBDAV [%s]: %s \n", r.Method, r.URL)
			}
		},
	}

	router.PathPrefix("/api/files").Handler(webdavHandler)

	//router.HandleFunc("/api/test", security.ValidateJWTMiddleware(TestEndpoint, ))
	log.Fatal(http.ListenAndServe(":2080", router))
}
