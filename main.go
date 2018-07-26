package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/nicolaspernoud/ninicobox-v3-server/security"
)

func TestEndpoint(w http.ResponseWriter, req *http.Request) {
	var user = req.Context().Value("Username")
	json.NewEncoder(w).Encode(user)
}

func main() {
	router := mux.NewRouter()
	fmt.Println("Starting the application...")
	router.HandleFunc("/api/login", security.Authenticate).Methods("POST")
	router.HandleFunc("/api/test", security.ValidateJWTMiddleware(TestEndpoint, []string{"admin"})).Methods("GET")
	log.Fatal(http.ListenAndServe(":2080", router))
}
