package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nicolaspernoud/ninicobox-v3-server/types"
)

func Test_MainRouter(t *testing.T) {
	router := createMainRouter()
	// Do a login with an unknown user
	doLogin(t, router, "unknownuser", "password", http.StatusBadRequest, `User not found`)
	// Do a login with a known user but bad password
	doLogin(t, router, "admin", "badpassword", http.StatusBadRequest, `User not found`)
	// Do a login with the correct admin user
	adminToken := doLogin(t, router, "admin", "password", http.StatusOK, `{"token":"`)
	t.Logf("Got admin token: %v", adminToken)
}

func doLogin(t *testing.T, router http.Handler, login string, password string, expectedStatus int, expectedBody string) string {

	// Create a request to pass to handler
	req, err := http.NewRequest("POST", "/api/login", strings.NewReader(`{"login": "`+login+`","password": "`+password+`"}`))
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	router.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != expectedStatus {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, expectedStatus)
	}

	// Check the response body is what we expect.
	if !strings.HasPrefix(rr.Body.String(), expectedBody) {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expectedBody)
	}

	var token types.JwtToken
	json.NewDecoder(rr.Body).Decode(&token)
	return token.Token
}
