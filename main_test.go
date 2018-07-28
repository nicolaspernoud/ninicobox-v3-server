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

	initialUsers := `[{"id":1,"login":"admin","name":"Ad","surname":"MIN","role":"admin","passwordHash":"$2a$10$WQeaeTOQbzC1w3FP41x7tuHT.LI9AfjL1UV7LoYzozZ7XzAJ.YRtu"},{"id":2,"login":"user","name":"Us","surname":"ER","role":"user","passwordHash":"$2a$10$bWxtHLE.3pFkzg.XP4eR1eSBIkUOHiCaGvTUT3hiBxmhqtyRydA26"}]`
	updatedUsers := `[{"id":1,"login":"admin","name":"Ad","surname":"MIN","role":"admin","password":"newpassword","passwordHash":"$2a$10$WQeaeTOQbzC1w3FP41x7tuHT.LI9AfjL1UV7LoYzozZ7XzAJ.YRtu"},{"id":2,"login":"user","name":"Us","surname":"ER","role":"user","passwordHash":"$2a$10$bWxtHLE.3pFkzg.XP4eR1eSBIkUOHiCaGvTUT3hiBxmhqtyRydA26"}]`
	updatedUsersBlankPassword := `[{"id":1,"login":"admin","name":"Ad","surname":"MIN","role":"admin","password":"","passwordHash":""},{"id":2,"login":"user","name":"Us","surname":"ER","role":"user","passwordHash":"$2a$10$bWxtHLE.3pFkzg.XP4eR1eSBIkUOHiCaGvTUT3hiBxmhqtyRydA26"}]`

	// === Try to access the ressources as an unidentified user ===
	// Do a login with an unknown user
	doLogin(t, router, "unknownuser", "password", http.StatusBadRequest, `User not found`)
	// Do a login with a known user but bad password
	doLogin(t, router, "admin", "badpassword", http.StatusBadRequest, `User not found`)
	// Try to get the files access control lists
	doRequest(t, router, "GET", "/api/common/fileacls", "", "", http.StatusUnauthorized, "no token found")
	// Try to get the users
	doRequest(t, router, "GET", "/api/admin/users", "", "", http.StatusUnauthorized, "no token found")
	// Try to update the users
	doRequest(t, router, "POST", "/api/admin/users", "", updatedUsers, http.StatusUnauthorized, "no token found")
	// Try to read a webdav ressource
	doRequest(t, router, "GET", "/api/files/usersrw/File users 01.txt", "", "", http.StatusUnauthorized, "no token found")
	// Try to create a webdav ressource
	doRequest(t, router, "PUT", "/api/files/adminsrw/Test.txt", "", "This is a test", http.StatusUnauthorized, "no token found")
	// Try to delete a webdav ressource
	doRequest(t, router, "DELETE", "/api/files/usersrw/Test.txt", "", "", http.StatusUnauthorized, "no token found")

	// === Try to access the ressources as an normal user ===
	userHeader := "Bearer " + doLogin(t, router, "user", "password", http.StatusOK, `{"token":"`)
	t.Logf("Got user auth header: %v", userHeader)
	// Try to get the files access control lists
	doRequest(t, router, "GET", "/api/common/fileacls", userHeader, "", http.StatusOK, `[{"name":"Users Read Only"`)
	// Try to get the users
	doRequest(t, router, "GET", "/api/admin/users", userHeader, "", http.StatusForbidden, "User has role user, which is not in allowed roles ([admin])")
	// Try to update the users
	doRequest(t, router, "POST", "/api/admin/users", userHeader, updatedUsers, http.StatusForbidden, "User has role user, which is not in allowed roles ([admin])")
	// Try to read a webdav ressource
	doRequest(t, router, "GET", "/api/files/usersrw/File users 01.txt", userHeader, "", http.StatusOK, "Lorem ipsum")
	// Try to create a webdav ressource
	doRequest(t, router, "PUT", "/api/files/adminsrw/Test.txt", userHeader, "This is a test", http.StatusForbidden, "User has role user, which is not in allowed roles ([admin])")
	// Try to delete a webdav ressource
	doRequest(t, router, "DELETE", "/api/files/adminsrw/Test.txt", userHeader, "", http.StatusForbidden, "User has role user, which is not in allowed roles ([admin])")

	// === Try to access the ressources as an admin ===
	// Do a login with the correct admin user
	adminHeader := "Bearer " + doLogin(t, router, "admin", "password", http.StatusOK, `{"token":"`)
	t.Logf("Got admin auth header: %v", adminHeader)
	// Try to get the files access control lists
	doRequest(t, router, "GET", "/api/common/fileacls", adminHeader, "", http.StatusOK, `[{"name":"Users Read Only"`)
	// Try to get the users
	doRequest(t, router, "GET", "/api/admin/users", adminHeader, "", http.StatusOK, `[{"id":1,"login":"admin"`)
	// Try to update the users with a blank password
	doRequest(t, router, "POST", "/api/admin/users", adminHeader, updatedUsersBlankPassword, http.StatusBadRequest, "Passwords cannot be blank")
	// Try to update the users
	doRequest(t, router, "POST", "/api/admin/users", adminHeader, updatedUsers, http.StatusOK, "Users updated")
	// Try to login with old password
	doLogin(t, router, "admin", "password", http.StatusBadRequest, `User not found`)
	// Update the user to revert to old password
	doRequest(t, router, "POST", "/api/admin/users", adminHeader, initialUsers, http.StatusOK, "Users updated")
	// Try again to login
	adminHeader = "Bearer " + doLogin(t, router, "admin", "password", http.StatusOK, `{"token":"`)
	// Try to read a webdav ressource
	doRequest(t, router, "GET", "/api/files/usersrw/File users 01.txt", adminHeader, "", http.StatusOK, "Lorem ipsum")
	// Try to create a webdav ressource
	doRequest(t, router, "PUT", "/api/files/adminsrw/Test.txt", adminHeader, "This is a test", http.StatusCreated, "Created")
	// Try to read the created ressource
	doRequest(t, router, "GET", "/api/files/adminsrw/Test.txt", adminHeader, "", http.StatusOK, "This is a test")
	// Try to delete a webdav ressource
	doRequest(t, router, "DELETE", "/api/files/adminsrw/Test.txt", adminHeader, "", http.StatusNoContent, "")
}

// doLogin is different from doRequest since we need to get the received token from the response
func doLogin(t *testing.T, router http.Handler, login string, password string, expectedStatus int, expectedBody string) string {
	// Create a request to pass to handler
	req, err := http.NewRequest("POST", "/api/login", strings.NewReader(`{"login": "`+login+`","password": "`+password+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response
	rr := httptest.NewRecorder()
	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method directly and pass in our Request and ResponseRecorder
	router.ServeHTTP(rr, req)
	// Check the status code is what we expect
	if status := rr.Code; status != expectedStatus {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, expectedStatus)
	}
	// Check the response body is what we expect
	if !strings.HasPrefix(rr.Body.String(), expectedBody) {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expectedBody)
	}
	var token types.JwtToken
	json.NewDecoder(rr.Body).Decode(&token)
	return token.Token
}

// doRequest does a request on the main router and check the response
func doRequest(t *testing.T, router http.Handler, method string, route string, authHeader string, payload string, expectedStatus int, expectedBody string) {
	req, err := http.NewRequest(method, route, strings.NewReader(payload))
	req.Header.Set("Authorization", authHeader)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if status := rr.Code; status != expectedStatus {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, expectedStatus)
	}
	if !strings.HasPrefix(rr.Body.String(), expectedBody) {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expectedBody)
	}
}
