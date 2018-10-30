package tester

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// DoRequest does a request on a router (or handler) and check the response
func DoRequest(t *testing.T, router http.Handler, method string, route string, authHeader string, payload string, expectedStatus int, expectedBody string) string {
	req, err := http.NewRequest(method, route, strings.NewReader(payload))
	req.Header.Set("Authorization", authHeader)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if status := rr.Code; status != expectedStatus {
		t.Errorf("Tested %v %v %v ; handler returned wrong status code: got %v want %v", method, route, payload, status, expectedStatus)
	}
	if !strings.HasPrefix(rr.Body.String(), expectedBody) {
		t.Errorf("Tested %v %v %v ; handler returned unexpected body: got %v want %v", method, route, payload, rr.Body.String(), expectedBody)
	}
	return string(rr.Body.String())
}
