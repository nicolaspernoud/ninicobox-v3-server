package tester

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// DoRequestOnHandler does a request on a router (or handler) and check the response
func DoRequestOnHandler(t *testing.T, router http.Handler, method string, route string, authHeader string, payload string, expectedStatus int, expectedBody string) string {
	req, err := http.NewRequest(method, route, strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", authHeader)
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

// DoRequestOnServer does a request on listening server
func DoRequestOnServer(t *testing.T, port string, method string, url string, authHeader string, payload string, expectedStatus int, expectedBody string) string {
	if strings.HasPrefix(url, "/") {
		url = "http://localhost:" + port + url
	} else {
		if strings.Contains(url, "?") {
			parts := strings.Split(url, "?")
			url = "http://" + parts[0] + ":" + port + "?" + parts[1]
		} else {
			url = "http://" + url + ":" + port
		}
	}
	req, err := http.NewRequest(method, url, strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", authHeader)
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	bodyString := string(body)
	if status := res.StatusCode; status != expectedStatus {
		t.Errorf("Tested %v %v %v ; handler returned wrong status code: got %v want %v", method, url, payload, status, expectedStatus)
	}
	if !strings.HasPrefix(bodyString, expectedBody) {
		t.Errorf("Tested %v %v %v ; handler returned unexpected body: got %v want %v", method, url, payload, bodyString, expectedBody)
	}
	return bodyString
}
