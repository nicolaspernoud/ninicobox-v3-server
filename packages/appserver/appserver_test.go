package appserver

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"../security"
	"../tester"
	"../types"
)

func TestServer(t *testing.T) {
	// Create config directory (errors are not handled, since is testing)
	os.MkdirAll("config", os.ModePerm)
	// Copy config file from parent directory (errors are not handled, since is testing)
	input, _ := ioutil.ReadFile("../../config/users.json")
	ioutil.WriteFile("./config/users.json", input, os.ModePerm)
	// Delete config directory after completion (errors are not handled, since is testing)
	defer os.RemoveAll("config")

	// Get JWTs
	userHeader := "Bearer " + tester.DoRequestOnHandler(t, http.HandlerFunc(security.Authenticate), "POST", "/api/login", "", `{"login": "user","password": "password"}`, http.StatusOK, `eyJhbG`)
	adminHeader := "Bearer " + tester.DoRequestOnHandler(t, http.HandlerFunc(security.Authenticate), "POST", "/api/login", "", `{"login": "admin","password": "password"}`, http.StatusOK, `eyJhbG`)
	wrongAuthHeader := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwibG9naW4iOiJhZG1pbiIsIm5hbWUiOiJBZCIsInN1cm5hbWUiOiJNSU4iLCJyb2xlIjoiYWRtaW4iLCJwYXNzd29yZEhhc2giOiIkMmEkMTAkV1FlYWVUT1FiekMxdzNGUDQxeDd0dUhULkxJOUFmakwxVVY3TG9Zem96WjdYekFKLllSdHUiLCJleHAiOjE1MzMwMzI3MTUsImlhdCI6MTUzMzAyOTExNX0.3FF273T6VXxhFOLR3gjBvPvYwSxiiyF_XPVTE_U2PSg"

	// Create the proxy target servers
	target := httptest.NewServer(http.HandlerFunc(testHandler))
	defer target.Close()

	redirectLocalTarget := httptest.NewServer(http.HandlerFunc(testRedirectLocalHandler))
	defer redirectLocalTarget.Close()

	redirectGlobalTarget := httptest.NewServer(http.HandlerFunc(testRedirectGlobalHandler))
	defer redirectGlobalTarget.Close()

	// Create apps
	appFile := writeApps([]*app{
		{App: types.App{Host: "example.com", IsProxy: true, ForwardTo: target.Listener.Addr().String()}},
		{App: types.App{Host: "example.org", IsProxy: false, Serve: "testdata"}},
		{App: types.App{Host: "example.localredirect", IsProxy: true, ForwardTo: redirectLocalTarget.Listener.Addr().String()}},
		{App: types.App{Host: "example.globalredirect", IsProxy: true, ForwardTo: redirectGlobalTarget.Listener.Addr().String()}},
		{App: types.App{Host: "example.securedproxy", IsProxy: true, ForwardTo: target.Listener.Addr().String(), Secured: true, Roles: []string{"admin", "user"}}},
		{App: types.App{Host: "example.adminsecuredproxy", IsProxy: true, ForwardTo: target.Listener.Addr().String(), Secured: true, Roles: []string{"admin"}}},
		{App: types.App{Host: "example.emptyrolesproxy", IsProxy: true, ForwardTo: target.Listener.Addr().String(), Secured: true, Roles: []string{}}},
		{App: types.App{Host: "example.emptyroleproxy", IsProxy: true, ForwardTo: target.Listener.Addr().String(), Secured: true, Roles: []string{""}}},
		{App: types.App{Host: "example.securedstatic", IsProxy: false, Serve: "testdata", Secured: true, Roles: []string{"admin", "user"}}},
		{App: types.App{Host: "example.adminsecuredstatic", IsProxy: false, Serve: "testdata", Secured: true, Roles: []string{"admin"}}},
	})
	defer os.Remove(appFile)

	s, err := NewServer(appFile, 443, "localhost", "localhost")
	if err != nil {
		t.Fatal(err)
	}

	// Create tests
	var tests = []struct {
		url        string
		authHeader string
		code       int
		body       string
	}{
		{"http://example.com/", "", 200, "OK"},
		{"http://foo.example.com/", "", 200, "OK"},
		{"http://example.org/", "", 200, "contents of index.html"},
		{"http://example.net/", "", 404, "Not found."},
		{"http://fooexample.com/", "", 404, "Not found."},
		{"http://example.securedproxy/", "", 401, "no token found"},
		{"http://example.securedproxy/", wrongAuthHeader, 403, "signature is invalid"},
		{"http://example.securedproxy/", userHeader, 200, "OK"},
		{"http://example.securedproxy/", adminHeader, 200, "OK"},
		{"http://example.adminsecuredproxy/", "", 401, "no token found"},
		{"http://example.adminsecuredproxy/", wrongAuthHeader, 403, "signature is invalid"},
		{"http://example.adminsecuredproxy/", userHeader, 403, "user has role user, which is not in allowed roles ([admin])"},
		{"http://example.adminsecuredproxy/", adminHeader, 200, "OK"},
		{"http://example.emptyrolesproxy/", "", 401, "no token found"},
		{"http://example.emptyrolesproxy/", wrongAuthHeader, 403, "signature is invalid"},
		{"http://example.emptyrolesproxy/", userHeader, 403, "user has role user, which is not in allowed roles ([])"},
		{"http://example.emptyrolesproxy/", adminHeader, 403, "user has role admin, which is not in allowed roles ([])"},
		{"http://example.emptyroleproxy/", "", 401, "no token found"},
		{"http://example.emptyroleproxy/", wrongAuthHeader, 403, "signature is invalid"},
		{"http://example.emptyroleproxy/", userHeader, 403, "user has role user, which is not in allowed roles ([])"},
		{"http://example.emptyroleproxy/", adminHeader, 403, "user has role admin, which is not in allowed roles ([])"},
		{"http://example.securedstatic/", "", 401, "no token found"},
		{"http://example.securedstatic/", wrongAuthHeader, 403, "signature is invalid"},
		{"http://example.securedstatic/", userHeader, 200, "contents of index.html"},
		{"http://example.securedstatic/", adminHeader, 200, "contents of index.html"},
		{"http://example.adminsecuredstatic/", "", 401, "no token found"},
		{"http://example.adminsecuredstatic/", wrongAuthHeader, 403, "signature is invalid"},
		{"http://example.adminsecuredstatic/", userHeader, 403, "user has role user, which is not in allowed roles ([admin])"},
		{"http://example.adminsecuredstatic/", adminHeader, 200, "contents of index.html"},
	}

	// Run tests
	for _, test := range tests {
		tester.DoRequestOnHandler(t, s, "GET", test.url, test.authHeader, "", test.code, test.body)
	}

	// Create redirect tests
	var redirectTests = []struct {
		url      string
		code     int
		location string
	}{
		{"http://example.localredirect/", 302, "https://example.localredirect:443"},
		{"http://example.globalredirect/", 302, "https://global.example.globalredirect"},
	}

	// Run redirect tests
	for _, test := range redirectTests {
		rw := httptest.NewRecorder()
		rw.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", test.url, nil)
		s.ServeHTTP(rw, req)
		if g, w := rw.Code, test.code; g != w {
			t.Errorf("%s: code = %d, want %d", test.url, g, w)
		}
		if g, w := rw.Header().Get("Location"), test.location; g != w {
			t.Errorf("%s: location header = %q, want %q", test.url, g, w)
		}
	}
}

func testHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK"))
}

func testRedirectLocalHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "http://a.local.adress", http.StatusFound)
}

func testRedirectGlobalHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://global."+r.Host, http.StatusFound)
}

func writeApps(apps []*app) (name string) {
	f, err := ioutil.TempFile("", "webfront-apps")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	err = json.NewEncoder(f).Encode(apps)
	if err != nil {
		panic(err)
	}
	return f.Name()
}
