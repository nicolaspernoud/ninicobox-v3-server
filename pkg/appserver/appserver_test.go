package appserver

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/nicolaspernoud/ninicobox-v3-server/pkg/security"
	"github.com/nicolaspernoud/ninicobox-v3-server/pkg/tester"
)

func TestServer(t *testing.T) {
	// Create config directory (errors are not handled, since is testing)
	os.MkdirAll("configs", os.ModePerm)
	// Copy config file from parent directory (errors are not handled, since is testing)
	input, _ := ioutil.ReadFile("../../configs/users.json")
	ioutil.WriteFile("./configs/users.json", input, os.ModePerm)
	// Delete config directory after completion (errors are not handled, since is testing)
	defer os.RemoveAll("configs")

	// Get JWTs
	userHeader := "Bearer " + tester.DoRequestOnHandler(t, http.HandlerFunc(security.Authenticate), "POST", "/api/login", "", `{"login": "user","password": "password"}`, http.StatusOK, `eyJhbG`)
	adminHeader := "Bearer " + tester.DoRequestOnHandler(t, http.HandlerFunc(security.Authenticate), "POST", "/api/login", "", `{"login": "admin","password": "password"}`, http.StatusOK, `eyJhbG`)
	wrongAuthHeader := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwibG9naW4iOiJhZG1pbiIsIm5hbWUiOiJBZCIsInN1cm5hbWUiOiJNSU4iLCJyb2xlIjoiYWRtaW4iLCJwYXNzd29yZEhhc2giOiIkMmEkMTAkV1FlYWVUT1FiekMxdzNGUDQxeDd0dUhULkxJOUFmakwxVVY3TG9Zem96WjdYekFKLllSdHUiLCJleHAiOjE1MzMwMzI3MTUsImlhdCI6MTUzMzAyOTExNX0.3FF273T6VXxhFOLR3gjBvPvYwSxiiyF_XPVTE_U2PSg"

	// Create the proxy target servers
	target := httptest.NewServer(http.HandlerFunc(testHandler))
	defer target.Close()

	redirectAbsoluteTarget := httptest.NewServer(http.HandlerFunc(testAbsoluteRedirectHandler))
	defer redirectAbsoluteTarget.Close()

	redirectRelativeTarget := httptest.NewServer(http.HandlerFunc(testRelativeRedirectHandler))
	defer redirectRelativeTarget.Close()

	// Create apps
	appFile := writeApps([]*app{
		{App: App{Host: "test.unsecuredproxy", IsProxy: true, ForwardTo: target.Listener.Addr().String()}},
		{App: App{Host: "*.test.wildcard", IsProxy: true, ForwardTo: target.Listener.Addr().String()}},
		{App: App{Host: "test.unsecuredstatic", IsProxy: false, Serve: "testdata"}},
		{App: App{Host: "test.absoluteredirect", IsProxy: true, ForwardTo: redirectAbsoluteTarget.Listener.Addr().String()}},
		{App: App{Host: "test.relativeredirect", IsProxy: true, ForwardTo: redirectRelativeTarget.Listener.Addr().String()}},
		{App: App{Host: "test.securedproxy", IsProxy: true, ForwardTo: target.Listener.Addr().String(), Secured: true, Roles: []string{"admin", "user"}}},
		{App: App{Host: "test.adminsecuredproxy", IsProxy: true, ForwardTo: target.Listener.Addr().String(), Secured: true, Roles: []string{"admin"}}},
		{App: App{Host: "test.emptyrolesproxy", IsProxy: true, ForwardTo: target.Listener.Addr().String(), Secured: true, Roles: []string{}}},
		{App: App{Host: "test.emptyroleproxy", IsProxy: true, ForwardTo: target.Listener.Addr().String(), Secured: true, Roles: []string{""}}},
		{App: App{Host: "test.securedstatic", IsProxy: false, Serve: "testdata", Secured: true, Roles: []string{"admin", "user"}}},
		{App: App{Host: "test.adminsecuredstatic", IsProxy: false, Serve: "testdata", Secured: true, Roles: []string{"admin"}}},
	})
	defer os.Remove(appFile)

	s, err := NewServer(appFile, 443, "localhost", "localhost", security.ValidateJWTMiddleware)
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
		{"http://test.unsecuredproxy/", "", 200, "OK"},
		{"http://foo.test.unsecuredproxy/", "", 404, "Not found."},
		{"http://footest.unsecuredproxy/", "", 404, "Not found."},
		{"http://test.wildcard/", "", 200, "OK"},
		{"http://foo.test.wildcard/", "", 200, "OK"},
		{"http://test.unsecuredstatic/", "", 200, "contents of index.html"},
		{"http://test.net/", "", 404, "Not found."},
		{"http://test.securedproxy/", "", 401, "no token found"},
		{"http://test.securedproxy/", wrongAuthHeader, 403, "signature is invalid"},
		{"http://test.securedproxy/", userHeader, 200, "OK"},
		{"http://test.securedproxy/", adminHeader, 200, "OK"},
		{"http://test.adminsecuredproxy/", "", 401, "no token found"},
		{"http://test.adminsecuredproxy/", wrongAuthHeader, 403, "signature is invalid"},
		{"http://test.adminsecuredproxy/", userHeader, 403, "user has role user, which is not in allowed roles ([admin])"},
		{"http://test.adminsecuredproxy/", adminHeader, 200, "OK"},
		{"http://test.emptyrolesproxy/", "", 401, "no token found"},
		{"http://test.emptyrolesproxy/", wrongAuthHeader, 403, "signature is invalid"},
		{"http://test.emptyrolesproxy/", userHeader, 403, "user has role user, which is not in allowed roles ([])"},
		{"http://test.emptyrolesproxy/", adminHeader, 403, "user has role admin, which is not in allowed roles ([])"},
		{"http://test.emptyroleproxy/", "", 401, "no token found"},
		{"http://test.emptyroleproxy/", wrongAuthHeader, 403, "signature is invalid"},
		{"http://test.emptyroleproxy/", userHeader, 403, "user has role user, which is not in allowed roles ([])"},
		{"http://test.emptyroleproxy/", adminHeader, 403, "user has role admin, which is not in allowed roles ([])"},
		{"http://test.securedstatic/", "", 401, "no token found"},
		{"http://test.securedstatic/", wrongAuthHeader, 403, "signature is invalid"},
		{"http://test.securedstatic/", userHeader, 200, "contents of index.html"},
		{"http://test.securedstatic/", adminHeader, 200, "contents of index.html"},
		{"http://test.adminsecuredstatic/", "", 401, "no token found"},
		{"http://test.adminsecuredstatic/", wrongAuthHeader, 403, "signature is invalid"},
		{"http://test.adminsecuredstatic/", userHeader, 403, "user has role user, which is not in allowed roles ([admin])"},
		{"http://test.adminsecuredstatic/", adminHeader, 200, "contents of index.html"},
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
		{"http://test.absoluteredirect/", 302, "https://test.absoluteredirect:443"},
		{"http://test.relativeredirect/", 302, "https://relative.redirect.test.relativeredirect"},
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

// Redirect is bad when is made absolute, regardless of the host header
func testAbsoluteRedirectHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://absolute.redirect.bad", http.StatusFound)
}

// Redirect is good when is redirect relative to the host header
func testRelativeRedirectHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://relative.redirect."+r.Host, http.StatusFound)
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
