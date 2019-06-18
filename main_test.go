package main

import (
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"nicolaspernoud/ninicobox-v3-server/pkg/tester"
)

var (
	initialUsers              = `[{"id":1,"login":"admin","name":"Ad","surname":"MIN","role":"admin","passwordHash":"$2a$10$WQeaeTOQbzC1w3FP41x7tuHT.LI9AfjL1UV7LoYzozZ7XzAJ.YRtu","longLivedToken":true},{"id":2,"login":"user","name":"Us","surname":"ER","role":"user","passwordHash":"$2a$10$bWxtHLE.3pFkzg.XP4eR1eSBIkUOHiCaGvTUT3hiBxmhqtyRydA26","longLivedToken":false}]`
	updatedUsers              = `[{"id":1,"login":"admin","name":"Ad","surname":"MIN","role":"admin","password":"newpassword","passwordHash":"$2a$10$WQeaeTOQbzC1w3FP41x7tuHT.LI9AfjL1UV7LoYzozZ7XzAJ.YRtu","longLivedToken":true},{"id":2,"login":"user","name":"Us","surname":"ER","role":"user","passwordHash":"$2a$10$bWxtHLE.3pFkzg.XP4eR1eSBIkUOHiCaGvTUT3hiBxmhqtyRydA26","longLivedToken":false}]`
	initialAppsBuff, _        = ioutil.ReadFile("./configs/apps.json")
	reg, _                    = regexp.Compile("[\n \t]+")
	initialApps               = reg.ReplaceAllString(string(initialAppsBuff), "")
	updatedAppsWithSchemes    = strings.Replace(initialApps, "unsecuredreverseproxy.", "http://unsecuredreverseproxy.", 1)
	filteredApps              = `[{"name":"UnsecuredReverseProxy","icon":"navigation","rank":"1","iframed":true,"iframepath":"/test","isProxy":true,"host":"unsecuredreverseproxy.127.0.0.1.nip.io","forwardTo":"www.example.com","serve":"","secured":false,"login":"","password":"","roles":[]},{"name":"SecuredProxy","icon":"navigation","rank":"2","iframed":true,"iframepath":"/test","isProxy":true,"host":"securedreverseproxy.127.0.0.1.nip.io","forwardTo":"www.example.com","serve":"","secured":true,"login":"","password":"","roles":["admin","user"]},{"name":"StaticServer","icon":"folder","rank":"4","iframed":false,"iframepath":"","isProxy":false,"host":"staticserver.127.0.0.1.nip.io","forwardTo":"","serve":"./appserver/testdata","secured":false,"login":"","password":"","roles":[]}]`
	updatedUsersBlankPassword = `[{"id":1,"login":"admin","name":"Ad","surname":"MIN","role":"admin","password":"","passwordHash":""},{"id":2,"login":"user","name":"Us","surname":"ER","role":"user","passwordHash":"$2a$10$bWxtHLE.3pFkzg.XP4eR1eSBIkUOHiCaGvTUT3hiBxmhqtyRydA26"}]`
	shareTokenTarget          = `{"sharedfor":"download","url":"/api/files/usersrw/File%20users%2001.txt","lifespan":7}`
	wrongAuthHeader           = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwibG9naW4iOiJhZG1pbiIsIm5hbWUiOiJBZCIsInN1cm5hbWUiOiJNSU4iLCJyb2xlIjoiYWRtaW4iLCJwYXNzd29yZEhhc2giOiIkMmEkMTAkV1FlYWVUT1FiekMxdzNGUDQxeDd0dUhULkxJOUFmakwxVVY3TG9Zem96WjdYekFKLllSdHUiLCJleHAiOjE1MzMwMzI3MTUsImlhdCI6MTUzMzAyOTExNX0.3FF273T6VXxhFOLR3gjBvPvYwSxiiyF_XPVTE_U2PSg"
	basicAuthAdminHeader      = "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:password"))
)

func TestEndToEnd(t *testing.T) {
	rootMux, _ := createRootMux(*httpsPort, frameSource, *mainHostName)
	ts := httptest.NewServer(rootMux)
	defer ts.Close()

	url, _ := url.Parse(ts.URL)
	port := url.Port()

	// Try to access the general informations
	tester.DoRequestOnServer(t, port, "GET", "/api/infos", "", "", http.StatusOK, `{"server_version":`)

	var wg sync.WaitGroup
	functions := []func(t *testing.T, port string, wg *sync.WaitGroup){CheckUnidentifiedUser, CheckUser, CheckAdmin}
	for _, f := range functions {
		wg.Add(1)
		go f(t, port, &wg)
	}
	wg.Wait()
}

// === Try to access the resources as an unidentified user ===
func CheckUnidentifiedUser(t *testing.T, port string, wg *sync.WaitGroup) {
	defer wg.Done()
	// Do a login with an unknown user
	tester.DoRequestOnServer(t, port, "POST", "/api/login", "", `{"login": "unknownuser","password": "password"}`, http.StatusForbidden, `user not found`)
	// Do a login with a known user but bad password
	tester.DoRequestOnServer(t, port, "POST", "/api/login", "", `{"login": "admin","password": "badpassword"}`, http.StatusForbidden, `user not found`)
	// Try to use a token signed with the wrong key
	tester.DoRequestOnServer(t, port, "GET", "/api/common/filesacls", wrongAuthHeader, "", http.StatusForbidden, "signature is invalid")
	// Try to get the files access control lists
	tester.DoRequestOnServer(t, port, "GET", "/api/common/filesacls", "", "", http.StatusUnauthorized, "no token found")
	// Try to get the users
	tester.DoRequestOnServer(t, port, "GET", "/api/admin/users", "", "", http.StatusUnauthorized, "no token found")
	// Try to update the users
	tester.DoRequestOnServer(t, port, "POST", "/api/admin/users", "", updatedUsers, http.StatusUnauthorized, "no token found")
	// Try to get the apps
	tester.DoRequestOnServer(t, port, "GET", "/api/common/apps", "", "", http.StatusUnauthorized, "no token found")
	// Try to update the apps
	tester.DoRequestOnServer(t, port, "POST", "/api/admin/apps", "", updatedAppsWithSchemes, http.StatusUnauthorized, "no token found")
	// Try to read a webdav resource
	tester.DoRequestOnServer(t, port, "GET", "/api/files/usersrw/File users 01.txt", "", "", http.StatusUnauthorized, "no token found")
	// Try to create a webdav resource
	tester.DoRequestOnServer(t, port, "PUT", "/api/files/adminsrw/Test.txt", "", "This is a test", http.StatusUnauthorized, "no token found")
	// Try to delete a webdav resource
	tester.DoRequestOnServer(t, port, "DELETE", "/api/files/usersrw/Test.txt", "", "", http.StatusUnauthorized, "no token found")
	// Try to get a share token for an user reserved resource
	tester.DoRequestOnServer(t, port, "POST", "/api/common/getsharetoken", "", shareTokenTarget, http.StatusUnauthorized, "no token found")
	// Try to get a basic auth protected webdav ressource without basic auth
	tester.DoRequestOnServer(t, port, "GET", "/api/files/basicauth/File admins 01.txt", "", "", http.StatusUnauthorized, "authorization header could not be processed")
	// Try to get an admin basic auth protected webdav ressource with incorrect basic auth
	tester.DoRequestOnServer(t, port, "GET", "/api/files/basicauth/File admins 01.txt", "Basic "+base64.StdEncoding.EncodeToString([]byte("password")), "", http.StatusForbidden, "user not found")
}

// === Try to access the resources as an normal user ===
func CheckUser(t *testing.T, port string, wg *sync.WaitGroup) {
	defer wg.Done()
	// Do a login with an incorrect method
	tester.DoRequestOnServer(t, port, "GET", "/api/login", "", `{"login": "user","password": "password"}`, http.StatusMethodNotAllowed, "method not allowed")
	// Do a login with the correct user
	userHeader := "Bearer " + tester.DoRequestOnServer(t, port, "POST", "/api/login", "", `{"login": "user","password": "password"}`, http.StatusOK, `eyJhbG`)
	t.Logf("Got user auth header: %v", userHeader)
	// Try to post the files access control lists (should fail)
	tester.DoRequestOnServer(t, port, "POST", "/api/common/filesacls", userHeader, "", http.StatusMethodNotAllowed, "method not allowed")
	// Try to get the files access control lists
	tester.DoRequestOnServer(t, port, "GET", "/api/common/filesacls", userHeader, "", http.StatusOK, `[{"name":"Users Read Only","path":"usersro","directory":"./data/admins","roles":["user","guest"],"permissions":"r","basicauth":false`)
	// Try to get the users
	tester.DoRequestOnServer(t, port, "GET", "/api/admin/users", userHeader, "", http.StatusForbidden, "user has role user, which is not in allowed roles ([admin])")
	// Try to update the users
	tester.DoRequestOnServer(t, port, "POST", "/api/admin/users", userHeader, updatedUsers, http.StatusForbidden, "user has role user, which is not in allowed roles ([admin])")
	// Try to get the apps
	tester.DoRequestOnServer(t, port, "GET", "/api/common/apps", userHeader, "", http.StatusOK, filteredApps)
	// Try to update the apps
	tester.DoRequestOnServer(t, port, "POST", "/api/admin/apps", userHeader, updatedAppsWithSchemes, http.StatusForbidden, "user has role user, which is not in allowed roles ([admin])")
	// Try to read a webdav resource
	tester.DoRequestOnServer(t, port, "GET", "/api/files/usersrw/File users 01.txt", userHeader, "", http.StatusOK, "Lorem ipsum")
	// Try to walk back the shared path (gives index.html)
	tester.DoRequestOnServer(t, port, "GET", "/api/files/usersrw/Folder user 01/../..", userHeader, "", http.StatusNotFound, "")
	// Try to create a webdav resource
	tester.DoRequestOnServer(t, port, "PUT", "/api/files/adminsrw/Test.txt", userHeader, "This is a test", http.StatusForbidden, "user has role user, which is not in allowed roles ([admin])")
	// Try to delete a webdav resource
	tester.DoRequestOnServer(t, port, "DELETE", "/api/files/adminsrw/Test.txt", userHeader, "", http.StatusForbidden, "user has role user, which is not in allowed roles ([admin])")
	// Try to get a share token with an empty url
	tester.DoRequestOnServer(t, port, "POST", "/api/common/getsharetoken", userHeader, `{"sharedfor":"download","url":"","lifespan":7}`, http.StatusBadRequest, `url cannot be empty`)
	// Try to get a share token for an user reserved resource
	shareToken := tester.DoRequestOnServer(t, port, "POST", "/api/common/getsharetoken", userHeader, shareTokenTarget, http.StatusOK, `eyJhbG`)
	t.Logf("Got share token: %v", shareToken)
	// Try to use the share token in an header
	tester.DoRequestOnServer(t, port, "GET", "/api/files/usersrw/File users 01.txt", "Bearer "+shareToken, "", http.StatusForbidden, "CSRF protection triggered")
	// Try to use the share token for the token path
	tester.DoRequestOnServer(t, port, "GET", "/api/files/usersrw/File users 01.txt?token="+shareToken, "", "", http.StatusOK, "Lorem ipsum")
	// Try to use the share token to alter the ressource
	tester.DoRequestOnServer(t, port, "PUT", "/api/files/usersrw/File users 01.txt?token="+shareToken, "", "new content", http.StatusMethodNotAllowed, "the share token can only be used for the GET method")
	// Try to use the share token for a different path than the token path
	tester.DoRequestOnServer(t, port, "GET", "/api/files/usersrw/File users 02.txt?token="+shareToken, "", "", http.StatusForbidden, "the share token can only be used for the given path")
	// Try to get a share token for an admin reserved resource (it's possible but the token will not be usable)
	shareToken = tester.DoRequestOnServer(t, port, "POST", "/api/common/getsharetoken", userHeader, `{"sharedfor":"download","url":"/api/files/adminsrw/File%20admins%2001.txt","lifespan":7}`, http.StatusOK, `eyJhbG`)
	// Try to use the share token for the admin token path
	tester.DoRequestOnServer(t, port, "GET", "/api/files/adminsrw/File admins 01.txt?token="+shareToken, "", "", http.StatusForbidden, "user has role user, which is not in allowed roles ([admin])")
	// Try to get an admin basic auth protected webdav ressource with user basic auth
	tester.DoRequestOnServer(t, port, "GET", "/api/files/basicauth/File admins 01.txt", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:password")), "", http.StatusForbidden, "user has role user, which is not in allowed roles ([admin])")
	// Try to get a share token for an allowed app hostname
	shareToken = tester.DoRequestOnServer(t, port, "POST", "/api/common/getsharetoken", userHeader, `{"sharedfor":"download","url":"securedreverseproxy.127.0.0.1.nip.io","lifespan":7}`, http.StatusOK, `eyJhbG`)
	t.Logf("Got share token: %v", shareToken)
	// Try to use the share token for the allowed app
	tester.DoRequestOnServer(t, port, "GET", "securedreverseproxy.127.0.0.1.nip.io?token="+shareToken, "", "", http.StatusOK, "<!doctype html>\n<html>\n<head>\n    <title>Example Domain</title>")
	// Try to use the share token for an admin only app
	tester.DoRequestOnServer(t, port, "GET", "adminonlyproxy.127.0.0.1.nip.io?token="+shareToken, "", "", http.StatusForbidden, "the share token can only be used for the given host")
	// Try to use the share token for an admin file
	tester.DoRequestOnServer(t, port, "GET", "/api/files/adminsrw/File admins 01.txt?token="+shareToken, "", "", http.StatusForbidden, "the share token can only be used for the given host")
}

// === Try to access the resources as an admin ===
func CheckAdmin(t *testing.T, port string, wg *sync.WaitGroup) {
	defer wg.Done()
	// Do a login with the correct admin user
	adminHeader := "Bearer " + tester.DoRequestOnServer(t, port, "POST", "/api/login", "", `{"login": "admin","password": "password"}`, http.StatusOK, `eyJhbG`)
	t.Logf("Got admin auth header: %v", adminHeader)
	// Try to get the files access control lists
	tester.DoRequestOnServer(t, port, "GET", "/api/common/filesacls", adminHeader, "", http.StatusOK, `[{"name":"Users Read Write","path":"usersrw","directory":"./data/users","roles":["user","admin"],"permissions":"rw","basicauth":false`)
	// Try to get the users
	tester.DoRequestOnServer(t, port, "GET", "/api/admin/users", adminHeader, "", http.StatusOK, initialUsers)
	// Try to update the users with a blank password
	tester.DoRequestOnServer(t, port, "POST", "/api/admin/users", adminHeader, updatedUsersBlankPassword, http.StatusBadRequest, "passwords cannot be blank")
	// Try to update the users
	tester.DoRequestOnServer(t, port, "POST", "/api/admin/users", adminHeader, updatedUsers, http.StatusOK, `[{"id":1,"login":"admin",`)
	// Try to get the apps
	tester.DoRequestOnServer(t, port, "GET", "/api/common/apps", adminHeader, "", http.StatusOK, initialApps)
	// Try to update the apps with schemes
	tester.DoRequestOnServer(t, port, "POST", "/api/admin/apps", adminHeader, updatedAppsWithSchemes, http.StatusOK, initialApps)
	// Try to login with old password
	tester.DoRequestOnServer(t, port, "POST", "/api/login", "", `{"login": "admin","password": "password"}`, http.StatusForbidden, `user not found`)
	// Update the user to revert to old password
	tester.DoRequestOnServer(t, port, "POST", "/api/admin/users", adminHeader, initialUsers, http.StatusOK, initialUsers)
	// Try again to login
	adminHeader = "Bearer " + tester.DoRequestOnServer(t, port, "POST", "/api/login", "", `{"login": "admin","password": "password"}`, http.StatusOK, `eyJhbG`)
	// Try to read a webdav resource
	tester.DoRequestOnServer(t, port, "GET", "/api/files/usersrw/File users 01.txt", adminHeader, "", http.StatusOK, "Lorem ipsum")
	// Try to create a webdav resource
	tester.DoRequestOnServer(t, port, "PUT", "/api/files/adminsrw/Test.txt", adminHeader, "This is a test", http.StatusCreated, "Created")
	// Try to read the created resource
	tester.DoRequestOnServer(t, port, "GET", "/api/files/adminsrw/Test.txt", adminHeader, "", http.StatusOK, "This is a test")
	// Try to delete a webdav resource
	tester.DoRequestOnServer(t, port, "DELETE", "/api/files/adminsrw/Test.txt", adminHeader, "", http.StatusNoContent, "")
	// Try to read a non basic auth webdav resource with basic auth header
	tester.DoRequestOnServer(t, port, "GET", "/api/files/usersrw/File users 01.txt", basicAuthAdminHeader, "", http.StatusForbidden, "token contains an invalid number of segments")
	// Try to read a webdav resource with basic auth
	tester.DoRequestOnServer(t, port, "GET", "/api/files/basicauth/File admins 01.txt", basicAuthAdminHeader, "", http.StatusOK, "Lorem ipsum")
	// Try to create a webdav resource with basic auth
	tester.DoRequestOnServer(t, port, "PUT", "/api/files/basicauth/Test basic auth.txt", basicAuthAdminHeader, "This is a test", http.StatusCreated, "Created")
	// Try to read the created resource with basic auth
	tester.DoRequestOnServer(t, port, "GET", "/api/files/basicauth/Test basic auth.txt", basicAuthAdminHeader, "", http.StatusOK, "This is a test")
	// Try to delete a webdav resource with basic auth
	tester.DoRequestOnServer(t, port, "DELETE", "/api/files/basicauth/Test basic auth.txt", basicAuthAdminHeader, "", http.StatusNoContent, "")
}
