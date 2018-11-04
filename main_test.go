package main

import (
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"./appserver"
	"./tester"
)

func Test_MainRouter(t *testing.T) {
	appServer, _ := appserver.NewServer("./config/apps.json", 80, "localhost", "localhost")
	router := createMainMux(appServer)

	initialUsers := `[{"id":1,"login":"admin","name":"Ad","surname":"MIN","role":"admin","passwordHash":"$2a$10$WQeaeTOQbzC1w3FP41x7tuHT.LI9AfjL1UV7LoYzozZ7XzAJ.YRtu"},{"id":2,"login":"user","name":"Us","surname":"ER","role":"user","passwordHash":"$2a$10$bWxtHLE.3pFkzg.XP4eR1eSBIkUOHiCaGvTUT3hiBxmhqtyRydA26"}]`
	updatedUsers := `[{"id":1,"login":"admin","name":"Ad","surname":"MIN","role":"admin","password":"newpassword","passwordHash":"$2a$10$WQeaeTOQbzC1w3FP41x7tuHT.LI9AfjL1UV7LoYzozZ7XzAJ.YRtu"},{"id":2,"login":"user","name":"Us","surname":"ER","role":"user","passwordHash":"$2a$10$bWxtHLE.3pFkzg.XP4eR1eSBIkUOHiCaGvTUT3hiBxmhqtyRydA26"}]`
	initialAppsBuff, _ := ioutil.ReadFile("./config/apps.json")
	initialApps := string(initialAppsBuff)
	reg, _ := regexp.Compile("[\n \t]+")
	initialApps = reg.ReplaceAllString(initialApps, "")
	updatedAppsWithSchemes := strings.Replace(initialApps, "www.", "http://www.", 1)
	updatedUsersBlankPassword := `[{"id":1,"login":"admin","name":"Ad","surname":"MIN","role":"admin","password":"","passwordHash":""},{"id":2,"login":"user","name":"Us","surname":"ER","role":"user","passwordHash":"$2a$10$bWxtHLE.3pFkzg.XP4eR1eSBIkUOHiCaGvTUT3hiBxmhqtyRydA26"}]`
	shareTokenTargetPath := "/api/files/usersrw/File users 01.txt"
	wrongAuthHeader := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwibG9naW4iOiJhZG1pbiIsIm5hbWUiOiJBZCIsInN1cm5hbWUiOiJNSU4iLCJyb2xlIjoiYWRtaW4iLCJwYXNzd29yZEhhc2giOiIkMmEkMTAkV1FlYWVUT1FiekMxdzNGUDQxeDd0dUhULkxJOUFmakwxVVY3TG9Zem96WjdYekFKLllSdHUiLCJleHAiOjE1MzMwMzI3MTUsImlhdCI6MTUzMzAyOTExNX0.3FF273T6VXxhFOLR3gjBvPvYwSxiiyF_XPVTE_U2PSg"
	basicAuthAdminHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:password"))

	// Try to access the general informations
	tester.DoRequest(t, router, "GET", "/api/infos", "", "", http.StatusOK, `{"server_version":`)

	// === Try to access the resources as an unidentified user ===
	// Do a login with an unknown user
	tester.DoRequest(t, router, "POST", "/api/login", "", `{"login": "unknownuser","password": "password"}`, http.StatusForbidden, `user not found`)
	// Do a login with a known user but bad password
	tester.DoRequest(t, router, "POST", "/api/login", "", `{"login": "admin","password": "badpassword"}`, http.StatusForbidden, `user not found`)
	// Try to use a token signed with the wrong key
	tester.DoRequest(t, router, "GET", "/api/common/filesacls", wrongAuthHeader, "", http.StatusForbidden, "signature is invalid")
	// Try to get the files access control lists
	tester.DoRequest(t, router, "GET", "/api/common/filesacls", "", "", http.StatusUnauthorized, "no token found")
	// Try to get the users
	tester.DoRequest(t, router, "GET", "/api/admin/users", "", "", http.StatusUnauthorized, "no token found")
	// Try to update the users
	tester.DoRequest(t, router, "POST", "/api/admin/users", "", updatedUsers, http.StatusUnauthorized, "no token found")
	// Try to get the apps
	tester.DoRequest(t, router, "GET", "/api/common/apps", "", "", http.StatusUnauthorized, "no token found")
	// Try to update the apps
	tester.DoRequest(t, router, "POST", "/api/admin/apps", "", updatedAppsWithSchemes, http.StatusUnauthorized, "no token found")
	// Try to read a webdav resource
	tester.DoRequest(t, router, "GET", "/api/files/usersrw/File users 01.txt", "", "", http.StatusUnauthorized, "no token found")
	// Try to create a webdav resource
	tester.DoRequest(t, router, "PUT", "/api/files/adminsrw/Test.txt", "", "This is a test", http.StatusUnauthorized, "no token found")
	// Try to delete a webdav resource
	tester.DoRequest(t, router, "DELETE", "/api/files/usersrw/Test.txt", "", "", http.StatusUnauthorized, "no token found")
	// Try to get a share token for an user reserved resource
	tester.DoRequest(t, router, "POST", "/api/common/getsharetoken", "", shareTokenTargetPath, http.StatusUnauthorized, "no token found")
	// Try to get a basic auth protected webdav ressource without basic auth
	tester.DoRequest(t, router, "GET", "/api/files/basicauth/File admins 01.txt", "", "", http.StatusUnauthorized, "authorization header could not be processed")
	// Try to get an admin basic auth protected webdav ressource with incorrect basic auth
	tester.DoRequest(t, router, "GET", "/api/files/basicauth/File admins 01.txt", "Basic "+base64.StdEncoding.EncodeToString([]byte("password")), "", http.StatusForbidden, "user not found")

	// === Try to access the resources as an normal user ===
	// Do a login with an incorrect method
	tester.DoRequest(t, router, "GET", "/api/login", "", `{"login": "user","password": "password"}`, http.StatusMethodNotAllowed, "method not allowed")
	// Do a login with the correct user
	userHeader := "Bearer " + tester.DoRequest(t, router, "POST", "/api/login", "", `{"login": "user","password": "password"}`, http.StatusOK, `eyJhbG`)
	t.Logf("Got user auth header: %v", userHeader)
	// Try to post the files access control lists (should fail)
	tester.DoRequest(t, router, "POST", "/api/common/filesacls", userHeader, "", http.StatusMethodNotAllowed, "method not allowed")
	// Try to get the files access control lists
	tester.DoRequest(t, router, "GET", "/api/common/filesacls", userHeader, "", http.StatusOK, `[{"name":"Users Read Only"`)
	// Try to get the users
	tester.DoRequest(t, router, "GET", "/api/admin/users", userHeader, "", http.StatusForbidden, "user has role user, which is not in allowed roles ([admin])")
	// Try to update the users
	tester.DoRequest(t, router, "POST", "/api/admin/users", userHeader, updatedUsers, http.StatusForbidden, "user has role user, which is not in allowed roles ([admin])")
	// Try to get the apps
	tester.DoRequest(t, router, "GET", "/api/common/apps", userHeader, "", http.StatusOK, initialApps)
	// Try to update the apps
	tester.DoRequest(t, router, "POST", "/api/admin/apps", userHeader, updatedAppsWithSchemes, http.StatusForbidden, "user has role user, which is not in allowed roles ([admin])")
	// Try to read a webdav resource
	tester.DoRequest(t, router, "GET", "/api/files/usersrw/File users 01.txt", userHeader, "", http.StatusOK, "Lorem ipsum")
	// Try to walk back the shared path
	tester.DoRequest(t, router, "GET", "/api/files/usersrw/Folder user 01/../..", userHeader, "", http.StatusMovedPermanently, "")
	// Try to create a webdav resource
	tester.DoRequest(t, router, "PUT", "/api/files/adminsrw/Test.txt", userHeader, "This is a test", http.StatusForbidden, "user has role user, which is not in allowed roles ([admin])")
	// Try to delete a webdav resource
	tester.DoRequest(t, router, "DELETE", "/api/files/adminsrw/Test.txt", userHeader, "", http.StatusForbidden, "user has role user, which is not in allowed roles ([admin])")
	// Try to get a share token with an empty path
	tester.DoRequest(t, router, "POST", "/api/common/getsharetoken", userHeader, "", http.StatusBadRequest, `path cannot be empty, and must began with /api/files`)
	// Try to get a share token for an user reserved resource
	shareHeader := "Bearer " + tester.DoRequest(t, router, "POST", "/api/common/getsharetoken", userHeader, shareTokenTargetPath, http.StatusOK, `eyJhbG`)
	t.Logf("Got share token auth header: %v", shareHeader)
	// Try to use the share token for the token path
	tester.DoRequest(t, router, "GET", "/api/files/usersrw/File users 01.txt", shareHeader, "", http.StatusOK, "Lorem ipsum")
	// Try to use the share token for a different path than the token path
	tester.DoRequest(t, router, "GET", "/api/files/usersrw/File users 02.txt", shareHeader, "", http.StatusForbidden, "the share token can only be used for the given path")
	// Try to get a share token for an admin reserved resource (it's possible but the token will not be usable)
	shareHeader = "Bearer " + tester.DoRequest(t, router, "POST", "/api/common/getsharetoken", userHeader, "/api/files/adminsrw/File admins 01.txt", http.StatusOK, `eyJhbG`)
	// Try to use the share token for the admin token path
	tester.DoRequest(t, router, "GET", "/api/files/adminsrw/File admins 01.txt", shareHeader, "", http.StatusForbidden, "user has role user, which is not in allowed roles ([admin])")
	// Try to get an admin basic auth protected webdav ressource with user basic auth
	tester.DoRequest(t, router, "GET", "/api/files/basicauth/File admins 01.txt", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:password")), "", http.StatusForbidden, "user has role user, which is not in allowed roles ([admin])")

	// === Try to access the resources as an admin ===
	// Do a login with the correct admin user
	adminHeader := "Bearer " + tester.DoRequest(t, router, "POST", "/api/login", "", `{"login": "admin","password": "password"}`, http.StatusOK, `eyJhbG`)
	t.Logf("Got admin auth header: %v", adminHeader)
	// Try to get the files access control lists
	tester.DoRequest(t, router, "GET", "/api/common/filesacls", adminHeader, "", http.StatusOK, `[{"name":"Users Read Only"`)
	// Try to get the users
	tester.DoRequest(t, router, "GET", "/api/admin/users", adminHeader, "", http.StatusOK, initialUsers)
	// Try to update the users with a blank password
	tester.DoRequest(t, router, "POST", "/api/admin/users", adminHeader, updatedUsersBlankPassword, http.StatusBadRequest, "passwords cannot be blank")
	// Try to update the users
	tester.DoRequest(t, router, "POST", "/api/admin/users", adminHeader, updatedUsers, http.StatusOK, `[{"id":1,"login":"admin",`)
	// Try to get the apps
	tester.DoRequest(t, router, "GET", "/api/common/apps", adminHeader, "", http.StatusOK, initialApps)
	// Try to update the apps with schemes
	tester.DoRequest(t, router, "POST", "/api/admin/apps", adminHeader, updatedAppsWithSchemes, http.StatusOK, initialApps)
	// Try to login with old password
	tester.DoRequest(t, router, "POST", "/api/login", "", `{"login": "admin","password": "password"}`, http.StatusForbidden, `user not found`)
	// Update the user to revert to old password
	tester.DoRequest(t, router, "POST", "/api/admin/users", adminHeader, initialUsers, http.StatusOK, initialUsers)
	// Try again to login
	adminHeader = "Bearer " + tester.DoRequest(t, router, "POST", "/api/login", "", `{"login": "admin","password": "password"}`, http.StatusOK, `eyJhbG`)
	// Try to read a webdav resource
	tester.DoRequest(t, router, "GET", "/api/files/usersrw/File users 01.txt", adminHeader, "", http.StatusOK, "Lorem ipsum")
	// Try to create a webdav resource
	tester.DoRequest(t, router, "PUT", "/api/files/adminsrw/Test.txt", adminHeader, "This is a test", http.StatusCreated, "Created")
	// Try to read the created resource
	tester.DoRequest(t, router, "GET", "/api/files/adminsrw/Test.txt", adminHeader, "", http.StatusOK, "This is a test")
	// Try to delete a webdav resource
	tester.DoRequest(t, router, "DELETE", "/api/files/adminsrw/Test.txt", adminHeader, "", http.StatusNoContent, "")
	// Try to read a non basic auth webdav resource with basic auth header
	tester.DoRequest(t, router, "GET", "/api/files/usersrw/File users 01.txt", basicAuthAdminHeader, "", http.StatusForbidden, "token contains an invalid number of segments")
	// Try to read a webdav resource with basic auth
	tester.DoRequest(t, router, "GET", "/api/files/basicauth/File admins 01.txt", basicAuthAdminHeader, "", http.StatusOK, "Lorem ipsum")
	// Try to create a webdav resource with basic auth
	tester.DoRequest(t, router, "PUT", "/api/files/basicauth/Test basic auth.txt", basicAuthAdminHeader, "This is a test", http.StatusCreated, "Created")
	// Try to read the created resource with basic auth
	tester.DoRequest(t, router, "GET", "/api/files/basicauth/Test basic auth.txt", basicAuthAdminHeader, "", http.StatusOK, "This is a test")
	// Try to delete a webdav resource with basic auth
	tester.DoRequest(t, router, "DELETE", "/api/files/basicauth/Test basic auth.txt", basicAuthAdminHeader, "", http.StatusNoContent, "")
}
