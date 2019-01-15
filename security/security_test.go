package security

import (
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"../tester"
)

func Test_checkUserRoleIsAllowed(t *testing.T) {
	type args struct {
		userRole     string
		allowedRoles []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"role_exists", args{"user", []string{"user", "admin"}}, false},
		{"allow_all", args{"user", []string{"all", "admin"}}, false},
		{"role_does_not_exists", args{"notuser", []string{"user", "admin"}}, true},
		{"empty_role", args{"", []string{"user", "admin"}}, true},
		{"emptystr_role_and_empty_roles_array", args{"", []string{}}, true},
		{"space_role_and_empty_roles_array", args{" ", []string{}}, true},
		{"space_role_and_emptystr_roles_array", args{" ", []string{""}}, true},
		{"emptystr_role_and_emptystr_roles_array", args{"", []string{"", "admin"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkUserRoleIsAllowed(tt.args.userRole, tt.args.allowedRoles); (err != nil) != tt.wantErr {
				t.Errorf("checkUserRoleIsAllowed() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestJWTAuthAndMiddleware(t *testing.T) {

	// Create config directory (errors are not handled, since is testing)
	os.MkdirAll("config", os.ModePerm)
	// Copy config file from parent directory (errors are not handled, since is testing)
	input, _ := ioutil.ReadFile("../config/users.json")
	ioutil.WriteFile("./config/users.json", input, os.ModePerm)
	// Delete config directory after completion (errors are not handled, since is testing)
	defer os.RemoveAll("config")

	// Get old JWTs
	now = func() time.Time { return time.Now().Add(time.Hour * time.Duration(-24*8)) }
	veryOldAdminHeader := "Bearer " + tester.DoRequestOnHandler(t, http.HandlerFunc(Authenticate), "POST", "/api/login", "", `{"login": "admin","password": "password"}`, http.StatusOK, `eyJhbG`)
	now = func() time.Time { return time.Now().Add(time.Hour * time.Duration(-24*6)) }
	oldUserHeader := "Bearer " + tester.DoRequestOnHandler(t, http.HandlerFunc(Authenticate), "POST", "/api/login", "", `{"login": "user","password": "password"}`, http.StatusOK, `eyJhbG`)
	oldAdminHeader := "Bearer " + tester.DoRequestOnHandler(t, http.HandlerFunc(Authenticate), "POST", "/api/login", "", `{"login": "admin","password": "password"}`, http.StatusOK, `eyJhbG`)
	// Get JWTs
	now = time.Now
	userHeader := "Bearer " + tester.DoRequestOnHandler(t, http.HandlerFunc(Authenticate), "POST", "/api/login", "", `{"login": "user","password": "password"}`, http.StatusOK, `eyJhbG`)
	adminHeader := "Bearer " + tester.DoRequestOnHandler(t, http.HandlerFunc(Authenticate), "POST", "/api/login", "", `{"login": "admin","password": "password"}`, http.StatusOK, `eyJhbG`)
	wrongAuthHeader := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwibG9naW4iOiJhZG1pbiIsIm5hbWUiOiJBZCIsInN1cm5hbWUiOiJNSU4iLCJyb2xlIjoiYWRtaW4iLCJwYXNzd29yZEhhc2giOiIkMmEkMTAkV1FlYWVUT1FiekMxdzNGUDQxeDd0dUhULkxJOUFmakwxVVY3TG9Zem96WjdYekFKLllSdHUiLCJleHAiOjE1MzMwMzI3MTUsImlhdCI6MTUzMzAyOTExNX0.3FF273T6VXxhFOLR3gjBvPvYwSxiiyF_XPVTE_U2PSg"

	handler := ValidateJWTMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}), []string{"admin", "user"})
	tester.DoRequestOnHandler(t, handler, "GET", "/", veryOldAdminHeader, ``, http.StatusForbidden, `token is expired`)
	tester.DoRequestOnHandler(t, handler, "GET", "/", oldUserHeader, ``, http.StatusForbidden, `token is expired`)
	tester.DoRequestOnHandler(t, handler, "GET", "/", oldAdminHeader, ``, http.StatusOK, `OK`)
	tester.DoRequestOnHandler(t, handler, "GET", "/", userHeader, ``, http.StatusOK, `OK`)
	tester.DoRequestOnHandler(t, handler, "GET", "/", adminHeader, ``, http.StatusOK, `OK`)
	tester.DoRequestOnHandler(t, handler, "GET", "/", wrongAuthHeader, ``, http.StatusForbidden, `signature is invalid`)
}
