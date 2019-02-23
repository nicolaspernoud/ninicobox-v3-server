package security

import (
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"

	"../../pkg/common"
	"../../pkg/tester"
)

func TestMatchUser(t *testing.T) {
	// Create config directory (errors are not handled, since is testing)
	os.MkdirAll("configs", os.ModePerm)
	// Copy config file from parent directory (errors are not handled, since is testing)
	input, _ := ioutil.ReadFile("../../configs/users.json")
	ioutil.WriteFile("./configs/users.json", input, os.ModePerm)
	// Delete config directory after completion (errors are not handled, since is testing)
	defer os.RemoveAll("configs")

	existingUser := User{ID: 2, Login: "user", Name: "Us", Surname: "ER", Role: "user", PasswordHash: "$2a$10$bWxtHLE.3pFkzg.XP4eR1eSBIkUOHiCaGvTUT3hiBxmhqtyRydA26"}
	veryLongString := string(common.RandomByteArray(10000))
	specialCharString := "\""

	type args struct {
		sentUser User
	}
	tests := []struct {
		name    string
		args    args
		want    User
		wantErr bool
	}{
		{"user_exists", args{User{Login: "user", Password: "password"}}, existingUser, false},
		{"user_does_not_exists", args{User{Login: "notuser", Password: "password"}}, User{}, true},
		{"user_does_not_exists_and_wrong_password", args{User{Login: "notuser", Password: "wrongpassword"}}, User{}, true},
		{"wrong_password", args{User{Login: "user", Password: "wrongpassword"}}, User{}, true},
		{"no_password", args{User{Login: "user", Password: ""}}, User{}, true},
		{"empty_user", args{User{Login: "", Password: "password"}}, User{}, true},
		{"empty_user_and_password", args{User{Login: "", Password: ""}}, User{}, true},
		{"very_long_string_as_user", args{User{Login: veryLongString, Password: "password"}}, User{}, true},
		{"very_long_string_as_password", args{User{Login: "user", Password: veryLongString}}, User{}, true},
		{"very_long_string_as_user_and_password", args{User{Login: veryLongString, Password: veryLongString}}, User{}, true},
		{"special_char_string_as_user", args{User{Login: specialCharString, Password: "password"}}, User{}, true},
		{"special_char_string_as_password", args{User{Login: "user", Password: specialCharString}}, User{}, true},
		{"special_char_string_as_user_and_password", args{User{Login: specialCharString, Password: specialCharString}}, User{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MatchUser(tt.args.sentUser)
			if (err != nil) != tt.wantErr {
				t.Errorf("MatchUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MatchUser() = %v, want %v", got, tt.want)
			}
		})
	}
}

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
	os.MkdirAll("configs", os.ModePerm)
	// Copy config file from parent directory (errors are not handled, since is testing)
	input, _ := ioutil.ReadFile("../../configs/users.json")
	ioutil.WriteFile("./configs/users.json", input, os.ModePerm)
	// Delete config directory after completion (errors are not handled, since is testing)
	defer os.RemoveAll("configs")

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
