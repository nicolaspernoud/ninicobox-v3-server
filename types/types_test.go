package types

import (
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

func TestMatchUser(t *testing.T) {
	// Create config directory (errors are not handled, since is testing)
	os.MkdirAll("config", os.ModePerm)
	// Copy config file from parent directory (errors are not handled, since is testing)
	input, _ := ioutil.ReadFile("../config/users.json")
	ioutil.WriteFile("./config/users.json", input, os.ModePerm)
	// Delete config directory after completion (errors are not handled, since is testing)
	defer os.RemoveAll("config")

	existingUser := User{ID: 2, Login: "user", Name: "Us", Surname: "ER", Role: "user", PasswordHash: "$2a$10$bWxtHLE.3pFkzg.XP4eR1eSBIkUOHiCaGvTUT3hiBxmhqtyRydA26"}
	veryLongString := string(RandomByteArray(10000))

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
