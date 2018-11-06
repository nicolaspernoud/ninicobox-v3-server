package security

import "testing"

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
