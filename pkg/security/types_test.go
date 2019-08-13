package security

import (
	"net/http"
	"os"
	"testing"

	"github.com/nicolaspernoud/ninicobox-v3-server/pkg/tester"
)

func TestSetUsers(t *testing.T) {
	// Create config directory (errors are not handled, since is testing)
	os.MkdirAll("configs", os.ModePerm)
	// Delete config directory after completion (errors are not handled, since is testing)
	defer os.RemoveAll("configs")

	handler := http.HandlerFunc(SetUsers)
	tester.DoRequestOnHandler(t, handler, "POST", "/", "", `[
		{
			"id": 1,
			"login": "admin",
			"password": "password"
		},
		{
			"id": 2,
			"login": "user",
			"password": "password"
		}
	]`, http.StatusOK, `[{"id":1,"login":"admin"`)
	tester.DoRequestOnHandler(t, handler, "POST", "/", "", `[
		{
			"id": 1,
			"login": "admin",
			"password": "password"
		},
		{
			"id": 1,
			"login": "user",
			"password": "password"
		}
	]`, http.StatusBadRequest, `IDs must be uniques`)
}
