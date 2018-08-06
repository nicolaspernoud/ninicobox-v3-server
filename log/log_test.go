package log

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetCityAndCountryFromRequest(t *testing.T) {

	ipDbLocation = "../ipgeodatabase/GeoLite2-City.mmdb"

	requestFromLocalHost := httptest.NewRequest("GET", "/test", strings.NewReader(""))
	requestFromLocalHost.RemoteAddr = "[::1]:1234"

	requestFromLondon := httptest.NewRequest("GET", "/test", strings.NewReader(""))
	requestFromLondon.RemoteAddr = "81.2.69.142"

	type args struct {
		req *http.Request
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Request from localhost",
			args: args{
				req: requestFromLocalHost,
			},
			want: "localhost",
		},
		{
			name: "Request from london",
			args: args{
				req: requestFromLondon,
			},
			want: "Londres, Royaume-Uni",
		},
		{
			name: "Request from london, again",
			args: args{
				req: requestFromLondon,
			},
			want: "Londres, Royaume-Uni (from cache)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetCityAndCountryFromRequest(tt.args.req); got != tt.want {
				t.Errorf("GetCityAndCountryFromRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}
