package log

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

// Logger represents a standard logger sets up for this application usage
var Logger *log.Logger

func init() {
	// Initialize logger
	Logger = log.New(os.Stdout, "", log.LstdFlags)
}

// GetCityAndCountryFromRequest returns a string containing the city and the contry where the request is from
func GetCityAndCountryFromRequest(req *http.Request) string {
	// If the request remote adress is local return "localhost"
	if req.RemoteAddr == "" || strings.HasPrefix(req.RemoteAddr, "[::1]") || strings.HasPrefix(req.RemoteAddr, "127.0.0.1") {
		return "localhost"
	}
	db, err := maxminddb.Open("./ipgeodatabase/GeoLite2-City.mmdb")
	if err != nil {
		Logger.Fatal(err)
	}
	defer db.Close()

	ip := net.ParseIP(req.RemoteAddr)

	var record struct {
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
		Country struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"country"`
	}

	err = db.Lookup(ip, &record)
	if err != nil {
		Logger.Fatal(err)
	}
	return fmt.Sprintf("%v, %v", record.City.Names["fr"], record.Country.Names["fr"])
}
