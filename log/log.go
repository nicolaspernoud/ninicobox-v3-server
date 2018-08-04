package log

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

var Logger *log.Logger

func init() {
	// Initialize logger
	Logger = log.New(os.Stdout, "", log.LstdFlags)
}

// GetCityAndCountryFromRequest returns a string containing the city and the contry where the request is from
func GetCityAndCountryFromRequest(req *http.Request) string {
	db, err := maxminddb.Open("test-data/test-data/GeoIP2-City-Test.mmdb")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	ip := net.ParseIP("81.2.69.142")

	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	} // Or any appropriate struct

	err = db.Lookup(ip, &record)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(record.Country.ISOCode)
	// Output:
	// GB
}
