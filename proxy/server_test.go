package proxy

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"../types"
)

func TestServer(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(testHandler))
	defer target.Close()

	ruleFile := writeRules([]*rule{
		{Rule: types.Rule{Host: "example.com", IsProxy: true, ForwardTo: target.Listener.Addr().String()}},
		{Rule: types.Rule{Host: "example.org", IsProxy: false, Serve: "testdata"}},
	})
	defer os.Remove(ruleFile)

	s, err := NewServer(ruleFile, 2443, "localhost", "localhost")
	if err != nil {
		t.Fatal(err)
	}

	var tests = []struct {
		url  string
		code int
		body string
	}{
		{"http://example.com/", 200, "OK"},
		{"http://foo.example.com/", 200, "OK"},
		{"http://example.org/", 200, "contents of index.html\n"},
		{"http://example.net/", 404, "Not found.\n"},
		{"http://fooexample.com/", 404, "Not found.\n"},
	}

	for _, test := range tests {
		rw := httptest.NewRecorder()
		rw.Body = new(bytes.Buffer)
		req, _ := http.NewRequest("GET", test.url, nil)
		s.ServeHTTP(rw, req)
		if g, w := rw.Code, test.code; g != w {
			t.Errorf("%s: code = %d, want %d", test.url, g, w)
		}
		if g, w := rw.Body.String(), test.body; g != w {
			t.Errorf("%s: body = %q, want %q", test.url, g, w)
		}
	}
}

func testHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK"))
}

func writeRules(rules []*rule) (name string) {
	f, err := ioutil.TempFile("", "webfront-rules")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	err = json.NewEncoder(f).Encode(rules)
	if err != nil {
		panic(err)
	}
	return f.Name()
}
