package webdavaug

import (
	"log"
	"net/http"
	"strings"

	"github.com/nicolaspernoud/ninicobox-v3-server/security"
	"golang.org/x/net/webdav"
)

// WebdavAug represents an augmented webdav which :
// - is secured with basic auth or json web tokens (JWT)
// - enable download of directories as streamed zip files
type WebdavAug struct {
	prefix    string
	methodMux map[string]http.Handler
}

// New create an initialized WebdavAug instance
func New(prefix string, directory string, allowedRoles []string, canWrite bool) WebdavAug {

	unsecuredFiles := http.StripPrefix(prefix, http.FileServer(http.Dir(directory)))
	unsecuredWebdav := &webdav.Handler{
		Prefix:     prefix,
		FileSystem: webdav.Dir(directory),
		LockSystem: webdav.NewMemLS(),
		Logger:     webdavLogger,
	}

	files := security.ValidateJWTMiddleware(unsecuredFiles, allowedRoles)
	webdav := security.ValidateJWTMiddleware(unsecuredWebdav, allowedRoles)

	if canWrite {
		return WebdavAug{
			prefix: prefix,
			methodMux: map[string]http.Handler{
				"GET":       files,
				"OPTIONS":   webdav,
				"PROPFIND":  webdav,
				"PROPPATCH": webdav,
				"MKCOL":     webdav,
				"COPY":      webdav,
				"MOVE":      webdav,
				"LOCK":      webdav,
				"UNLOCK":    webdav,
				"DELETE":    webdav,
				"PUT":       webdav,
			},
		}
	}
	return WebdavAug{
		prefix: prefix,
		methodMux: map[string]http.Handler{
			"GET":      files,
			"OPTIONS":  webdav,
			"PROPFIND": webdav,
		},
	}

}

func (wdaug WebdavAug) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h, ok := wdaug.methodMux[r.Method]; ok {
		if r.Method == "GET" {
			filename := strings.TrimPrefix(r.URL.Path, wdaug.prefix+"/")
			w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		}
		h.ServeHTTP(w, r)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func webdavLogger(r *http.Request, err error) {
	if err != nil {
		log.Printf("WEBDAV [%s]: %s, ERROR: %s\n", r.Method, r.URL, err)
	} else {
		log.Printf("WEBDAV [%s]: %s \n", r.Method, r.URL)
	}
}
