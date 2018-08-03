package webdavaug

import (
	"archive/zip"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/nicolaspernoud/ninicobox-v3-server/security"
	"golang.org/x/net/webdav"
)

// WebdavAug represents an augmented webdav which :
// - is secured with basic auth or json web tokens (JWT)
// - enable download of directories as streamed zip files
type WebdavAug struct {
	prefix     string
	directory  string
	methodMux  map[string]http.Handler
	zipHandler http.Handler
}

// New create an initialized WebdavAug instance
func New(prefix string, directory string, allowedRoles []string, canWrite bool) WebdavAug {

	unsecuredZip := http.StripPrefix(prefix, ZipServer(directory))
	unsecuredWebdav := &webdav.Handler{
		Prefix:     prefix,
		FileSystem: webdav.Dir(directory),
		LockSystem: webdav.NewMemLS(),
		Logger:     webdavLogger,
	}

	zip := security.ValidateJWTMiddleware(unsecuredZip, allowedRoles)
	webdav := security.ValidateJWTMiddleware(unsecuredWebdav, allowedRoles)

	var mMux map[string]http.Handler

	if canWrite {
		mMux = map[string]http.Handler{
			"GET":       webdav,
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
		}
	} else {
		mMux = map[string]http.Handler{
			"GET":      webdav,
			"OPTIONS":  webdav,
			"PROPFIND": webdav,
		}
	}

	return WebdavAug{
		prefix:     prefix,
		directory:  directory,
		methodMux:  mMux,
		zipHandler: zip,
	}

}

func (wdaug WebdavAug) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h, ok := wdaug.methodMux[r.Method]; ok {
		if r.Method == "GET" {
			// Work out if trying to serve a directory
			ressource := strings.TrimPrefix(r.URL.Path, wdaug.prefix)
			fullName := filepath.Join(wdaug.directory, filepath.FromSlash(path.Clean("/"+ressource)))
			info, err := os.Stat(fullName)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !info.IsDir() { // The file will be handled by webdav server
				filename := strings.TrimPrefix(r.URL.Path, wdaug.prefix+"/")
				w.Header().Set("Content-Disposition", "attachment; filename="+filename)
			} else {
				h = wdaug.zipHandler
			}
		}
		h.ServeHTTP(w, r)
	} else {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func webdavLogger(r *http.Request, err error) {
	user := security.UserLoginFromContext(r.Context())
	if err != nil {
		log.Printf("WEBDAV [%s]: %s, USER: %v, ERROR: %s\n", r.Method, r.URL, user, err)
	} else {
		log.Printf("WEBDAV [%s]: %s, USER: %v\n", r.Method, r.URL, user)
	}
}

type zipHandler struct {
	root string
}

// ZipServer serve the content of a directory as streamed zip file
func ZipServer(root string) http.Handler {
	return &zipHandler{root}
}

func (zh *zipHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upath := r.URL.Path
	if !strings.HasPrefix(upath, "/") {
		upath = "/" + upath
		r.URL.Path = upath
	}
	zipAndServe(w, r, zh.root, path.Clean(upath))
}

func zipAndServe(w http.ResponseWriter, r *http.Request, root string, name string) {

	source := filepath.Join(root, filepath.FromSlash(path.Clean("/"+name)))

	archive := zip.NewWriter(w)
	defer archive.Close()

	info, err := os.Stat(source)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var baseDir string
	if info.IsDir() {
		baseDir = filepath.Base(source)
	}

	err = filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		if baseDir != "" {
			header.Name = filepath.Join(baseDir, strings.TrimPrefix(path, source))
		}

		if info.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Deflate
		}

		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(writer, file)
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}
