package webdavaug

import (
	"archive/zip"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"../log"
	"../security"
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
func New(prefix string, directory string, allowedRoles []string, canWrite bool, basicAuth bool) WebdavAug {

	unsecuredZip := http.StripPrefix(prefix, ZipServer(directory))
	unsecuredWebdav := &webdav.Handler{
		Prefix:     prefix,
		FileSystem: webdav.Dir(directory),
		LockSystem: webdav.NewMemLS(),
		Logger:     webdavLogger,
	}

	var zip http.Handler
	var webdav http.Handler
	if basicAuth {
		zip = security.ValidateBasicAuthMiddleware(unsecuredZip, allowedRoles)
		webdav = security.ValidateBasicAuthMiddleware(unsecuredWebdav, allowedRoles)
	} else {
		zip = security.ValidateJWTMiddleware(unsecuredZip, allowedRoles)
		webdav = security.ValidateJWTMiddleware(unsecuredWebdav, allowedRoles)
	}

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
				filename := url.PathEscape(filepath.Base(r.URL.Path))
				w.Header().Set("Content-Disposition", "attachment; filename*="+filename)
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
		log.Logger.Printf("| %v | Webdav access error : [%s] %s, %s | %v | %v", user, r.Method, r.URL, err, r.RemoteAddr, log.GetCityAndCountryFromRequest(r))
	} else {
		log.Logger.Printf("| %v | Webdav access : [%s] %s | %v | %v", user, r.Method, r.URL.Path, r.RemoteAddr, log.GetCityAndCountryFromRequest(r))
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
	webdavLogger(r, nil)
	zipAndServe(w, zh.root, path.Clean(upath))
}

func zipAndServe(w http.ResponseWriter, root string, name string) {

	source := filepath.Join(root, filepath.FromSlash(path.Clean("/"+name)))

	size, err := maxZipSize(source)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("content-length", strconv.FormatInt(size, 10))

	archive := zip.NewWriter(w)
	defer archive.Close()

	var rootPath string

	err = filepath.Walk(source, func(path string, info os.FileInfo, err error) error {

		// On root call, set filename and rootPath
		if rootPath == "" {
			rootPath = path
			w.Header().Set("Content-Disposition", "attachment; filename="+info.Name()+".zip")
		}

		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		header.Name, err = filepath.Rel(rootPath, path)
		if err != nil {
			return err
		}
		header.Method = zip.Deflate

		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
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

func maxZipSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size() + 262144 // Allow 256 kB for zip files overhead (headers, etc.)
		}
		return err
	})
	return size, err
}
