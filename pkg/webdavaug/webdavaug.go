package webdavaug

import (
	"archive/zip"
	"image"
	"image/jpeg"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/disintegration/imaging"

	"github.com/nicolaspernoud/ninicobox-v3-server/pkg/common"
	"github.com/nicolaspernoud/ninicobox-v3-server/pkg/log"
	"github.com/nicolaspernoud/ninicobox-v3-server/pkg/security"

	"golang.org/x/net/webdav"
)

// WebdavAug represents an augmented webdav which :
// - is secured with basic auth or json web tokens (JWT)
// - enable download of directories as streamed zip files
type WebdavAug struct {
	prefix        string
	directory     string
	methodMux     map[string]http.Handler
	zipHandler    http.Handler
	resizeHandler http.Handler
}

// New create an initialized WebdavAug instance
func New(prefix string, directory string, allowedRoles []string, canWrite bool, basicAuth bool) WebdavAug {

	unsecuredZip := http.StripPrefix(prefix, ZipServer(directory))
	unsecuredResize := http.StripPrefix(prefix, ResizeServer(directory))
	unsecuredWebdav := &webdav.Handler{
		Prefix:     prefix,
		FileSystem: webdav.Dir(directory),
		LockSystem: webdav.NewMemLS(),
		Logger:     webdavLogger,
	}

	var securityMiddleware func(http.Handler, []string) http.Handler
	if basicAuth {
		securityMiddleware = security.ValidateBasicAuthMiddleware
	} else {
		securityMiddleware = security.ValidateJWTMiddleware
	}

	zip := securityMiddleware(unsecuredZip, allowedRoles)
	resize := securityMiddleware(unsecuredResize, allowedRoles)
	webdav := securityMiddleware(unsecuredWebdav, allowedRoles)

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
		prefix:        prefix,
		directory:     directory,
		methodMux:     mMux,
		zipHandler:    zip,
		resizeHandler: resize,
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
				_, inline := r.URL.Query()["inline"]
				if !inline {
					w.Header().Set("Content-Disposition", "attachment; filename*="+filename)
				}
			} else {
				h = wdaug.zipHandler
			}
		}
		if resize := r.URL.Query().Get("resize"); r.Method == "PUT" && strings.Contains(r.Header.Get("content-type"), "image/jp") && resize != "" {
			h = wdaug.resizeHandler
		}
		h.ServeHTTP(w, r)
	} else {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func webdavLogger(r *http.Request, err error) {
	user := security.UserLoginFromContext(r.Context())
	if !common.Contains([]string{"PROPFIND", "OPTIONS", "LOCK", "UNLOCK", "GET"}, r.Method) || strings.Contains(user, "_share_") {
		if err != nil {
			log.Logger.Printf("| %v | Webdav access error : [%s] %s, %s | %v | %v", user, r.Method, r.URL, err, r.RemoteAddr, log.GetCityAndCountryFromRequest(r))
		} else {
			log.Logger.Printf("| %v | Webdav access : [%s] %s | %v | %v", user, r.Method, r.URL.Path, r.RemoteAddr, log.GetCityAndCountryFromRequest(r))
		}
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
			w.Header().Set("Content-Disposition", "attachment; filename*="+url.PathEscape(info.Name())+".zip")
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

type resizeHandler struct {
	root string
}

// ResizeServer write the uploaded content as a jpg image after resizing it
func ResizeServer(root string) http.Handler {
	return &resizeHandler{root}
}

func (rh *resizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	webdavLogger(r, nil)
	ressource := r.URL.Path
	fullName := filepath.Join(rh.root, filepath.FromSlash(path.Clean("/"+ressource)))

	img, _, err := image.Decode(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnsupportedMediaType)
		return
	}

	minRes, err := strconv.Atoi(r.URL.Query().Get("resize"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	width := img.Bounds().Dx()
	height := img.Bounds().Dy()

	var m image.Image
	// Do not try to upsize the image
	if minRes >= width || minRes >= height {
		m = img
	} else if width >= height { // Landscape images
		m = imaging.Resize(img, 0, minRes, imaging.Lanczos)
	} else { // Portrait image
		m = imaging.Resize(img, minRes, 0, imaging.Lanczos)
	}
	// Prepare the out file
	out, err := os.Create(fullName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer out.Close()

	err = jpeg.Encode(out, m, &jpeg.Options{90})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
