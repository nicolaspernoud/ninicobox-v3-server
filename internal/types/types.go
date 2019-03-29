package types

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"../../pkg/common"
	"../../pkg/du"
	"../../pkg/security"
)

const (
	gB = 1 << (10 * 3)
)

// FilesACL represents an access control list for an directory exposed with webdav
type FilesACL struct {
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	Directory   string   `json:"directory"`
	Roles       []string `json:"roles"`
	Permissions string   `json:"permissions"`
	BasicAuth   bool     `json:"basicauth"`
	UsedGB      uint64   `json:"usedgb"`
	TotalGB     uint64   `json:"totalgb"`
}

// SendFilesACLs send files acls as response from an http requests
func SendFilesACLs(w http.ResponseWriter, req *http.Request) {
	role := req.Context().Value(security.ContextRole).(string)
	if req.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	var filesacls []FilesACL
	err := common.Load("./configs/filesacls.json", &filesacls)
	if err != nil {
		http.Error(w, err.Error(), 400)
	} else {
		sentfilesacls := filesacls[:0]
		for _, filesacl := range filesacls {
			for _, allowedRole := range filesacl.Roles {
				if !filesacl.BasicAuth && (role == allowedRole || allowedRole == "all") {
					usage, err := du.NewDiskUsage(filesacl.Directory)
					if err != nil {
						fmt.Printf("Error getting disk usage: %v\n", err)
					} else {
						filesacl.UsedGB = usage.Used() / gB
						filesacl.TotalGB = usage.Size() / gB
					}
					sentfilesacls = append(sentfilesacls, filesacl)
					break
				}
			}
		}
		json.NewEncoder(w).Encode(sentfilesacls)
	}
}

// Infos represents global infos shared by the server with the client
type Infos struct {
	ServerVersion string     `json:"server_version"`
	ClientVersion string     `json:"client_version"`
	Bookmarks     []Bookmark `json:"bookmarks"`
}

// Bookmark represents a bookmark shared by the server with the client into the infos
type Bookmark struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Icon string `json:"icon"`
}

// SendInfos send infos as response from an http requests
func SendInfos(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	infos, err := InfosFromJSONFiles()
	if err != nil {
		http.Error(w, err.Error(), 400)
	} else {
		json.NewEncoder(w).Encode(infos)
	}
}

// InfosFromJSONFiles returns Infos gotten from several json files
func InfosFromJSONFiles() (Infos, error) {
	// Get the client version
	var clientPackage interface{}
	err := common.Load("./web/package.json", &clientPackage)
	if err != nil {
		return Infos{}, err
	}
	clientVersion := clientPackage.(map[string]interface{})["version"].(string)

	// Get the server version

	// Get the bookmarks
	var bookmarks []Bookmark
	err = common.Load("./configs/bookmarks.json", &bookmarks)
	if err != nil {
		return Infos{}, err
	}
	return Infos{
		ServerVersion: "3.1.18",
		ClientVersion: clientVersion,
		Bookmarks:     bookmarks,
	}, nil
}

// App represents a app serving static content proxying a web server
type App struct {
	Name       string   `json:"name"`
	IsProxy    bool     `json:"isProxy"`   // true if reverse proxy
	Host       string   `json:"host"`      // to match against request Host header
	ForwardTo  string   `json:"forwardTo"` // non-empty if reverse proxy
	Serve      string   `json:"serve"`     // non-empty if file server
	Secured    bool     `json:"secured"`   // true if the handler is JWT secured
	Icon       string   `json:"icon"`
	Rank       string   `json:"rank"`
	Iframed    bool     `json:"iframed"`
	IframePath string   `json:"iframepath"`
	Login      string   `json:"login"`    // Basic auth login for automatic login
	Password   string   `json:"password"` // Basic auth password for automatic login
	Roles      []string `json:"roles"`    // Roles allowed to access the app
}

// SendApps send apps as response from an http requests
func SendApps(w http.ResponseWriter, req *http.Request) {
	role := req.Context().Value(security.ContextRole).(string)
	var apps []App
	err := common.Load("./configs/apps.json", &apps)
	if err != nil {
		http.Error(w, err.Error(), 400)
	} else {
		if role != "admin" {
			tmp := apps[:0]
			for _, app := range apps {
				allowed := false
				for _, allowedRole := range app.Roles {
					if role == allowedRole || allowedRole == "all" {
						allowed = true
						break
					}
				}
				if !app.Secured || allowed {
					tmp = append(tmp, app)
				}
			}
			apps = tmp
		}
		json.NewEncoder(w).Encode(apps)
	}
}

// SetApps sets apps from an http request
func SetApps(w http.ResponseWriter, req *http.Request) {
	var apps []App
	if req.Body == nil {
		http.Error(w, "please send a request body", 400)
		return
	}
	err := json.NewDecoder(req.Body).Decode(&apps)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	// Strip schemes from hosts
	for key, val := range apps {
		if strings.HasPrefix(val.Host, "http://") {
			apps[key].Host = strings.TrimPrefix(val.Host, "http://")
		}
		if strings.HasPrefix(val.Host, "https://") {
			apps[key].Host = strings.TrimPrefix(val.Host, "https://")
		}
	}
	err = common.Save("./configs/apps.json", &apps)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	SendApps(w, req)
}
