package types

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

// Mutex used to lock file writing
var lock sync.Mutex

// JWTPayload represents the payload of a JWT
type JWTPayload struct {
	User
	jwt.StandardClaims
}

// User represents an application user
type User struct {
	ID               int    `json:"id"`
	Login            string `json:"login"`
	Name             string `json:"name"`
	Surname          string `json:"surname"`
	Role             string `json:"role"`
	PasswordHash     string `json:"passwordHash"`
	Password         string `json:"password,omitempty"`
	Path             string `json:"path,omitempty"`             // For share token
	SharingUserLogin string `json:"sharingUserLogin,omitempty"` // For share token
}

// SendUsers send users as response from an http requests
func SendUsers(w http.ResponseWriter, req *http.Request) {
	var users []User
	err := Load("./config/users.json", &users)
	if err != nil {
		http.Error(w, err.Error(), 400)
	} else {
		json.NewEncoder(w).Encode(users)
	}
}

// SetUsers sets users from an http request
func SetUsers(w http.ResponseWriter, req *http.Request) {
	var users []User
	if req.Body == nil {
		http.Error(w, "please send a request body", 400)
		return
	}
	jsonErr := json.NewDecoder(req.Body).Decode(&users)
	if jsonErr != nil {
		http.Error(w, jsonErr.Error(), 400)
		return
	}
	for key, user := range users {
		if user.Password == "" && user.PasswordHash == "" {
			http.Error(w, "passwords cannot be blank", 400)
			return
		}
		if user.Password != "" {
			hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			users[key].PasswordHash = string(hash)
			users[key].Password = ""
		}
	}

	err := Save("./config/users.json", &users)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	SendUsers(w, req)
}

// MatchUser attempt to find the given user against users in configuration file
func MatchUser(sentUser User) (User, error) {
	var emptyUser User
	var users []User
	err := Load("./config/users.json", &users)
	if err != nil {
		fmt.Println(err.Error())
		return emptyUser, err
	}
	for _, user := range users {
		if user.Login == sentUser.Login {
			notFound := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(sentUser.Password))
			if notFound == nil {
				return user, nil
			}
		}
	}
	return emptyUser, errors.New("user not found")
}

// FilesACL represents an access control list for an directory exposed with webdav
type FilesACL struct {
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	Directory   string   `json:"directory"`
	Roles       []string `json:"roles"`
	Permissions string   `json:"permissions"`
	BasicAuth   bool     `json:"basicauth"`
}

// SendFilesACLs send files acls as response from an http requests
func SendFilesACLs(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	var filesacls []FilesACL
	err := Load("./config/filesacls.json", &filesacls)
	if err != nil {
		http.Error(w, err.Error(), 400)
	} else {
		json.NewEncoder(w).Encode(filesacls)
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
	err := Load("./client/package.json", &clientPackage)
	if err != nil {
		return Infos{}, err
	}
	clientVersion := clientPackage.(map[string]interface{})["version"].(string)

	// Get the server version

	// Get the bookmarks
	var bookmarks []Bookmark
	err = Load("./config/bookmarks.json", &bookmarks)
	if err != nil {
		return Infos{}, err
	}
	return Infos{
		ServerVersion: "3.0.2",
		ClientVersion: clientVersion,
		Bookmarks:     bookmarks,
	}, nil
}

// Rule represents a rule to serve static content or to proxy a web server
type Rule struct {
	Name       string `json:"name"`
	IsProxy    bool   `json:"isProxy"`   // true if reverse proxy
	Host       string `json:"host"`      // to match against request Host header
	ForwardTo  string `json:"forwardTo"` // non-empty if reverse proxy
	Serve      string `json:"serve"`     // non-empty if file server
	Secured    bool   `json:"secured"`   // true if the handler is JWT secured
	Icon       string `json:"icon"`
	Rank       string `json:"rank"`
	Iframed    bool   `json:"iframed"`
	IframePath string `json:"iframepath"`
	Login      string `json:"login"`    // Basic auth login for automatic login
	Password   string `json:"password"` // Basic auth password for automatic login
}

// SendRules send rules as response from an http requests
func SendRules(w http.ResponseWriter, req *http.Request) {
	var rules []Rule
	err := Load("./config/rules.json", &rules)
	if err != nil {
		http.Error(w, err.Error(), 400)
	} else {
		json.NewEncoder(w).Encode(rules)
	}
}

// SetRules sets rules from an http request
func SetRules(w http.ResponseWriter, req *http.Request) {
	var rules []Rule
	if req.Body == nil {
		http.Error(w, "please send a request body", 400)
		return
	}
	err := json.NewDecoder(req.Body).Decode(&rules)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	// Strip schemes from hosts
	for key, val := range rules {
		if strings.HasPrefix(val.Host, "http://") {
			rules[key].Host = strings.TrimPrefix(val.Host, "http://")
		}
		if strings.HasPrefix(val.Host, "https://") {
			rules[key].Host = strings.TrimPrefix(val.Host, "https://")
		}
	}
	err = Save("./config/rules.json", &rules)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	SendRules(w, req)
}

// Save saves a representation of v to the file at path.
func Save(path string, v interface{}) error {
	lock.Lock()
	defer lock.Unlock()
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := Marshal(v)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, r)
	return err
}

// Load loads the file at path into v. Use os.IsNotExist() to see if the returned error is due to the file being missing.
func Load(path string, v interface{}) error {
	lock.Lock()
	defer lock.Unlock()
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return Unmarshal(f, v)
}

// Marshal is a function that marshals the object into an io.Reader. By default, it uses the JSON marshaller.
var Marshal = func(v interface{}) (io.Reader, error) {
	b, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}

// Unmarshal is a function that unmarshals the data from the reader into the specified value. By default, it uses the JSON unmarshaller.
var Unmarshal = func(r io.Reader, v interface{}) error {
	return json.NewDecoder(r).Decode(v)
}
