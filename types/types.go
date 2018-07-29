package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

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
	Path             string `json:"path"`             // For share token
	SharingUserLogin string `json:"sharingUserLogin"` // For share token
}

// UsersToJSONFile write an array of users in a json file
func UsersToJSONFile(users *[]User, file string) error {
	return structToJSONFile(users, file)
}

// UsersFromJSONFile create an array of users from a json file
func UsersFromJSONFile(file string) ([]User, error) {
	var users []User
	jsonFile, err := os.Open(file)
	defer jsonFile.Close()
	if err != nil {
		return nil, err
	}
	return users, json.NewDecoder(jsonFile).Decode(&users)
}

// SendUsers send users as response from an http requests
func SendUsers(w http.ResponseWriter, req *http.Request) {
	users, error := UsersFromJSONFile("./config/users.json")
	if error != nil {
		http.Error(w, error.Error(), 400)
	} else {
		json.NewEncoder(w).Encode(users)
	}
}

// SetUsers sets users from an http request
func SetUsers(w http.ResponseWriter, req *http.Request) {
	var users []User
	if req.Body == nil {
		http.Error(w, "Please send a request body", 400)
		return
	}
	jsonErr := json.NewDecoder(req.Body).Decode(&users)
	if jsonErr != nil {
		http.Error(w, jsonErr.Error(), 400)
		return
	}
	for key, user := range users {
		if user.Password == "" && user.PasswordHash == "" {
			http.Error(w, "Passwords cannot be blank", 400)
			return
		}
		if user.Password != "" {
			hash, error := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
			if error != nil {
				http.Error(w, error.Error(), 400)
				return
			}
			users[key].PasswordHash = string(hash)
			users[key].Password = ""
		}
	}

	err := UsersToJSONFile(&users, "./config/users.json")
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	fmt.Fprintf(w, "Users updated")
}

// MatchUser attempt to find the given user against users in configuration file
func MatchUser(sentUser User) (User, error) {
	var emptyUser User
	users, err := UsersFromJSONFile("./config/users.json")
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
	return emptyUser, errors.New("User not found")
}

// FilesACL represents an access control list for an directory exposed with webdav
type FilesACL struct {
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	Directory   string   `json:"directory"`
	Roles       []string `json:"roles"`
	Permissions string   `json:"permissions"`
}

// ACLsFromJSONFile create an array of access control lists from a json file
func ACLsFromJSONFile(file string) ([]FilesACL, error) {
	var filesacls []FilesACL
	jsonFile, err := os.Open(file)
	defer jsonFile.Close()
	if err != nil {
		return nil, err
	}
	return filesacls, json.NewDecoder(jsonFile).Decode(&filesacls)
}

// SendFilesACLs send files acls as response from an http requests
func SendFilesACLs(w http.ResponseWriter, req *http.Request) {
	filesacls, error := ACLsFromJSONFile("./config/filesacls.json")
	if error != nil {
		http.Error(w, error.Error(), 400)
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
	infos, error := InfosFromJSONFiles()
	if error != nil {
		http.Error(w, error.Error(), 400)
	} else {
		json.NewEncoder(w).Encode(infos)
	}
}

// InfosFromJSONFiles returns Infos gotten from several json files
func InfosFromJSONFiles() (Infos, error) {
	// Get the client version
	var clientPackage interface{}
	jsonFile, err := os.Open("./client_package.json")
	defer jsonFile.Close()
	if err != nil {
		return Infos{}, err
	}
	err = json.NewDecoder(jsonFile).Decode(&clientPackage)
	clientVersion := clientPackage.(map[string]interface{})["version"].(string)

	// Get the server version

	// Get the bookmarks
	var bookmarks []Bookmark
	jsonFile, err = os.Open("./config/bookmarks.json")
	defer jsonFile.Close()
	if err != nil {
		return Infos{}, err
	}
	err = json.NewDecoder(jsonFile).Decode(&bookmarks)
	if err != nil {
		return Infos{}, err
	}
	return Infos{
		ServerVersion: "wip",
		ClientVersion: clientVersion,
		Bookmarks:     bookmarks,
	}, nil
}

func structToJSONFile(structure interface{}, file string) error {
	jsonData, err := json.Marshal(structure)
	if err != nil {
		return err
	}
	jsonFile, err := os.Create(file)
	if err != nil {
		return err
	}
	_, err = jsonFile.Write(jsonData)
	if err != nil {
		return err
	}
	err = jsonFile.Close()
	if err != nil {
		return err
	}
	return nil
}
