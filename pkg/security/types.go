package security

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/nicolaspernoud/ninicobox-v3-server/pkg/common"
	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type key int

const (
	// ContextLogin is the connected user login from the request context
	ContextLogin key = 0
	// ContextRole is the connected user role from the request context
	ContextRole key = 1
	gB              = 1 << (10 * 3)
)

// CommonClaims represents the claims common to Auth and Share tokens
type CommonClaims struct {
	Login string `json:"login"`
	Role  string `json:"role"`
	jwt.StandardClaims
}

// AuthToken represents a token identifying an user
type AuthToken struct {
	CommonClaims
	CSRFToken string `json:"csrftoken"`
}

// ShareToken represents a token identifying an user
type ShareToken struct {
	CommonClaims
	URL              string `json:"url,omitempty"`              // For share token
	SharingUserLogin string `json:"sharingUserLogin,omitempty"` // For share token
}

// User represents an application user
type User struct {
	ID             int    `json:"id"`
	Login          string `json:"login"`
	Name           string `json:"name"`
	Surname        string `json:"surname"`
	Role           string `json:"role"`
	PasswordHash   string `json:"passwordHash"`
	Password       string `json:"password,omitempty"`
	LongLivedToken bool   `json:"longLivedToken"`
}

// SendUsers send users as response from an http requests
func SendUsers(w http.ResponseWriter, req *http.Request) {
	var users []User
	err := common.Load("./configs/users.json", &users)
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

	err := common.Save("./configs/users.json", &users)
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
	err := common.Load("./configs/users.json", &users)
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
