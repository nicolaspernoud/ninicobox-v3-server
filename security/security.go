package security

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/nicolaspernoud/ninicobox-v3-server/types"
	"golang.org/x/crypto/bcrypt"
)

// ValidateJWTMiddleware tests if a JWT token is present and valid in the request and returns an Error if not
func ValidateJWTMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authorizationHeader := req.Header.Get("authorization")
		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, " ")
			if len(bearerToken) == 2 {
				token, error := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("There was an error")
					}
					return []byte("secret"), nil
				})
				if error != nil {
					http.Error(w, error.Error(), 400)
					return
				}
				if token.Valid {
					context.Set(req, "decoded", token.Claims)
					next(w, req)
				} else {
					http.Error(w, "Invalid authorization token", 400)
				}
			}
		} else {
			http.Error(w, "An authorization header is required", 401)
		}
	})
}

// Authenticate validate the username and password provided in the function body against a local file and return a token if the user is found
func Authenticate(w http.ResponseWriter, req *http.Request) {

	var sentUser types.User
	var error error
	error = json.NewDecoder(req.Body).Decode(&sentUser)
	if error != nil {
		http.Error(w, "Body is not correct", 400)
		return
	}
	// Try to match the user with an user in the database
	var user types.User
	user, error = matchUser(sentUser)
	if error != nil {
		http.Error(w, "User not found", 400)
		return
	}
	// If user is found, create and send a JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, types.JWTPayload{
		User: user,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(24)).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	})
	tokenString, error := token.SignedString([]byte("secret"))
	if error != nil {
		fmt.Println(error)
	}
	json.NewEncoder(w).Encode(types.JwtToken{Token: tokenString})
}

// matchUser attempt to find the given user against users in configuration file
func matchUser(sentUser types.User) (types.User, error) {
	var users []types.User
	var emptyUser types.User

	userFile, err := os.Open("./config/users.json")
	defer userFile.Close()
	if err != nil {
		fmt.Println(err.Error())
		return emptyUser, err
	}
	err = json.NewDecoder(userFile).Decode(&users)
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
