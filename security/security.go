package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/nicolaspernoud/ninicobox-v3-server/types"
	"golang.org/x/crypto/bcrypt"
)

var jWTSignature = randomString(48)

// AuthenticationMiddleware allow access for users of allowed Roles
type AuthenticationMiddleware struct {
	AllowedRoles []string
}

// // SetAllowedRoles sets the AuthenticationMiddleware allowed roles
// func (amw *AuthenticationMiddleware) SetAllowedRoles(allowedRoles []string) {
// 	amw.allowedRoles = allowedRoles
// }

// ValidateJWTMiddleware tests if a JWT token is present, and valid, in the request and returns an Error if not
func (amw *AuthenticationMiddleware) ValidateJWTMiddleware(next http.Handler) http.Handler {
	return ValidateJWTMiddleware(next, amw.AllowedRoles)
}

// ValidateJWTMiddleware tests if a JWT token is present, and valid, in the request and returns an Error if not
func ValidateJWTMiddleware(next http.Handler, allowedRoles []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		JWT, errExtractToken := ExtractToken(req)
		if errExtractToken != nil {
			http.Error(w, errExtractToken.Error(), 401)
			return
		}
		token, errParseToken := jwt.ParseWithClaims(JWT, &types.JWTPayload{}, func(token *jwt.Token) (interface{}, error) {
			return jWTSignature, nil
		})
		if errParseToken != nil {
			http.Error(w, errParseToken.Error(), 400)
			return
		}
		if claims, ok := token.Claims.(*types.JWTPayload); ok && token.Valid {
			if errRole := checkUserRoleIsAllowed(claims.Role, allowedRoles); errRole == nil {
				ctx := context.WithValue(req.Context(), "login", claims.Login)
				ctx = context.WithValue(ctx, "role", claims.Role)
				next.ServeHTTP(w, req.WithContext(ctx))
			} else {
				http.Error(w, errRole.Error(), 403)
			}
		} else {
			http.Error(w, "Invalid authorization token", 400)
		}
	})
}

// Authenticate validate the username and password provided in the function body against a local file and return a token if the user is found
func Authenticate(w http.ResponseWriter, req *http.Request) {
	var sentUser types.User
	var error error
	error = json.NewDecoder(req.Body).Decode(&sentUser)
	if error != nil {
		http.Error(w, error.Error(), 400)
		return
	}
	// Try to match the user with an user in the database
	var user types.User
	user, error = matchUser(sentUser)
	if error != nil {
		http.Error(w, error.Error(), 400)
		return
	}
	// If user is found, create and send a JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, types.JWTPayload{
		User: user,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(1)).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	})
	tokenString, error := token.SignedString(jWTSignature)
	if error != nil {
		http.Error(w, error.Error(), 400)
		return
	}
	json.NewEncoder(w).Encode(types.JwtToken{Token: tokenString})
}

// GetUsers get users from users.json file
func GetUsers() ([]types.User, error) {
	var users []types.User
	usrFile, err := os.Open("./config/users.json")
	defer usrFile.Close()
	if err != nil {
		fmt.Println(err.Error())
		return users, err
	}
	err = json.NewDecoder(usrFile).Decode(&users)
	return users, err
}

// SetUsers sets users from an http request
func SetUsers(w http.ResponseWriter, req *http.Request) {
	var users []types.User
	if req.Body == nil {
		http.Error(w, "Please send a request body", 400)
	}
	jsonErr := json.NewDecoder(req.Body).Decode(&users)
	if jsonErr != nil {
		http.Error(w, jsonErr.Error(), 400)
	}
	for key, user := range users {
		if user.Password != "" {
			hash, error := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
			if error != nil {
				http.Error(w, error.Error(), 400)
			}
			users[key].PasswordHash = string(hash)
			users[key].Password = ""
		}
	}

	jsonData, err := json.Marshal(users)
	if err != nil {
		http.Error(w, err.Error(), 400)
	}
	jsonFile, err := os.Create("./config/users.json")
	if err != nil {
		http.Error(w, err.Error(), 400)
	}
	_, err = jsonFile.Write(jsonData)
	if err != nil {
		http.Error(w, err.Error(), 400)
	}
	err = jsonFile.Close()
	if err != nil {
		http.Error(w, err.Error(), 400)
	}
	fmt.Fprintf(w, "Users updated")
}

// matchUser attempt to find the given user against users in configuration file
func matchUser(sentUser types.User) (types.User, error) {
	var emptyUser types.User
	users, err := GetUsers()
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

func checkUserRoleIsAllowed(userRole string, allowedRoles []string) error {
	for _, allowedRole := range allowedRoles {
		if userRole == allowedRole || allowedRole == "all" {
			return nil
		}
	}
	return fmt.Errorf("User has role %v, which is not in allowed roles (%v)", userRole, allowedRoles)
}

func randomString(length int) []byte {
	rand.Seed(time.Now().UnixNano())
	letterBytes := "123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, length)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	fmt.Printf("Token signing key is %v\n", string(b))
	return b
}

// ExtractToken from Authorization header in the form `Bearer <JWT Token>`
// OR in an cookie named `jwt_token`
// OR a URL query paramter of the form https://example.com?token=<JWT token>
func ExtractToken(r *http.Request) (string, error) {
	jwtHeader := strings.Split(r.Header.Get("Authorization"), " ")
	if jwtHeader[0] == "Bearer" && len(jwtHeader) == 2 {
		return jwtHeader[1], nil
	}

	jwtCookie, err := r.Cookie("jwt_token")
	if err == nil {
		return jwtCookie.Value, nil
	}

	jwtQuery := r.URL.Query().Get("token")
	if jwtQuery != "" {
		return jwtQuery, nil
	}

	return "", fmt.Errorf("no token found")
}
