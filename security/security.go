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

// ValidateJWTMiddleware tests if a JWT token is present, and valid, in the request and returns an Error if not
func ValidateJWTMiddleware(next http.HandlerFunc, allowedRoles []string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		JWT, errExtractToken := ExtractToken(req)
		if errExtractToken != nil {
			http.Error(w, errExtractToken.Error(), 401)
			return
		}
		token, errParseToken := jwt.ParseWithClaims(JWT, &types.JWTPayload{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return jWTSignature, nil
		})
		if errParseToken != nil {
			http.Error(w, errParseToken.Error(), 400)
			return
		}
		if claims, ok := token.Claims.(*types.JWTPayload); ok && token.Valid {
			if err := checkUserRoleIsAllowed(claims.Role, allowedRoles); err == nil {
				ctx := context.WithValue(req.Context(), "login", claims.Login)
				ctx = context.WithValue(ctx, "role", claims.Role)
				next(w, req.WithContext(ctx))
			} else {
				http.Error(w, err.Error(), 403)
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

func checkUserRoleIsAllowed(userRole string, allowedRoles []string) error {
	for _, allowedRole := range allowedRoles {
		if userRole == allowedRole {
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

// ExtractToken will find a JWT token passed one of three ways: (1) as the Authorization
// header in the form `Bearer <JWT Token>`; (2) as a cookie named `jwt_token`; (3) as
// a URL query paramter of the form https://example.com?token=<JWT token>
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
