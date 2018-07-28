package security

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/nicolaspernoud/ninicobox-v3-server/types"
)

type key int

const (
	contextLogin key = 0
	contextRole  key = 1
)

var jWTSignature = randomString(48)

// AuthenticationMiddleware allow access for users of allowed Roles
type AuthenticationMiddleware struct {
	AllowedRoles []string
}

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
		// Try to parse the token as a normal token
		token, errParseToken := jwt.ParseWithClaims(JWT, &types.JWTPayload{}, func(token *jwt.Token) (interface{}, error) {
			return jWTSignature, nil
		})
		if errParseToken != nil {
			// Try to parse the token as a share token ...
			token, errParseToken = jwt.ParseWithClaims(JWT, &types.ShareTokenPayload{}, func(token *jwt.Token) (interface{}, error) {
				return jWTSignature, nil
			})
			if errParseToken != nil {
				http.Error(w, errParseToken.Error(), 400)
				return
			}
			// ... continue trying to parse the token as a share token
			if claims, ok := token.Claims.(*types.ShareTokenPayload); ok && token.Valid {
				// Check if the role herited from the sharing user is allowed and if the requested path is exactly the allowed one
				if errRole := checkUserRoleIsAllowed(claims.Role, allowedRoles); errRole == nil && claims.Path == req.URL.Path {
					ctx := context.WithValue(req.Context(), contextLogin, claims.SharingUserLogin)
					ctx = context.WithValue(ctx, contextRole, claims.Role)
					next.ServeHTTP(w, req.WithContext(ctx))
				} else {
					http.Error(w, errRole.Error(), 403)
				}
			} else {
				http.Error(w, "Invalid authorization token", 400)
			}
		} else {
			if claims, ok := token.Claims.(*types.JWTPayload); ok && token.Valid {
				if errRole := checkUserRoleIsAllowed(claims.Role, allowedRoles); errRole == nil {
					ctx := context.WithValue(req.Context(), contextLogin, claims.Login)
					ctx = context.WithValue(ctx, contextRole, claims.Role)
					next.ServeHTTP(w, req.WithContext(ctx))
				} else {
					http.Error(w, errRole.Error(), 403)
				}
			} else {
				http.Error(w, "Invalid authorization token", 400)
			}
		}
	})
}

// Authenticate validate the username and password provided in the function body against a local file and return a token if the user is found
func Authenticate(w http.ResponseWriter, req *http.Request) {
	var sentUser types.User
	error := json.NewDecoder(req.Body).Decode(&sentUser)
	if error != nil {
		http.Error(w, error.Error(), 400)
		return
	}
	// Try to match the user with an user in the database
	var user types.User
	user, error = types.MatchUser(sentUser)
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

// GetShareToken provide a token to access the ressource on a given path
func GetShareToken(w http.ResponseWriter, req *http.Request) {
	var shareTokenPL types.ShareTokenPayload
	error := json.NewDecoder(req.Body).Decode(&shareTokenPL)
	if error != nil {
		http.Error(w, error.Error(), 400)
		return
	}
	// Get the user role from the request
	shareTokenPL.Role = req.Context().Value(contextRole).(string)
	shareTokenPL.SharingUserLogin = req.Context().Value(contextLogin).(string)
	shareTokenPL.ExpiresAt = time.Now().Add(time.Hour * time.Duration(24*7)).Unix()
	shareTokenPL.IssuedAt = time.Now().Unix()

	// If user is found, create and send a JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, shareTokenPL)
	tokenString, error := token.SignedString(jWTSignature)
	if error != nil {
		http.Error(w, error.Error(), 400)
		return
	}
	json.NewEncoder(w).Encode(types.JwtToken{Token: tokenString})
}

func checkUserRoleIsAllowed(userRole string, allowedRoles []string) error {
	for _, allowedRole := range allowedRoles {
		if userRole == allowedRole || allowedRole == "all" {
			return nil
		}
	}
	return fmt.Errorf("User has role %v, which is not in allowed roles (%v)", userRole, allowedRoles)
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
