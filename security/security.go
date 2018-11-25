package security

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"../log"
	"../types"
	jwt "github.com/dgrijalva/jwt-go"
)

var (
	jWTSignature []byte
	now          = time.Now
)

// init sets the jWTSignature
func init() {
	var jWTConfig struct {
		JWTSignature string
	}
	err := types.Load("./config/jwtsignature.json", &jWTConfig)
	if err != nil {
		jWTSignature = types.RandomByteArray(48)
		jWTConfig.JWTSignature = string(jWTSignature)
		err := types.Save("./config/jwtsignature.json", jWTConfig)
		if err != nil {
			log.Logger.Println("Token signing key could not be saved")
		}
	} else {
		jWTSignature = []byte(jWTConfig.JWTSignature)
	}
	log.Logger.Println("Token signing key set")
}

// ValidateBasicAuthMiddleware tests if a Basic Auth header is present, and valid, in the request and returns an Error if not
func ValidateBasicAuthMiddleware(next http.Handler, allowedRoles []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Extract the login and password
		var sentUser types.User
		basicAuthHeader := strings.Split(req.Header.Get("Authorization"), " ")
		err := errors.New("authorization header could not be processed")
		if basicAuthHeader[0] == "Basic" && len(basicAuthHeader) == 2 {
			var decoded []byte
			decoded, err = base64.StdEncoding.DecodeString(basicAuthHeader[1])
			if err == nil {
				if auth := strings.Split(string(decoded), ":"); len(auth) == 2 {
					sentUser = types.User{
						Login:    auth[0],
						Password: auth[1],
					}
				}
			}
		}
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="server"`)
			http.Error(w, err.Error(), 401)
			return
		}

		// Try to match an user with the credentials provided
		user, err := types.MatchUser(sentUser)
		if err != nil {
			http.Error(w, err.Error(), 403)
			log.Logger.Printf("| %v | Basic auth failure | %v | %v", sentUser.Login, req.RemoteAddr, log.GetCityAndCountryFromRequest(req))
			return
		}

		if err := checkUserRoleIsAllowed(user.Role, allowedRoles); err == nil {
			ctx := context.WithValue(req.Context(), types.ContextLogin, user.Login)
			ctx = context.WithValue(ctx, types.ContextRole, user.Role)
			next.ServeHTTP(w, req.WithContext(ctx))
		} else {
			http.Error(w, err.Error(), 403)
		}
	})
}

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
		JWT, origin, err := ExtractToken(req)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="server"`)
			http.Error(w, err.Error(), 401)
			return
		}
		token, err := jwt.ParseWithClaims(JWT, &types.JWTPayload{}, func(token *jwt.Token) (interface{}, error) {
			return jWTSignature, nil
		})
		if err != nil {
			http.Error(w, err.Error(), 403)
			return
		}
		if claims, ok := token.Claims.(*types.JWTPayload); ok && token.Valid {
			urlPath, err := url.Parse(claims.Path)
			if err != nil {
				http.Error(w, err.Error(), 400)
			}
			urlEncodedPath := urlPath.String()
			if pathNotMatched := urlEncodedPath != "" && urlEncodedPath != req.URL.EscapedPath(); pathNotMatched {
				http.Error(w, "the share token can only be used for the given path", 403)
				return
			}
			if err := checkUserRoleIsAllowed(claims.Role, allowedRoles); err == nil {
				ctx := context.WithValue(req.Context(), types.ContextLogin, claims.Login)
				ctx = context.WithValue(ctx, types.ContextRole, claims.Role)
				// if the JWT origin is a query set the token as cookie in the response
				if origin == "query" {
					w.Header().Set("Set-Cookie", "jwt_token="+JWT+"; Path=/; Expires="+time.Unix(claims.ExpiresAt, 0).Format(time.RFC1123))
				}
				next.ServeHTTP(w, req.WithContext(ctx))
			} else {
				http.Error(w, err.Error(), 403)
			}
		} else {
			http.Error(w, "invalid authorization token", 400)
		}
	})
}

// Authenticate validate the username and password provided in the function body against a local file and return a token if the user is found
func Authenticate(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var sentUser types.User
	err := json.NewDecoder(req.Body).Decode(&sentUser)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	// Try to match the user with an user in the database
	user, err := types.MatchUser(sentUser)
	if err != nil {
		http.Error(w, err.Error(), 403)
		log.Logger.Printf("| %v | Login failure | %v | %v", sentUser.Login, req.RemoteAddr, log.GetCityAndCountryFromRequest(req))
		return
	}
	// Remove the password hash from sent user
	user.PasswordHash = ""
	// Work out the time to live for the token
	var timeToLive int64
	if user.LongLivedToken {
		timeToLive = now().Add(time.Hour * time.Duration(24*7)).Unix()
	} else {
		timeToLive = now().Add(time.Hour * time.Duration(12)).Unix()
	}
	// If user is found, create and send a JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, types.JWTPayload{
		User: user,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: timeToLive,
			IssuedAt:  now().Unix(),
		},
	})
	tokenString, err := token.SignedString(jWTSignature)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	fmt.Fprintf(w, tokenString)
	log.Logger.Printf("| %v (%v %v) | Login success | %v | %v", sentUser.Login, user.Name, user.Surname, req.RemoteAddr, log.GetCityAndCountryFromRequest(req))
}

// GetShareToken provide a token to access the ressource on a given path
func GetShareToken(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	path := string(body)
	if !strings.HasPrefix(path, "/api/files") {
		http.Error(w, "path cannot be empty, and must began with /api/files", 400)
		return
	}
	shareTokenUser := types.User{
		Login:            "share",
		Role:             req.Context().Value(types.ContextRole).(string),
		Path:             path,
		SharingUserLogin: req.Context().Value(types.ContextLogin).(string),
	}
	// If user is found, create and send a JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, types.JWTPayload{
		User: shareTokenUser,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: now().Add(time.Hour * time.Duration(24*7)).Unix(),
			IssuedAt:  now().Unix(),
		},
	})
	tokenString, err := token.SignedString(jWTSignature)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	fmt.Fprintf(w, tokenString)
}

func checkUserRoleIsAllowed(userRole string, allowedRoles []string) error {
	for _, allowedRole := range allowedRoles {
		if userRole != "" && (userRole == allowedRole || allowedRole == "all") {
			return nil
		}
	}
	return fmt.Errorf("user has role %v, which is not in allowed roles (%v)", userRole, allowedRoles)
}

// ExtractToken from Authorization header in the form `Bearer <JWT Token>`
// OR in an cookie named `jwt_token`
// OR a URL query paramter of the form https://example.com?token=<JWT token>
func ExtractToken(r *http.Request) (string, string, error) {
	jwtHeader := strings.Split(r.Header.Get("Authorization"), " ")
	if jwtHeader[0] == "Bearer" && len(jwtHeader) == 2 {
		return jwtHeader[1], "bearerHeader", nil
	}

	jwtQuery := r.URL.Query().Get("token")
	if jwtQuery != "" {
		return jwtQuery, "query", nil
	}

	jwtCookie, err := r.Cookie("jwt_token")
	if err == nil {
		return jwtCookie.Value, "cookie", nil
	}

	// try to use the basic auth header instead
	if jwtHeader[0] == "Basic" && len(jwtHeader) == 2 {
		decoded, err := base64.StdEncoding.DecodeString(jwtHeader[1])
		if err == nil {
			jwtHeader = strings.Split(string(decoded), ":")
			return jwtHeader[1], "basicHeader", nil
		}
	}

	return "", "", fmt.Errorf("no token found")
}

// UserLoginFromContext retrieve user login from request context
func UserLoginFromContext(ctx context.Context) string {
	user, ok := ctx.Value(types.ContextLogin).(string)
	if ok {
		return user
	}
	return "unknown_user"
}
