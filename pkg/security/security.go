package security

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"../../pkg/common"
	"../../pkg/log"
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
	err := common.Load("./configs/jwtsignature.json", &jWTConfig)
	if err != nil {
		jWTSignature = common.RandomByteArray(48)
		jWTConfig.JWTSignature = string(jWTSignature)
		err := common.Save("./configs/jwtsignature.json", jWTConfig)
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
		var sentUser User
		basicAuthHeader := strings.Split(req.Header.Get("Authorization"), " ")
		err := errors.New("authorization header could not be processed")
		if basicAuthHeader[0] == "Basic" && len(basicAuthHeader) == 2 {
			var decoded []byte
			decoded, err = base64.StdEncoding.DecodeString(basicAuthHeader[1])
			if err == nil {
				if auth := strings.Split(string(decoded), ":"); len(auth) == 2 {
					sentUser = User{
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
		user, err := MatchUser(sentUser)
		if err != nil {
			http.Error(w, err.Error(), 403)
			log.Logger.Printf("| %v | Basic auth failure | %v | %v", sentUser.Login, req.RemoteAddr, log.GetCityAndCountryFromRequest(req))
			return
		}

		if err := checkUserRoleIsAllowed(user.Role, allowedRoles); err == nil {
			ctx := context.WithValue(req.Context(), ContextLogin, user.Login)
			ctx = context.WithValue(ctx, ContextRole, user.Role)
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

func validateJWT(JWT string, allowedRoles []string, req *http.Request) (int, *JWTPayload, error) {
	token, err := jwt.ParseWithClaims(JWT, &JWTPayload{}, func(token *jwt.Token) (interface{}, error) {
		return jWTSignature, nil
	})
	if err != nil {
		return 403, nil, err
	}
	claims, ok := token.Claims.(*JWTPayload)
	if ok && token.Valid {
		url, err := url.Parse("http://" + claims.URL)
		if err != nil {
			return 400, claims, err
		}
		urlHost := url.Hostname()
		requestHost, _, err := net.SplitHostPort(req.Host)
		if err != nil {
			requestHost = req.Host
		}
		if hostNotMatched := urlHost != "" && urlHost != requestHost; hostNotMatched {
			return 403, claims, errors.New("the share token can only be used for the given host")
		}
		urlPath := url.Path
		if pathNotMatched := urlPath != "" && urlPath != req.URL.Path; pathNotMatched {
			return 403, claims, errors.New("the share token can only be used for the given path")
		}
		err = checkUserRoleIsAllowed(claims.Role, allowedRoles)
		if err != nil {
			return 403, claims, err
		}
		return 200, claims, err
	}
	return 400, claims, errors.New("invalid authorization token")
}

// ValidateJWTMiddleware tests if a JWT token is present, and valid, in the request and returns an Error if not
func (amw *AuthenticationMiddleware) ValidateJWTMiddleware(next http.Handler) http.Handler {
	return ValidateJWTMiddleware(next, amw.AllowedRoles)
}

// ValidateJWTMiddleware tests if a JWT token is present, and valid, in the request and returns an Error if not
func ValidateJWTMiddleware(next http.Handler, allowedRoles []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		JWT, err := ExtractToken(req)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="server"`)
			http.Error(w, err.Error(), 401)
			return
		}
		httpCode, claims, err := validateJWT(JWT, allowedRoles, req)
		if err != nil {
			http.Error(w, err.Error(), httpCode)
			return
		}
		ctx := context.WithValue(req.Context(), ContextLogin, claims.SharingUserLogin+claims.Login)
		ctx = context.WithValue(ctx, ContextRole, claims.Role)
		next.ServeHTTP(w, req.WithContext(ctx))
	})
}

// Authenticate validate the username and password provided in the function body against a local file and return a token if the user is found
func Authenticate(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var sentUser User
	err := json.NewDecoder(req.Body).Decode(&sentUser)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	// Try to match the user with an user in the database
	user, err := MatchUser(sentUser)
	if err != nil {
		http.Error(w, err.Error(), 403)
		log.Logger.Printf("| %v | Login failure | %v | %v", sentUser.Login, req.RemoteAddr, log.GetCityAndCountryFromRequest(req))
		return
	}
	// Work out the time to live for the token
	var expiresAt int64
	if user.LongLivedToken {
		expiresAt = now().Add(time.Hour * time.Duration(24*7)).Unix()
	} else {
		expiresAt = now().Add(time.Hour * time.Duration(12)).Unix()
	}
	// If user is found, create and send a JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, JWTPayload{
		Login:   user.Login,
		Name:    user.Name,
		Surname: user.Surname,
		Role:    user.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiresAt,
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

// GetShareToken provide a token to access the ressource on a given url
func GetShareToken(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var wantedToken struct {
		Sharedfor string `json:"sharedfor"`
		URL       string `json:"url"`
		Lifespan  int    `json:"lifespan"`
	}
	err := json.NewDecoder(req.Body).Decode(&wantedToken)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if wantedToken.URL == "" {
		http.Error(w, "url cannot be empty", 400)
		return
	}
	role := req.Context().Value(ContextRole).(string)
	var expiresAt int64
	if role == "admin" {
		expiresAt = now().Add(time.Hour * time.Duration(24*wantedToken.Lifespan)).Unix()
	} else {
		expiresAt = now().Add(time.Hour * time.Duration(3)).Unix()
	}
	// If user is found, create and send a JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, JWTPayload{
		Login:            "_share_for_" + wantedToken.Sharedfor,
		Role:             role,
		URL:              wantedToken.URL,
		SharingUserLogin: req.Context().Value(ContextLogin).(string),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiresAt,
			IssuedAt:  now().Unix(),
		},
	})
	tokenString, err := token.SignedString(jWTSignature)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	var domain string
	if idx := strings.Index(wantedToken.URL, "."); idx != -1 {
		domain = wantedToken.URL[idx:]
	}
	w.Header().Set("Set-Cookie", "jwt_token="+tokenString+"; Path=/; Domain="+domain+"; Expires="+time.Unix(expiresAt, 0).Format(time.RFC1123)+"; Secure; HttpOnly; SameSite=Strict")
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
func ExtractToken(r *http.Request) (string, error) {
	jwtHeader := strings.Split(r.Header.Get("Authorization"), " ")
	if jwtHeader[0] == "Bearer" && len(jwtHeader) == 2 {
		return jwtHeader[1], nil
	}

	jwtQuery := r.URL.Query().Get("token")
	if jwtQuery != "" {
		return jwtQuery, nil
	}

	jwtCookie, err := r.Cookie("jwt_token")
	if err == nil {
		return jwtCookie.Value, nil
	}

	// try to use the basic auth header instead
	if jwtHeader[0] == "Basic" && len(jwtHeader) == 2 {
		decoded, err := base64.StdEncoding.DecodeString(jwtHeader[1])
		if err == nil {
			jwtHeader = strings.Split(string(decoded), ":")
			return jwtHeader[1], nil
		}
	}

	return "", fmt.Errorf("no token found")
}

// UserLoginFromContext retrieve user login from request context
func UserLoginFromContext(ctx context.Context) string {
	user, ok := ctx.Value(ContextLogin).(string)
	if ok {
		return user
	}
	return "unknown_user"
}
