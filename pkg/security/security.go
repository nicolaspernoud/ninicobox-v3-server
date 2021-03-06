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

	"github.com/nicolaspernoud/ninicobox-v3-server/pkg/common"
	"github.com/nicolaspernoud/ninicobox-v3-server/pkg/log"

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
		jWTConfig.JWTSignature, err = common.GenerateRandomString(48)
		if err != nil {
			log.Logger.Fatal(err)
		}
		err := common.Save("./configs/jwtsignature.json", jWTConfig)
		if err != nil {
			log.Logger.Println("Token signing key could not be saved")
		}
	}
	jWTSignature = []byte(jWTSignature)
	log.Logger.Println("Token signing key set")
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
	CSRFToken, err := common.GenerateRandomString(16)
	if err != nil {
		log.Logger.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, AuthToken{
		CSRFToken: CSRFToken,
		CommonClaims: CommonClaims{
			Login: user.Login,
			Role:  user.Role,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expiresAt,
				IssuedAt:  now().Unix(),
			},
		},
	})
	tokenString, err := token.SignedString(jWTSignature)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	w.Header().Set("Set-Cookie", "auth_token="+tokenString+"; Path=/api/; Expires="+time.Unix(expiresAt, 0).Format(time.RFC1123)+"; Secure; HttpOnly; SameSite=Strict")
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
		CanWrite  bool   `json:"canwrite,omitempty"`
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
	expiresAt := now().Add(time.Hour * time.Duration(24*wantedToken.Lifespan)).Unix()
	// If user is found, create and send a JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, ShareToken{
		CommonClaims: CommonClaims{
			Login: "_share_for_" + wantedToken.Sharedfor,
			Role:  role,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expiresAt,
				IssuedAt:  now().Unix(),
			},
		},
		URL:              strings.TrimPrefix(wantedToken.URL, "*."),
		SharingUserLogin: req.Context().Value(ContextLogin).(string),
		CanWrite:         wantedToken.CanWrite,
	})
	tokenString, err := token.SignedString(jWTSignature)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	fmt.Fprintf(w, tokenString)
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
		JWT, tokenType, origin, err := ExtractToken(req)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="server"`)
			http.Error(w, err.Error(), 401)
			return
		}
		var httpCode int
		var claims CommonClaims
		if tokenType == "auth" {
			httpCode, claims, err = validateAuthToken(JWT, allowedRoles, origin, req)
		} else {
			httpCode, claims, err = validateShareToken(JWT, allowedRoles, req)
		}
		if err != nil {
			http.Error(w, err.Error(), httpCode)
			return
		}
		ctx := context.WithValue(req.Context(), ContextLogin, claims.Login)
		ctx = context.WithValue(ctx, ContextRole, claims.Role)
		// if the JWT origin is a query set the token as cookie in the response
		if origin == "query" {
			w.Header().Set("Set-Cookie", "share_token="+JWT+"; Path=/; Expires="+time.Unix(claims.ExpiresAt, 0).Format(time.RFC1123)+"; Secure; HttpOnly; SameSite=Strict")
		}
		next.ServeHTTP(w, req.WithContext(ctx))
	})
}

func validateAuthToken(JWT string, allowedRoles []string, origin string, req *http.Request) (int, CommonClaims, error) {
	token, err := jwt.ParseWithClaims(JWT, &AuthToken{}, checkJWT)
	if err != nil {
		return 403, CommonClaims{}, err
	}
	claims, ok := token.Claims.(*AuthToken)
	if ok && token.Valid {
		// if the origin is a cookie, check for CSRF protection
		if claims.CSRFToken == "" || (origin == "cookie" && claims.CSRFToken != req.Header.Get("X-XSRF-TOKEN")) {
			return 403, claims.CommonClaims, errors.New("CSRF protection triggered")
		}
		err = checkUserRoleIsAllowed(claims.Role, allowedRoles)
		if err != nil {
			return 403, claims.CommonClaims, err
		}
		return 200, claims.CommonClaims, err
	}
	return 400, CommonClaims{}, errors.New("invalid authorization token")
}

func validateShareToken(JWT string, allowedRoles []string, req *http.Request) (int, CommonClaims, error) {
	token, err := jwt.ParseWithClaims(JWT, &ShareToken{}, checkJWT)
	if err != nil {
		return 403, CommonClaims{}, err
	}
	claims, ok := token.Claims.(*ShareToken)
	if ok && token.Valid {
		url, err := url.Parse("http://" + claims.URL)
		if err != nil {
			return 400, claims.CommonClaims, err
		}
		urlHost := url.Hostname()
		requestHost, _, err := net.SplitHostPort(req.Host)
		if err != nil {
			requestHost = req.Host
		}
		if urlHost != "" && urlHost != requestHost {
			return 403, claims.CommonClaims, errors.New("the share token can only be used for the given host")
		}
		urlPath := url.Path
		if urlPath != "" && urlPath != req.URL.Path {
			return 403, claims.CommonClaims, errors.New("the share token can only be used for the given path")
		}
		// If a path is present, the share token is for a file share, only the GET method is allowed, unless CanWrite is true
		if urlPath != "" && req.Method != "GET" && !claims.CanWrite {
			return 405, claims.CommonClaims, errors.New("the share token can only be used for the GET method")
		}
		err = checkUserRoleIsAllowed(claims.Role, allowedRoles)
		if err != nil {
			return 403, claims.CommonClaims, err
		}
		claims.Login = claims.SharingUserLogin + claims.Login
		return 200, claims.CommonClaims, err
	}
	return 400, CommonClaims{}, errors.New("invalid authorization token")
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

// ExtractToken from a cookie
// OR an authorization header in the form `Bearer <JWT Token>`
// OR a URL query paramter of the form https://example.com?token=<JWT token>
// returns the token, a string indicating the token type, a string indicating where the token comes from, and an error
func ExtractToken(r *http.Request) (string, string, string, error) {
	// Try to get an share token from the query
	jwtQuery := r.URL.Query().Get("token")
	if jwtQuery != "" {
		return jwtQuery, "share", "query", nil
	}

	// Try to get an auth token from the cookie
	jwtCookie, err := r.Cookie("auth_token")
	if err == nil {
		return jwtCookie.Value, "auth", "cookie", nil
	}

	// Try to get a share token from the cookie
	jwtCookie, err = r.Cookie("share_token")
	if err == nil {
		return jwtCookie.Value, "share", "cookie", nil
	}

	// Try to get an auth token from the header
	jwtHeader := strings.Split(r.Header.Get("Authorization"), " ")
	if jwtHeader[0] == "Bearer" && len(jwtHeader) == 2 {
		return jwtHeader[1], "auth", "bearer_header", nil
	}

	// Try to use the basic auth header instead
	if jwtHeader[0] == "Basic" && len(jwtHeader) == 2 {
		decoded, err := base64.StdEncoding.DecodeString(jwtHeader[1])
		if err == nil {
			jwtHeader = strings.Split(string(decoded), ":")
			return jwtHeader[1], "auth", "basic_header", nil
		}
	}

	return "", "", "", fmt.Errorf("no token found")
}

func checkUserRoleIsAllowed(userRole string, allowedRoles []string) error {
	for _, allowedRole := range allowedRoles {
		if userRole != "" && (userRole == allowedRole || allowedRole == "all") {
			return nil
		}
	}
	return fmt.Errorf("user has role %v, which is not in allowed roles (%v)", userRole, allowedRoles)
}

// UserLoginFromContext retrieve user login from request context
func UserLoginFromContext(ctx context.Context) string {
	user, ok := ctx.Value(ContextLogin).(string)
	if ok {
		return user
	}
	return "unknown_user"
}

func checkJWT(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return jWTSignature, nil
}
