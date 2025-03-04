package traefik_rolexpert_plugin

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	BearerPrefix      = "Bearer "
	XAuthUserIdHeader = "X-Auth-User-Id"
)

// Config defines the middleware configuration.
type Config struct {
	ClientId      string      `json:"clientId"`
	ClientSecret  string      `json:"clientSecret"`
	RoleXpertUrl  string      `json:"rolexpertBaseUrl"`
	TraefikApiUrl string      `json:"traefikApiUrl"` // Traefik API URL
	CacheTTL      int         `json:"cacheTTL"`      // Cache expiration in seconds
	Whitelist     interface{} `json:"whitelist"`     // Plugin-defined whitelist
}

// Whitelist defines allowed paths and optional methods
type Whitelist struct {
	Path   string `json:"path"`
	Method string `json:"method,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		CacheTTL:      300,                   // Default to 5 minutes cache
		TraefikApiUrl: "http://traefik:8080", // 🔥 Default Traefik API URL
		Whitelist: []Whitelist{
			{Path: "/health", Method: "GET"}, // 🔥 Default whitelist example
		},
	}
}

type traefikPlugin struct {
	next            http.Handler
	name            string
	config          *Config
	roleXpertClient Client
	publicKey       []byte
	rolePermissions map[string][]string
	cache           sync.Map // 🔥 In-memory cache for whitelists
}

// New creates a new instance of the middleware plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var whitelist []Whitelist

	switch v := config.Whitelist.(type) {
	case string: // If whitelist is a JSON string, decode it
		if err := json.Unmarshal([]byte(v), &whitelist); err != nil {
			fmt.Printf("Failed to parse whitelist JSON: %v\n", err)
		}
	case []interface{}: // If it's already an array, cast it
		for _, item := range v {
			if wlMap, ok := item.(map[string]interface{}); ok {
				wl := Whitelist{}
				if path, exists := wlMap["path"].(string); exists {
					wl.Path = path
				}
				if method, exists := wlMap["method"].(string); exists {
					wl.Method = method
				}
				whitelist = append(whitelist, wl)
			}
		}
	case nil:
		fmt.Println("No whitelist provided.")
	default:
		fmt.Printf("Unexpected whitelist format: %T\n", v)
	}

	// Assign parsed whitelist
	config.Whitelist = whitelist

	client := NewClient(
		config.ClientId,
		config.ClientSecret,
		config.RoleXpertUrl,
	)

	return &traefikPlugin{
		next:            next,
		name:            name,
		config:          config,
		roleXpertClient: client,
		cache:           sync.Map{},
	}, nil
}

// ServeHTTP processes incoming requests.
func (a *traefikPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// 🔥 Check if the request is whitelisted (from plugin or service)
	if a.isWhitelisted(req) {
		a.next.ServeHTTP(rw, req) // ✅ Skip authentication
		return
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, BearerPrefix) {
		http.Error(rw, "token invalid!", http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(authHeader, BearerPrefix)
	ok, c := a.verifyTokenAndGetPayload(token)
	if !ok {
		http.Error(rw, "token invalid!", http.StatusUnauthorized)
		return
	}

	authUserId, err := c.GetSubject()
	if err != nil {
		http.Error(rw, "token invalid!", http.StatusUnauthorized)
		return
	}

	userRoles := c.Data.Roles
	if userRoles == nil {
		http.Error(rw, "illegal token payload", http.StatusExpectationFailed)
		return
	}

	rolesPermissions, err := a.getRoleAndPermissionsOrFetchFromRoleXpert()
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error fetching roles and permissions: %v", err), http.StatusInternalServerError)
		return
	}

	// Determine required roles for this request
	var requiredRoles []string
	for role, permissions := range rolesPermissions {
		for _, permission := range permissions {
			parts := strings.SplitN(permission, ":", 2)
			if len(parts) != 2 {
				continue
			}
			method, pattern := parts[0], parts[1]

			if strings.ToUpper(req.Method) != strings.ToUpper(method) {
				continue
			}

			if patternMatched(pattern, req) {
				return
			}

			if patternMatched(pattern, req) {
				requiredRoles = append(requiredRoles, role)
				break
			}
		}
	}

	req.Header.Set(XAuthUserIdHeader, authUserId)

	// If no roles are required, allow access
	if len(requiredRoles) == 0 {
		a.next.ServeHTTP(rw, req)
		return
	}

	// Check if user has a required role
	for _, ur := range userRoles {
		for _, rr := range requiredRoles {
			if ur == rr {
				a.next.ServeHTTP(rw, req)
				return
			}
		}
	}

	// If no matching roles are found, deny access.
	http.Error(rw, "Access Denied", http.StatusForbidden)
}

func patternMatched(pattern string, req *http.Request) bool {
	regexPattern := "^" + regexp.QuoteMeta(pattern) + "$"
	regexPattern = strings.ReplaceAll(regexPattern, "\\*\\*", ".*")
	regexPattern = strings.ReplaceAll(regexPattern, "\\*", "[^/]*")
	if matched, err := regexp.MatchString(regexPattern, req.URL.Path); err == nil && matched {
		return true
	} else {
		return false
	}
}

// 🔥 isWhitelisted checks if the request matches any whitelisted paths (from plugin or service)
func (a *traefikPlugin) isWhitelisted(req *http.Request) bool {
	serviceHost := req.Host
	whitelist := a.getCachedWhitelist(serviceHost)

	for _, wl := range whitelist {
		if patternMatched(wl.Path, req) {
			if wl.Method == "" || strings.EqualFold(req.Method, wl.Method) {
				return true // ✅ Whitelisted
			}
		}
	}
	return false
}

// 🔥 getCachedWhitelist retrieves the whitelist from cache or fetches from Traefik API
func (a *traefikPlugin) getCachedWhitelist(serviceHost string) []Whitelist {
	cacheKey := "whitelist_" + serviceHost
	if cached, found := a.cache.Load(cacheKey); found {
		data := cached.(struct {
			whitelist []Whitelist
			expiry    time.Time
		})
		if time.Now().Before(data.expiry) {
			return data.whitelist // ✅ Return cached whitelist
		}
	}

	// Fetch new whitelist from Traefik API
	newWhitelist, err := a.FetchWhitelistFromTraefik(serviceHost)
	if err != nil {
		fmt.Printf("Warning: Failed to fetch whitelist from Traefik: %v\n", err)
		return a.config.Whitelist.([]Whitelist) // Default to plugin-defined whitelist
	}

	// Store in cache with expiration
	a.cache.Store(cacheKey, struct {
		whitelist []Whitelist
		expiry    time.Time
	}{whitelist: newWhitelist, expiry: time.Now().Add(time.Duration(a.config.CacheTTL) * time.Second)})

	return newWhitelist
}

// FetchWhitelistFromTraefik fetches the whitelist dynamically from Traefik API
func (a *traefikPlugin) FetchWhitelistFromTraefik(serviceHost string) ([]Whitelist, error) {
	resp, err := http.Get(a.config.TraefikApiUrl + "/api/rawdata")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var apiResponse TraefikAPIResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return nil, err
	}

	var whitelist []Whitelist

	for _, router := range apiResponse.HTTP.Routers {
		if strings.Contains(router.Rule, serviceHost) {
			for _, mw := range router.Middlewares {
				if mwConfig, exists := apiResponse.HTTP.Middlewares[mw.Name]; exists {
					if len(mwConfig.Plugin.RoleXpert.Whitelist) > 0 {
						for _, path := range mwConfig.Plugin.RoleXpert.Whitelist {
							whitelist = append(whitelist, Whitelist{Path: path})
						}
						return whitelist, nil
					}
				}
			}
		}
	}

	return whitelist, nil
}

// getRoleAndPermissionsOrFetchFromRoleXpert Fetch roles and permissions from RoleXpert API then cache all roles and permissions
func (a *traefikPlugin) getRoleAndPermissionsOrFetchFromRoleXpert() (map[string][]string, error) {
	if a.rolePermissions == nil {
		return a.rolePermissions, nil
	}
	rolesPermissions, err := a.roleXpertClient.FetchRoles()
	if err != nil {
		fmt.Printf("Error fetching roles and permissions: %v", err)
		return nil, err
	}

	a.rolePermissions = make(map[string][]string)
	for _, role := range rolesPermissions.Elements {
		a.rolePermissions[role.Name] = make([]string, 0)
		for _, permission := range role.Permissions {
			a.rolePermissions[role.Name] = append(a.rolePermissions[role.Name], permission.Permission)
		}
	}

	return a.rolePermissions, nil
}

func toPublicPem(base64Key string) ([]byte, error) {
	// Decode base64 string to bytes
	keyBytes, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %v", err)
	}

	// Parse the bytes into an RSA public key
	pubKey, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	// Type assert to RSA public key
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	// Convert to PEM format
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(rsaPubKey),
	})

	return pemBytes, nil
}

func (a *traefikPlugin) verifyTokenAndGetPayload(tokenString string) (bool, *Claims) {
	pk, err := a.getPublicKeyOrFetchFromRoleXpert()
	if err != nil {
		return false, nil
	}

	// Parse the public key (assuming RSA for this example)
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(pk)
	if err != nil {
		fmt.Printf("Failed to parse RSA public key: %v", err)
		return false, nil
	}

	// Parse and validate the JWT
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Ensure the token's signing method matches the expected method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		fmt.Printf("Failed to parse and validate token: %v", err)
		return false, nil
	}

	// If the token is valid, you can access its claims
	if c, ok := token.Claims.(*Claims); ok && token.Valid {
		fmt.Println("Token is valid.")
		// Access claims as needed
		return true, c
	} else {
		fmt.Println("Invalid token.")
		return false, nil
	}
}

func (a *traefikPlugin) getPublicKeyOrFetchFromRoleXpert() ([]byte, error) {
	if a.publicKey != nil {
		return a.publicKey, nil
	}

	response, err := a.roleXpertClient.GetPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %v", err)
	}

	pk, err := toPublicPem(response.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}
	a.publicKey = pk
	return a.publicKey, nil
}

type Claims struct {
	Data ClaimsData `json:"data"`
	jwt.RegisteredClaims
}

type ClaimsData struct {
	Roles []string `json:"roles"`
}

type TraefikAPIResponse struct {
	HTTP struct {
		Routers map[string]struct {
			Rule        string `json:"rule"`
			Middlewares []struct {
				Name string `json:"name"`
			} `json:"middlewares"`
		} `json:"routers"`
		Middlewares map[string]struct {
			Plugin struct {
				RoleXpert struct {
					Whitelist []string `json:"whitelist"`
				} `json:"rolexpert"`
			} `json:"plugin"`
		} `json:"middlewares"`
	} `json:"http"`
}
