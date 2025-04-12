package traefik_rolexpert_plugin

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
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
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	RoleXpertUrl string `json:"roleXpertUrl"`
	CacheTTL     int    `json:"cacheTTL"`  // Cache expiration in seconds
	Whitelist    string `json:"whitelist"` // Plugin-defined whitelist
}

// Whitelist defines allowed paths and optional methods
type Whitelist struct {
	Path   string `json:"path"`
	Method string `json:"method,omitempty"`
}

type config struct {
	*Config
	whitelist []Whitelist
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		CacheTTL: 300, // Default to 5 minutes cache
	}
}

type traefikPlugin struct {
	next            http.Handler
	name            string
	config          config
	roleXpertClient Client
	publicKey       []byte
	rolePermissions map[string][]string
	cache           sync.Map // In-memory cache for whitelists
}

// New creates a new instance of the middleware plugin.
func New(_ context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	var whitelist []Whitelist
	if cfg.Whitelist != "" {
		whitelist = parseRoutes(cfg.Whitelist)
	}

	client := NewClient(
		cfg.ClientId,
		cfg.ClientSecret,
		cfg.RoleXpertUrl,
	)

	var cf = config{
		Config:    cfg,
		whitelist: whitelist,
	}

	return &traefikPlugin{
		next:            next,
		name:            name,
		config:          cf,
		roleXpertClient: client,
		cache:           sync.Map{},
	}, nil
}

// ServeHTTP processes incoming requests.
func (a *traefikPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	//  Check if the request is whitelisted (from plugin or service)
	if a.isWhitelisted(req) {
		a.next.ServeHTTP(rw, req) // ✅ Skip authentication
		return
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, BearerPrefix) {
		http.Error(rw, "authorization header invalid!", http.StatusUnauthorized)
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
		http.Error(rw, "token subject invalid!", http.StatusUnauthorized)
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

// isWhitelisted checks if the request matches any whitelisted paths (from plugin or service)
func (a *traefikPlugin) isWhitelisted(req *http.Request) bool {
	serviceHost := req.Host
	whitelist := a.getCachedWhitelist(serviceHost)

	for _, wl := range whitelist {
		if patternMatched(wl.Path, req) {
			if wl.Method == "" || strings.EqualFold(req.Method, wl.Method) {
				return true
			}
		}
	}
	return false
}

// getCachedWhitelist retrieves the whitelist from cache or fetches from Traefik API
func (a *traefikPlugin) getCachedWhitelist(serviceHost string) []Whitelist {
	cacheKey := "whitelist_" + serviceHost
	if cached, found := a.cache.Load(cacheKey); found {
		data := cached.(struct {
			whitelist []Whitelist
			expiry    time.Time
		})
		if time.Now().Before(data.expiry) {
			return data.whitelist
		}
	}

	// Store in cache with expiration
	a.cache.Store(cacheKey, struct {
		whitelist []Whitelist
		expiry    time.Time
	}{whitelist: a.config.whitelist, expiry: time.Now().Add(time.Duration(a.config.CacheTTL) * time.Second)})

	return a.config.whitelist
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
		fmt.Printf("Failed to get RSA public key: %v", err)
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
		fmt.Printf("Return cached public key: %s", a.publicKey)
		return a.publicKey, nil
	}

	response, err := a.roleXpertClient.GetPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %v", err)
	}

	fmt.Printf("Get public key from API: %s", response.Base64PublicKey)
	pk, err := toPublicPem(response.Base64PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}
	a.publicKey = pk
	return a.publicKey, nil
}

// parseRoutes converts a comma-separated string of routes into a slice of unique WhitelistEntry structs,
// ensuring that if a wildcard method route (":/path") is present, specific method routes for that path are ignored.
func parseRoutes(routeString string) []Whitelist {
	// Split the input string by commas to get individual routes.
	routes := strings.Split(routeString, ",")

	// Map to track unique entries using a composite key of method and path.
	uniqueEntries := make(map[string]struct{})
	// Set to track paths that have a wildcard method.
	wildcardPaths := make(map[string]struct{})
	var whitelist []Whitelist

	for _, route := range routes {
		var methods, path string

		// Check if the route contains a colon, indicating the presence of methods.
		if colonIndex := strings.Index(route, ":"); colonIndex != -1 {
			methods = route[:colonIndex]
			path = route[colonIndex+1:]
		} else {
			// No methods specified; default to "*" (any method).
			methods = "*"
			path = route
		}

		// Trim any leading/trailing whitespace from path.
		path = strings.TrimSpace(path)

		// Ignore entries with both empty method and path.
		if methods == "" && path == "" {
			continue
		}

		// Handle the case where methods are empty (":/test").
		if methods == "" {
			methods = "*"
		}

		// Split methods by '|' to handle multiple methods.
		methodList := strings.Split(methods, "|")

		// Check if the path has a wildcard method.
		if methods == "*" {
			// Add path to wildcardPaths set.
			wildcardPaths[path] = struct{}{}
		}

		// Create a WhitelistEntry for each method.
		for _, method := range methodList {
			// Trim any leading/trailing whitespace from method.
			method = strings.TrimSpace(method)

			// If method is "*", it implies any method; we can represent it as an empty string.
			if method == "*" {
				method = ""
			}

			// Create a unique key for the map.
			key := method + ":" + path

			// Check if the entry already exists in the map or if the path has a wildcard method.
			if _, exists := uniqueEntries[key]; !exists {
				if _, isWildcard := wildcardPaths[path]; !isWildcard || method == "" {
					// Add the entry to the map and the whitelist slice.
					uniqueEntries[key] = struct{}{}
					whitelist = append(whitelist, Whitelist{
						Method: method,
						Path:   path,
					})
				}
			}
		}
	}

	return whitelist
}

type Claims struct {
	Data ClaimsData `json:"data"`
	jwt.RegisteredClaims
}

type ClaimsData struct {
	Roles []string `json:"roles"`
}
