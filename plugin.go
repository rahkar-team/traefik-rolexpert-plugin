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
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	BearerPrefix         = "Bearer "
	XAuthUserIdHeader    = "X-Auth-User-Id"
	XAuthUserRolesHeader = "X-Auth-User-Roles"
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
	fmt.Printf("Plugin %s initialized", name)

	var whitelist []Whitelist
	if cfg.Whitelist != "" {
		whitelist = parseRoutes(cfg.Whitelist)
	}

	client := NewClient(
		cfg.ClientId,
		cfg.ClientSecret,
		cfg.RoleXpertUrl,
	)
	fmt.Printf("Plugin %s http-client initilized with %s", name, cfg.RoleXpertUrl)

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
	// Check if the request is whitelisted (from plugin or service)
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
	fmt.Printf("Token %+v \n", c)

	authUserId := c.Subject
	if authUserId == "" {
		http.Error(rw, "token subject invalid!", http.StatusUnauthorized)
		return
	}
	fmt.Printf("Auth User: %s\n", authUserId)

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

	strRoles := strings.Join(userRoles, ",")
	req.Header.Set(XAuthUserRolesHeader, strRoles)

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
	}
	return false
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
		log.Fatalf("Error fetching roles and permissions: %v", err)
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
		log.Printf("Failed to get RSA public key: %v", err)
		return false, nil
	}

	// Parse the public key (assuming RSA for this example)
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(pk)
	if err != nil {
		log.Printf("Failed to parse RSA public key: %v", err)
		return false, nil
	}

	// Parse and validate the JWT
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		// Ensure the token's signing method matches the expected method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		log.Printf("Failed to parse and validate token: %v", err)
		return false, nil
	}

	if !token.Valid {
		log.Printf("Invalid token: %s", tokenString)
		return false, nil
	}
	c, err := extractPayload(tokenString)
	if err != nil {
		log.Printf("Failed to extract token payload: %v", err)
	}
	return true, c
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
	fmt.Printf("New public key: %s", pk)
	a.publicKey = pk
	return a.publicKey, nil
}

// parseRoutes converts a comma-separated string of routes into a slice of unique Whitelist structs
func parseRoutes(routeString string) []Whitelist {
	routes := strings.Split(routeString, ",")
	uniqueEntries := make(map[string]struct{})
	wildcardPaths := make(map[string]struct{})
	var whitelist []Whitelist

	for _, route := range routes {
		var methods, path string
		if colonIndex := strings.Index(route, ":"); colonIndex != -1 {
			methods = route[:colonIndex]
			path = route[colonIndex+1:]
		} else {
			methods = "*"
			path = route
		}
		path = strings.TrimSpace(path)
		if methods == "" && path == "" {
			continue
		}
		if methods == "" {
			methods = "*"
		}
		methodList := strings.Split(methods, "|")
		if methods == "*" {
			wildcardPaths[path] = struct{}{}
		}
		for _, method := range methodList {
			method = strings.TrimSpace(method)
			if method == "*" {
				method = ""
			}
			key := method + ":" + path
			if _, exists := uniqueEntries[key]; !exists {
				if _, isWildcard := wildcardPaths[path]; !isWildcard || method == "" {
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

func base64UrlDecode(input string) ([]byte, error) {
	// Replace non-standard URL characters with standard base64 characters
	input = strings.Replace(input, "-", "+", -1)
	input = strings.Replace(input, "_", "/", -1)

	// Pad the input if necessary to make its length a multiple of 4
	switch len(input) % 4 {
	case 2:
		input += "=="
	case 3:
		input += "="
	}

	// Decode the base64 string
	return base64.StdEncoding.DecodeString(input)
}

func extractPayload(jwtToken string) (*Claims, error) {
	// Split the token into three parts: Header, Payload, Signature
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT token format")
	}

	// Decode the payload (second part)
	payload, err := base64UrlDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %v", err)
	}

	// Parse the payload as a JSON object
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %v", err)
	}

	return &claims, nil
}

type Claims struct {
	Data      ClaimsData `json:"data"`
	Issuer    string     `json:"iss,omitempty"`
	Subject   string     `json:"sub,omitempty"`
	Audience  []string   `json:"aud,omitempty"`
	ExpiresAt int        `json:"exp,omitempty"`
	NotBefore int        `json:"nbf,omitempty"`
	IssuedAt  int        `json:"iat,omitempty"`
	ID        string     `json:"jti,omitempty"`
}

type ClaimsData struct {
	Roles []string `json:"roles"`
}
