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
	DefaultCacheTTL      = 300
)

// Config defines the middleware configuration.
type Config struct {
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	RoleXpertUrl string `json:"roleXpertUrl"`
	CacheTTL     int    `json:"cacheTTL"`  // Cache expiration in seconds
	Whitelist    string `json:"whitelist"` // Plugin-defined whitelist
}

type config struct {
	*Config
	whitelist []string
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	ttl := DefaultCacheTTL
	return &Config{
		CacheTTL: ttl, // Default to 5 minutes cache
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

	client := NewClient(
		cfg.ClientId,
		cfg.ClientSecret,
		cfg.RoleXpertUrl,
	)
	fmt.Printf("Plugin %s http-client initilized with %s", name, cfg.RoleXpertUrl)

	var wl []string
	if cfg.Whitelist != "" {
		wl = strings.Split(cfg.Whitelist, ",")
	}
	var cf = config{
		Config:    cfg,
		whitelist: wl,
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
	fmt.Printf("RoleXpert middleware is going to authorize: %s", req.URL.Path)

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

	req.Header.Set(XAuthUserIdHeader, authUserId)
	strRoles := strings.Join(userRoles, ",")
	req.Header.Set(XAuthUserRolesHeader, strRoles)

	// Determine user has access to the resource based on user's role
	for _, ur := range userRoles {
		for role, permissions := range rolesPermissions {
			if ur != role {
				continue //skip
			}

			for _, permission := range permissions {
				if patternMatched(permission, req.Method, req.URL.Path) {
					a.next.ServeHTTP(rw, req)
					return
				}
			}
		}
	}

	// If no matching roles are found, deny access.
	http.Error(rw, "Access Denied", http.StatusForbidden)
}

func patternMatched(pattern string, reqMethod string, reqPath string) bool {
	parts := strings.SplitN(pattern, ":", 2)
	methodPattern := parts[0]
	pathPattern := ""
	if len(parts) == 2 {
		pathPattern = parts[1]
	} else {
		pathPattern = methodPattern // Handle cases where no colon is present
		methodPattern = "*"         // Default to all methods
	}
	if methodPattern == "" {
		methodPattern = "*"
	}

	// Handle method matching
	if methodPattern != "*" {
		methods := strings.Split(methodPattern, "|")
		methodMatched := false
		for _, method := range methods {
			if strings.ToUpper(method) == strings.ToUpper(reqMethod) {
				methodMatched = true
				break
			}
		}
		if !methodMatched {
			return false
		}
	}

	// Handle path pattern matching
	if pathPattern != "" {
		regexPattern := "^" + regexp.QuoteMeta(pathPattern) + "$"
		regexPattern = strings.ReplaceAll(regexPattern, "\\*\\*", ".*")
		regexPattern = strings.ReplaceAll(regexPattern, "\\*", "[^/]*")
		if matched, err := regexp.MatchString(regexPattern, reqPath); err == nil && matched {
			return true
		}
	} else {
		// If no path pattern, and method matched (or was '*'), then it's a match.
		return true
	}

	return false
}

// isWhitelisted checks if the request matches any whitelisted paths (from plugin or service)
func (a *traefikPlugin) isWhitelisted(req *http.Request) bool {
	serviceHost := req.Host
	whitelist := a.getCachedWhitelist(serviceHost)

	for _, wl := range whitelist {
		if patternMatched(wl, req.Method, req.URL.Path) {
			return true
		}
	}
	return false
}

// getCachedWhitelist retrieves the whitelist from cache or fetches from Traefik API
func (a *traefikPlugin) getCachedWhitelist(serviceHost string) []string {
	cacheKey := "whitelist_" + serviceHost
	if cached, found := a.cache.Load(cacheKey); found {
		data := cached.(struct {
			whitelist []string
			expiry    time.Time
		})
		if time.Now().Before(data.expiry) {
			return data.whitelist
		}
	}

	// Store in cache with expiration
	a.cache.Store(cacheKey, struct {
		whitelist []string
		expiry    time.Time
	}{whitelist: a.config.whitelist, expiry: time.Now().Add(time.Duration(a.config.CacheTTL) * time.Second)})

	return a.config.whitelist
}

// getRoleAndPermissionsOrFetchFromRoleXpert Fetch roles and permissions from RoleXpert API then cache all roles and permissions
func (a *traefikPlugin) getRoleAndPermissionsOrFetchFromRoleXpert() (map[string][]string, error) {
	if a.rolePermissions != nil {
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
