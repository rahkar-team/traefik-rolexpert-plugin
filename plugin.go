package main

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
)

const (
	BearerPrefix      = "Bearer "
	XAuthUserIdHeader = "X-Auth-User-Id"
)

// Config defines the middleware configuration.
type Config struct {
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	RoleXpertUrl string `json:"rolexpertBaseUrl"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

type traefikPlugin struct {
	next            http.Handler
	name            string
	config          *Config
	roleXpertClient Client
	publicKey       []byte
	rolePermissions map[string][]string
}

// New creates a new instance of the middleware plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
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
	}, nil
}

// ServeHTTP processes incoming requests.
func (a *traefikPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
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

	// Determine which roles (if any) authorize the request.
	var requiredRoles []string

	for role, permissions := range rolesPermissions {
		for _, permission := range permissions {
			// Extract the HTTP method and BaseURL pattern
			parts := strings.SplitN(permission, ":", 2)
			if len(parts) != 2 {
				continue
			}
			method, pattern := parts[0], parts[1]

			if strings.ToUpper(req.Method) != strings.ToUpper(method) {
				continue
			}

			// Convert the permission pattern into a regular expression.
			regexPattern := "^" + regexp.QuoteMeta(pattern) + "$"
			regexPattern = strings.ReplaceAll(regexPattern, "\\*\\*", ".*")
			regexPattern = strings.ReplaceAll(regexPattern, "\\*", "[^/]*")
			if matched, err := regexp.MatchString(regexPattern, req.URL.Path); err == nil && matched {
				requiredRoles = append(requiredRoles, role)
				break
			}
		}
	}

	req.Header.Set(XAuthUserIdHeader, authUserId)

	// If no roles are applicable for this request, allow it.
	if len(requiredRoles) == 0 {
		a.next.ServeHTTP(rw, req)
		return
	}

	// Check if any of the user roles match the required roles.
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
