package traefik_rolexpert_plugin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Mocking the Client interface
type MockRoleXpertClient struct {
	mock.Mock
}

func (m *MockRoleXpertClient) FetchRoles() (RoleResponse, error) {
	args := m.Called()
	return args.Get(0).(RoleResponse), args.Error(1)
}

func (m *MockRoleXpertClient) GetPublicKey() (PublicKeyResponse, error) {
	args := m.Called()
	return args.Get(0).(PublicKeyResponse), args.Error(1)
}

// Mock Handler for testing purposes
func mockHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func TestAuthorizationHeader(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "No Authorization Header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid Authorization Header (No Bearer Prefix)",
			authHeader:     "Invalid token",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock handler for the test
			plugin := &traefikPlugin{
				next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Mock next handler, it just returns OK status for valid cases
					w.WriteHeader(http.StatusOK)
				}),
				config: config{Config: CreateConfig()},
			}

			// Create a request with the Authorization header
			req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Record the response
			rr := httptest.NewRecorder()

			// Call ServeHTTP
			plugin.ServeHTTP(rr, req)

			// Check the response status and body
			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}

func TestVerifyTokenAndGetPayloadWithRoleXpertClientMock(t *testing.T) {
	// Example of a dummy RSA public key (for mock purposes only)
	encodedPublicKey := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy2rZsLvMkrTJo4L04JWv/R530xxtvG0szCCIxlRij2r96+pRBnu41f0mfy5Hz5eVqtDZgOFZJ8Il8QczORwzoUZIZho9HqJ01dX5tPs3dNmYIB2uPpLs0OF+ZEUTv0+7fntTHFQHgwmEOers11Zz/o+hRMtHZwOZt3TX6svVGuaMyEawnyqYVTCL53h4qZL43U0C7de8jXb0xzYy9Jv64o9rHGB510oR9dx/dDYqnsEZ4nmDUONP16nHFJ1pUybVHu06HqpKpXjd2yV1QfM1ApXmLZ1zZ6MPs33VQtRQk/h1QrzXD9te25imIhCP8/tg5gM7U9zk10RUfEFDxgd3LQIDAQAB"

	tests := []struct {
		name                string
		authHeader          string
		mockRoleXpertClient func() *MockRoleXpertClient
		expectedStatus      int
		expectedBody        string
	}{
		{
			name:       "Valid Token with RoleXpertClient Mock",
			authHeader: "Bearer eyJ0eXBlIjoiQUNDRVNTIiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJSb2xlWHBlcnQiLCJzdWIiOiI2Y2I2NzlmYy1jNWU1LTRiZTYtYjNiYS1hNDVkNDQyODYxNmQiLCJkYXRhIjp7InJvbGVzIjpbIkdPRCJdLCJtZXRhZGF0YSI6e319LCJleHAiOjE3NDA5OTkyMTh9.UeqhZviY4QNQfZIiuFAP3ub9pfiz5MJ9zHXxRQFeVplpvjgjvhZLdljDpTVhG-ZwSpEc6ie7Ei5qz-3AlbeRvekfjktUK_mntWSybX-Ptqqz6hM7IhYzc-N4uI3KBkdt6QDofG9CfRqAQaeTNgHeA4P_PUleLEnORu6QGj6w1lnHzHRnJBjDz1OQdnDyvtHtzNw-my2UPpt-ib20yI19ZRW1RiSbeH4tp-S3AwD-NTvf2PbnD-lH5myoncUEd3yjLDC6qMlI2L4vSOnqE0h7vUGUVZabgz5XfrU-Saml0Prtimi9Cn3r2HI5IWW7k_CUC5NfKyJpfwvcEacJkYhUtg",
			mockRoleXpertClient: func() *MockRoleXpertClient {
				mockClient := new(MockRoleXpertClient)
				// Mock FetchRoles response
				mockClient.On("FetchRoles").Return(RoleResponse{
					Total: 1,
					Elements: []Role{
						{
							ID:   1,
							Name: "user",
							Permissions: []Permission{
								{Permission: "GET:/some/path"},
							},
						},
					},
				}, nil)
				// Mock GetPublicKey response with base64 encoded key
				mockClient.On("GetPublicKey").Return(PublicKeyResponse{Base64PublicKey: encodedPublicKey}, nil)
				return mockClient
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "",
		},
		{
			name:       "Invalid Token with RoleXpertClient Mock",
			authHeader: "Bearer invalid-token",
			mockRoleXpertClient: func() *MockRoleXpertClient {
				mockClient := new(MockRoleXpertClient)
				// Simulate error fetching roles
				mockClient.On("FetchRoles").Return(RoleResponse{}, fmt.Errorf("error fetching roles"))
				// Mock GetPublicKey response with base64 encoded key
				mockClient.On("GetPublicKey").Return(PublicKeyResponse{Base64PublicKey: encodedPublicKey}, nil)
				return mockClient
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "{\"errors\":[{\"code\":\"invalid_token\",\"message\":\"token invalid\"}]}\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize the mock RoleXpertClient
			mockClient := tt.mockRoleXpertClient()

			// Create the plugin instance with the mocked RoleXpertClient
			plugin := &traefikPlugin{
				next:            http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
				roleXpertClient: mockClient,
				config:          config{Config: CreateConfig()},
			}

			// Create a request with the Authorization header
			req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
			req.Header.Set("Authorization", tt.authHeader)

			// Record the response
			rr := httptest.NewRecorder()

			// Call ServeHTTP
			plugin.ServeHTTP(rr, req)

			// Check the response status and body
			assert.Equal(t, tt.expectedStatus, rr.Code)
			assert.Equal(t, tt.expectedBody, rr.Body.String())
		})
	}
}

// --- Helper Functions ---

func parseRSAPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, err := decodePEM(data)
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func decodePEM(data []byte) (*pem.Block, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	return block, nil
}

func pubKeyToBase64(pubKey *rsa.PublicKey) (string, error) {
	derBytes, err := x509.ParsePKIXPublicKey(pubKey.N.Bytes())
	if err != nil {
		return "", err
	}
	base64Str := base64.StdEncoding.EncodeToString(derBytes.([]byte))
	return base64Str, nil
}

// generateToken creates a JWT signed with the provided RSA private key and given claims.
func generateToken(privKey *rsa.PrivateKey, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privKey)
}

// --- Test Cases for Role Authorization Logic ---

func TestRoleAuthorizationLogic(t *testing.T) {
	// Parse our test private key.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Step 2: Extract the public key from the private key
	publicKey := &privateKey.PublicKey

	// Step 3: Convert the RSA public key to DER format
	derBytes, err := x509.MarshalPKIXPublicKey(interface{}(publicKey))
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
	}

	// Step 4: Encode the DER bytes as a Base64 string
	encodedPubKey := base64.StdEncoding.EncodeToString(derBytes)

	tests := []struct {
		name              string
		mockRolesResponse RoleResponse
		mockFetchRolesErr error
		// JWT claims to include in the token.
		tokenClaims jwt.MapClaims
		// Request parameters.
		reqMethod string
		reqURL    string
		// Expected HTTP status and response body.
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "Matching permission - allowed",
			mockRolesResponse: RoleResponse{
				Total: 1,
				Elements: []Role{
					{
						ID:   1,
						Name: "user",
						Permissions: []Permission{
							{Permission: "GET:/allowed"},
						},
					},
				},
			},
			tokenClaims: jwt.MapClaims{
				"sub":  "user123",
				"data": map[string]interface{}{"roles": []string{"user"}},
				"exp":  time.Now().Add(time.Hour).Unix(),
			},
			reqMethod:      "GET",
			reqURL:         "/allowed",
			expectedStatus: http.StatusOK,
			expectedBody:   "",
		},
		{
			name: "Non-matching permission (HTTP method mismatch) - allowed",
			mockRolesResponse: RoleResponse{
				Total: 1,
				Elements: []Role{
					{
						ID:   1,
						Name: "user",
						Permissions: []Permission{
							{Permission: "POST:/allowed"},
						},
					},
				},
			},
			tokenClaims: jwt.MapClaims{
				"sub":  "user123",
				"data": map[string]interface{}{"roles": []string{"user"}},
				"exp":  time.Now().Add(time.Hour).Unix(),
			},
			reqMethod: "GET",
			reqURL:    "/allowed",
			// No applicable permission; middleware allows the request.
			expectedStatus: http.StatusOK,
			expectedBody:   "",
		},
		{
			name: "Non-matching permission (Role mismatch) - allowed",
			mockRolesResponse: RoleResponse{
				Total: 1,
				Elements: []Role{
					{
						ID:   1,
						Name: "admin",
						Permissions: []Permission{
							{Permission: "POST:/allowed"},
						},
					},
				},
			},
			tokenClaims: jwt.MapClaims{
				"sub":  "user123",
				"data": map[string]interface{}{"roles": []string{"user"}},
				"exp":  time.Now().Add(time.Hour).Unix(),
			},
			reqMethod: "GET",
			reqURL:    "/allowed",
			// No applicable permission; middleware allows the request.
			expectedStatus: http.StatusOK,
			expectedBody:   "",
		},
		{
			name:              "FetchRoles error - internal server error",
			mockFetchRolesErr: fmt.Errorf("failed to fetch roles"),
			tokenClaims: jwt.MapClaims{
				"sub":  "user123",
				"data": map[string]interface{}{"roles": []string{"user"}},
				"exp":  time.Now().Add(time.Hour).Unix(),
			},
			reqMethod:      "GET",
			reqURL:         "/allowed",
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "{\"errors\":[{\"code\":\"internal_error\",\"message\":\"Error fetching roles and permissions\"}]}\n",
		},
		{
			name: "Malformed permission string - allowed",
			mockRolesResponse: RoleResponse{
				Total: 1,
				Elements: []Role{
					{
						ID:   1,
						Name: "user",
						Permissions: []Permission{
							// No colon in the permission, so it will be skipped.
							{Permission: "INVALID_PERMISSION"},
						},
					},
				},
			},
			tokenClaims: jwt.MapClaims{
				"sub":  "user123",
				"data": map[string]interface{}{"roles": []string{"user"}},
				"exp":  time.Now().Add(time.Hour).Unix(),
			},
			reqMethod: "GET",
			reqURL:    "/allowed",
			// No applicable permission; middleware allows the request.
			expectedStatus: http.StatusOK,
			expectedBody:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Generate a JWT token using the test private key.
			tokenString, err := generateToken(privateKey, tc.tokenClaims)
			assert.NoError(t, err)

			// Create a mock RoleXpertClient.
			mockClient := new(MockRoleXpertClient)
			// Mock GetPublicKey to return our encoded test public key.
			mockClient.On("GetPublicKey").Return(PublicKeyResponse{Base64PublicKey: encodedPubKey}, nil)
			// Mock FetchRoles per test case.
			if tc.mockFetchRolesErr != nil {
				mockClient.On("FetchRoles").Return(RoleResponse{}, tc.mockFetchRolesErr)
			} else {
				mockClient.On("FetchRoles").Return(tc.mockRolesResponse, nil)
			}

			// Create a dummy next handler that sets status OK.
			nextHandlerCalled := false
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextHandlerCalled = true
				w.WriteHeader(http.StatusOK)
			})

			// Create the plugin instance.
			plugin := &traefikPlugin{
				next:            nextHandler,
				roleXpertClient: mockClient,
				// Pre-set publicKey to bypass GetPublicKey call in verifyTokenAndGetPayload.
				config: config{Config: CreateConfig()},
			}
			// Initialize rolePermissions so that getRoleAndPermissionsOrFetchFromRoleXpert calls FetchRoles.
			plugin.rolePermissions = map[string][]string{}

			// Build the HTTP request.
			req := httptest.NewRequest(tc.reqMethod, tc.reqURL, nil)
			req.Header.Set("Authorization", "Bearer "+tokenString)
			rr := httptest.NewRecorder()

			// Call ServeHTTP.
			plugin.ServeHTTP(rr, req)

			// If FetchRoles returned an error, verify the error response.
			if tc.mockFetchRolesErr != nil {
				assert.Equal(t, tc.expectedStatus, rr.Code)
				assert.Equal(t, tc.expectedBody, rr.Body.String())
				return
			}

			// Otherwise, the request should be allowed and the next handler called.
			assert.True(t, nextHandlerCalled, "expected next handler to be called")
			assert.Equal(t, tc.expectedStatus, rr.Code)
		})
	}
}

func TestBlocklistFunctionality(t *testing.T) {
	tests := []struct {
		name           string
		blocklist      string
		reqMethod      string
		reqPath        string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Request matches blocklist - should proceed to auth (not bypass)",
			blocklist:      "GET:/blocked,POST:/admin",
			reqMethod:      "GET",
			reqPath:        "/blocked",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "{\"errors\":[{\"code\":\"unauthorized\",\"message\":\"authorization required\"}]}\n",
		},
		{
			name:           "Request doesn't match blocklist - should proceed to auth",
			blocklist:      "GET:/blocked,POST:/admin",
			reqMethod:      "GET",
			reqPath:        "/allowed",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "{\"errors\":[{\"code\":\"unauthorized\",\"message\":\"authorization required\"}]}\n",
		},
		{
			name:           "Empty blocklist - should proceed to auth",
			blocklist:      "",
			reqMethod:      "GET",
			reqPath:        "/anything",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "{\"errors\":[{\"code\":\"unauthorized\",\"message\":\"authorization required\"}]}\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create plugin config with blocklist
			cfg := &Config{
				Blocklist: tt.blocklist,
				CacheTTL:  300,
			}

			// Parse blocklist
			var bl []string
			if cfg.Blocklist != "" {
				bl = strings.Split(cfg.Blocklist, ",")
			}

			// Create plugin instance
			plugin := &traefikPlugin{
				next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}),
				config: config{
					Config:    cfg,
					blocklist: bl,
				},
				cache: sync.Map{},
			}

			// Create request
			req := httptest.NewRequest(tt.reqMethod, tt.reqPath, nil)
			rr := httptest.NewRecorder()

			// Call ServeHTTP
			plugin.ServeHTTP(rr, req)

			// Check response
			assert.Equal(t, tt.expectedStatus, rr.Code)
			assert.Equal(t, tt.expectedBody, rr.Body.String())
		})
	}
}

func TestWhitelistAndBlocklistTogether(t *testing.T) {
	tests := []struct {
		name           string
		whitelist      string
		blocklist      string
		reqMethod      string
		reqPath        string
		expectedStatus int
		description    string
	}{
		{
			name:           "Path in blocklist should not be whitelisted (requires auth)",
			whitelist:      "GET:/test,POST:/admin",
			blocklist:      "GET:/test",
			reqMethod:      "GET",
			reqPath:        "/test",
			expectedStatus: http.StatusUnauthorized,
			description:    "Blocklist prevents whitelist bypass, requires auth",
		},
		{
			name:           "Path in whitelist but not blocklist should be allowed",
			whitelist:      "GET:/allowed,POST:/admin",
			blocklist:      "GET:/blocked",
			reqMethod:      "GET",
			reqPath:        "/allowed",
			expectedStatus: http.StatusOK,
			description:    "Whitelisted path should be allowed when not blocked",
		},
		{
			name:           "Path not in either list should proceed to auth",
			whitelist:      "GET:/allowed",
			blocklist:      "GET:/blocked",
			reqMethod:      "GET",
			reqPath:        "/other",
			expectedStatus: http.StatusUnauthorized,
			description:    "Path not in whitelist or blocklist should require auth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create plugin config
			cfg := &Config{
				Whitelist: tt.whitelist,
				Blocklist: tt.blocklist,
				CacheTTL:  300,
			}

			// Parse lists
			var wl []string
			if cfg.Whitelist != "" {
				wl = strings.Split(cfg.Whitelist, ",")
			}
			var bl []string
			if cfg.Blocklist != "" {
				bl = strings.Split(cfg.Blocklist, ",")
			}

			// Create plugin instance
			plugin := &traefikPlugin{
				next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}),
				config: config{
					Config:    cfg,
					whitelist: wl,
					blocklist: bl,
				},
				cache: sync.Map{},
			}

			// Create request
			req := httptest.NewRequest(tt.reqMethod, tt.reqPath, nil)
			rr := httptest.NewRecorder()

			// Call ServeHTTP
			plugin.ServeHTTP(rr, req)

			// Check response
			assert.Equal(t, tt.expectedStatus, rr.Code, tt.description)
		})
	}
}

func TestPatternMatched(t *testing.T) {
	tests := []struct {
		pattern   string
		reqMethod string
		reqPath   string
		expected  bool
		name      string
	}{
		{
			name:      "Wildcard method and exact path match",
			pattern:   "*:/test",
			reqMethod: "GET",
			reqPath:   "/test",
			expected:  true,
		},
		{
			name:      "Wildcard method and path mismatch",
			pattern:   "*:/test",
			reqMethod: "POST",
			reqPath:   "/test/123",
			expected:  false,
		},
		{
			name:      "Empty method and exact path match",
			pattern:   ":/test",
			reqMethod: "PUT",
			reqPath:   "/test",
			expected:  true,
		},
		{
			name:      "Specific methods and matching GET",
			pattern:   "GET|POST:/test",
			reqMethod: "GET",
			reqPath:   "/test",
			expected:  true,
		},
		{
			name:      "Specific methods and matching POST",
			pattern:   "GET|POST:/test",
			reqMethod: "POST",
			reqPath:   "/test",
			expected:  true,
		},
		{
			name:      "Specific methods and non-matching PUT",
			pattern:   "GET|POST:/test",
			reqMethod: "PUT",
			reqPath:   "/test",
			expected:  false,
		},
		{
			name:      "Single specific method match",
			pattern:   "GET:/test",
			reqMethod: "GET",
			reqPath:   "/test",
			expected:  true,
		},
		{
			name:      "Single specific method no match",
			pattern:   "GET:/test",
			reqMethod: "POST",
			reqPath:   "/test",
			expected:  false,
		},
		{
			name:      "Path only match with GET method",
			pattern:   "/test",
			reqMethod: "GET",
			reqPath:   "/test",
			expected:  true,
		},
		{
			name:      "Path only mismatch",
			pattern:   "/test",
			reqMethod: "DELETE",
			reqPath:   "/test/123",
			expected:  false,
		},
		{
			name:      "Path with wildcard and GET method",
			pattern:   "/user/*",
			reqMethod: "GET",
			reqPath:   "/user/123",
			expected:  true,
		},
		{
			name:      "Method and path with wildcard match",
			pattern:   "GET:/items/*",
			reqMethod: "GET",
			reqPath:   "/items/5",
			expected:  true,
		},
		{
			name:      "Method and path with wildcard mismatch on method",
			pattern:   "POST:/items/*",
			reqMethod: "GET",
			reqPath:   "/items/5",
			expected:  false,
		},
		{
			name:      "Method and path with wildcard item id",
			pattern:   "GET:/items/*/children",
			reqMethod: "GET",
			reqPath:   "/items/5/children",
			expected:  true,
		},
		{
			name:      "Double stars wildcard",
			pattern:   "GET:/items/**",
			reqMethod: "GET",
			reqPath:   "/items/children/it-should-work",
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := patternMatched(tt.pattern, tt.reqMethod, tt.reqPath)
			if actual != tt.expected {
				t.Errorf("patternMatched(%q, %q, %q) = %v, want %v", tt.pattern, tt.reqMethod, tt.reqPath, actual, tt.expected)
			}
		})
	}
}
