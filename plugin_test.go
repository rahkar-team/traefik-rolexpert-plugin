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
			expectedBody:   "token invalid!\n",
		},
		{
			name:           "Invalid Authorization Header (No Bearer Prefix)",
			authHeader:     "Invalid token",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "token invalid!\n",
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
			assert.Equal(t, tt.expectedBody, rr.Body.String())
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
			expectedBody:   "token invalid!\n",
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

// --- Valid Test RSA Keys (for testing only) ---

const testRSAPrivateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgGAk62rtvyjzBQheIGQvXdGY9V/59k38/VspfsGuH02Kpt2wrkDl
JC8kwDn9GnS3yFtsFMCjXwEk/3dWg9Dy+uyEBgTZTnxW8KukF21otY0hcVOlPshT
rDiJrGlxS/UgZtL9jvhl/SnYCfbK9l/LaNCcRzF0p/sJ3t6NZ+7AH6VrAgMBAAEC
gYAEBufZZbXhCDTIwfCHYbiDQ+3bJEQdxh/yho1pnVpwTANrO7BAxZg7ZUWr6B8I
jn4U3jUMUIt1J9CPdg81XEgIPOSDQiTmMWDUXWcb0VTgT63t39hZIEU/m2ax4eXz
RbDoO8M/+ZtvljYw4WxExH7AaeOTfOoU+VAb48/dWu7HiQJBAKL6mPGCOgdeca36
vAQBwwihezmjzr6H9RYGfcsyP2IVtjIaVmpC8QCRIz32mZ9dqhyJMoIHtXXCUSUQ
vgxYlO0CQQCXBOESlvnSUf5whNgmD0+v9vaQhAkZcX6cj7K0YofMqYfLmNefFNpm
1YTIHMKmcjYzRQB8yPGbeKzAHyAHC/C3AkBsrn4FNxlpRpK6OSTd6yra+4xH0LOS
nOlT6bpDIVvhFads2+FadQ9vmFmO/X5OJtDEvLzgtzFLuOwRsot5giy1AkBALiap
C9in9Yi4sPxbUG6BTeeDi1mCoqU4TCmaV7V22SWI9S/Nv8MBqQSBNxfSPP+j0lNe
tNdZR3PDQncOB5kJAkBqxCLt6Pjd0fc7wef58Dh7Zrq9UmHIDBEWVe8/JdRqMTMV
rM5GWZ+IQSD6KSyF/5LkLkRKl4ZWFu6A1FHd5bnr
-----END RSA PRIVATE KEY-----`

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
			expectedBody:   "Error fetching roles and permissions: failed to fetch roles\n",
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
