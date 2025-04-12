package traefik_rolexpert_plugin

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Permission represents a permission object
type Permission struct {
	ID         int    `json:"id"`
	Permission string `json:"permission"`
}

// Role represents a role object with associated permissions
type Role struct {
	ID          int          `json:"id"`
	Name        string       `json:"name"`
	Permissions []Permission `json:"permissions"`
}

// RoleResponse represents the structure of the API response
type RoleResponse struct {
	Total    int    `json:"total"`
	Elements []Role `json:"elements"`
}

type PublicKeyResponse struct {
	Base64PublicKey string `json:"base64PublicKey"`
}

// Client represents the HTTP client with authentication details
type Client interface {
	FetchRoles() (RoleResponse, error)
	GetPublicKey() (PublicKeyResponse, error)
}

type roleXpertClient struct {
	ClientID     string
	ClientSecret string
	BaseURL      string
}

// NewClient is a constructor for creating a new Client instance
func NewClient(clientId, clientSecret, baseUrl string) Client {
	return roleXpertClient{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		BaseURL:      baseUrl,
	}
}

// FetchRoles makes the GET request and returns the response data
func (c roleXpertClient) FetchRoles() (RoleResponse, error) {
	// Create Basic Auth header value
	auth := fmt.Sprintf("%s:%s", c.ClientID, c.ClientSecret)
	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))

	// Make the GET request with Basic Authentication
	req, err := http.NewRequest("GET", c.BaseURL+"/roles", nil)
	if err != nil {
		return RoleResponse{}, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Add("Authorization", authHeader)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return RoleResponse{}, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return RoleResponse{}, fmt.Errorf("error reading response body: %v", err)
	}

	// Parse the JSON response
	var response RoleResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return RoleResponse{}, fmt.Errorf("error unmarshalling JSON: %v", err)
	}

	return response, nil
}

func (c roleXpertClient) GetPublicKey() (PublicKeyResponse, error) {
	// Create Basic Auth header value
	auth := fmt.Sprintf("%s:%s", c.ClientID, c.ClientSecret)
	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))

	// Make the GET request with Basic Authentication
	req, err := http.NewRequest("GET", c.BaseURL+"/auth/public-key", nil)
	if err != nil {
		return PublicKeyResponse{}, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Add("Authorization", authHeader)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return PublicKeyResponse{}, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return PublicKeyResponse{}, fmt.Errorf("error reading response body: %v", err)
	}

	// Parse the JSON response
	var response PublicKeyResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return PublicKeyResponse{}, fmt.Errorf("error unmarshalling JSON: %v", err)
	}

	return response, nil
}
