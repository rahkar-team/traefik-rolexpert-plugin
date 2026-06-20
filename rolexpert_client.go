package traefik_rolexpert_plugin

import (
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

// Client represents the HTTP client
type Client interface {
	FetchRoles() (RoleResponse, error)
	GetPublicKey() (PublicKeyResponse, error)
}

type roleXpertClient struct {
	BaseURL string
}

// NewClient is a constructor for creating a new Client instance
func NewClient(baseUrl string) Client {
	return roleXpertClient{
		BaseURL: baseUrl,
	}
}

// FetchRoles makes the GET request and returns the response data
func (c roleXpertClient) FetchRoles() (RoleResponse, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/internal/roles", nil)
	if err != nil {
		return RoleResponse{}, fmt.Errorf("error creating request: %v", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return RoleResponse{}, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return RoleResponse{}, fmt.Errorf("error reading response body: %v", err)
	}

	var response RoleResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return RoleResponse{}, fmt.Errorf("error unmarshalling JSON: %v", err)
	}

	return response, nil
}

func (c roleXpertClient) GetPublicKey() (PublicKeyResponse, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/internal/auth/public-key", nil)
	if err != nil {
		return PublicKeyResponse{}, fmt.Errorf("error creating request: %v", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return PublicKeyResponse{}, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return PublicKeyResponse{}, fmt.Errorf("error reading response body: %v", err)
	}

	var response PublicKeyResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return PublicKeyResponse{}, fmt.Errorf("error unmarshalling JSON: %v", err)
	}

	return response, nil
}
