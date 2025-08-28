# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

This is a Go-based Traefik plugin project. Common development commands:

- **Build**: `go build` or `go build ./cmd` (for the test main)
- **Run tests**: `go test` or `go test -v` for verbose output
- **Format code**: `go fmt ./...`
- **Vet code**: `go vet ./...`
- **Get dependencies**: `go mod tidy`
- **Run test server**: `go run cmd/main.go` (starts test server on port 9090)

## Project Architecture

This project implements a Traefik middleware plugin for role-based access control (RBAC). The architecture consists of:

### Core Components

1. **Plugin Interface** (`plugin.go`):
   - Main middleware implementation in `traefikPlugin` struct
   - Implements Traefik's middleware pattern with `ServeHTTP` method
   - Handles JWT token verification and role-based authorization
   - Manages caching for performance optimization

2. **RoleXpert Client** (`rolexpert_client.go`):
   - HTTP client interface for communicating with RoleXpert service
   - Fetches roles/permissions and public keys from external service
   - Uses Basic Auth for API authentication

3. **Test Suite** (`plugin_test.go`):
   - Comprehensive test coverage with mocked dependencies
   - Tests authorization logic, pattern matching, and token verification
   - Uses `testify/mock` for dependency injection in tests

4. **Test Application** (`cmd/main.go`):
   - Standalone test server to verify plugin functionality
   - Demonstrates plugin integration with mock configuration

### Key Features

- **JWT Token Processing**: Validates RS256-signed JWT tokens with public key verification
- **Pattern Matching**: Supports flexible path/method patterns with wildcards (`*`, `**`)
- **Caching**: In-memory cache for whitelists and role permissions to reduce API calls
- **Whitelist Support**: Plugin-level and service-level whitelisting for bypass scenarios
- **Blocklist Support**: Plugin-level and service-level path blocking (prevents whitelist bypass, forces authentication)
- **Header Forwarding**: Passes user identity information to backend services

### Configuration Structure

The plugin uses a `Config` struct with these key fields:
- `ClientId`/`ClientSecret`: Authentication credentials for RoleXpert API
- `RoleXpertUrl`: Base URL of the external authorization service
- `CacheTTL`: Cache expiration time in seconds (default: 300)
- `Whitelist`: Comma-separated list of paths/methods to bypass authorization
- `Blocklist`: Comma-separated list of paths/methods that cannot bypass authentication (prevents whitelist bypass)

### Dependencies

- **JWT**: `github.com/golang-jwt/jwt/v5` for token processing
- **Testing**: `github.com/stretchr/testify` for assertions and mocking
- Standard Go libraries for HTTP, crypto, and encoding operations

The plugin follows Traefik's middleware conventions and integrates with the broader Traefik ecosystem for dynamic configuration and service discovery.