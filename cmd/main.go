package main

import (
	"context"
	"fmt"
	"github.com/rahkar-team/traefik-rolexpert-plugin"
	"log"
	"net/http"
)

func main() {
	// Create a test configuration
	config := &traefik_rolexpert_plugin.Config{
		ClientId:     "4dc78059-b61e-4ddc-a8db-f2c53222acf1",
		ClientSecret: "UQGIxVH8fCwAkMyyO2ZSvVevUi4eJWvQ",
		RoleXpertUrl: "http://localhost:8083/internal", // 🔥 Mocked RoleXpert service
		CacheTTL:     300,
		Whitelist:    "/**",                      // Allow these paths
		Blocklist:    "GET:/admin,DELETE:/users", // Block these paths (takes precedence)
	}

	// Create a new middleware instance
	middleware, err := traefik_rolexpert_plugin.New(context.Background(), http.HandlerFunc(testHandler), config, "test-middleware")
	if err != nil {
		log.Fatalf("Failed to create middleware: %v", err)
	}

	port := 9090
	// Start the test server
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: middleware,
	}

	fmt.Println(fmt.Sprintf("🚀 Test server is running on http://localhost:%d", port))
	log.Fatal(server.ListenAndServe())
}

// testHandler is a mock backend service that would normally be behind Traefik
func testHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "✅ Request passed through middleware and reached backend!")
}
