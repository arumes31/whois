package service

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchCTSubdomains(t *testing.T) {
	// Mock crt.sh response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `[{"name_value":"api.example.com"},{"name_value":"www.example.com\ndev.example.com"}]`)
	}))
	defer server.Close()

	// Redirect crt.sh URL to mock server
	// Note: In real code we'd need to inject the URL, but for unit test we can wrap the logic
	// or modify the service to accept a base URL.
	// Since I cannot easily change the service code without permission, I will test the logic
	// by manually triggering a failure or using a real domain if allowed.
	// Actually, I'll update the service to support a base URL for better testability.
}
