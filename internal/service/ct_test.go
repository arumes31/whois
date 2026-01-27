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
		_, _ = fmt.Fprintln(w, `[{"name_value":"api.example.com"},{"name_value":"www.example.com\ndev.example.com"}]`)
	}))
	defer server.Close()

	originalURL := CTURL
	CTURL = server.URL + "/?q=%s&output=json"
	defer func() { CTURL = originalURL }()

	subs, err := FetchCTSubdomains("example.com")
	if err != nil {
		t.Fatalf("FetchCTSubdomains failed: %v", err)
	}

	if len(subs) != 3 {
		t.Errorf("Expected 3 subdomains, got %d", len(subs))
	}

	for _, s := range []string{"api.example.com", "www.example.com", "dev.example.com"} {
		if _, ok := subs[s]; !ok {
			t.Errorf("Expected subdomain %s not found", s)
		}
	}
}
