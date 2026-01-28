package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

	subs, err := FetchCTSubdomains(context.Background(), "example.com")
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

func TestFetchCTSubdomains_Errors(t *testing.T) {
	t.Parallel()
	originalURL := CTURL
	defer func() { CTURL = originalURL }()

	t.Run("HTTP Error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()
		CTURL = ts.URL + "/?q=%s"
		_, err := FetchCTSubdomains(context.Background(), "err.com")
		if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
			t.Errorf("Expected HTTP 500 error, got %v", err)
		}
	})

	t.Run("No Subdomains", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(w, `[]`)
		}))
		defer ts.Close()
		CTURL = ts.URL + "/?q=%s"
		_, err := FetchCTSubdomains(context.Background(), "empty.com")
		if err == nil || !strings.Contains(err.Error(), "No subdomains found") {
			t.Errorf("Expected 'No subdomains found' error, got %v", err)
		}
	})
}
