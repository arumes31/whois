package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchCTSubdomains(t *testing.T) {
	// Mock Certspotter response
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `[{"dns_names":["api.example.com","www.example.com","dev.example.com"]}]`)
	}))
	defer ts.Close()

	originalCert := CertspotterURL
	CertspotterURL = ts.URL + "?domain=%s"
	defer func() { CertspotterURL = originalCert }()

	subs, err := FetchCTSubdomains(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("FetchCTSubdomains failed: %v", err)
	}

	if len(subs) != 3 {
		t.Errorf("Expected 3 subdomains, got %d", len(subs))
	}
}

func TestFetchCTSubdomains_Fallback(t *testing.T) {
	// Fail Certspotter, mock crt.sh
	cs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer cs.Close()

	cr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `[{"name_value":"api.example.com"},{"name_value":"www.example.com"}]`)
	}))
	defer cr.Close()

	originalCert := CertspotterURL
	originalCRT := CRTURL
	CertspotterURL = cs.URL + "?domain=%s"
	CRTURL = cr.URL + "?q=%s"
	defer func() {
		CertspotterURL = originalCert
		CRTURL = originalCRT
	}()

	subs, err := FetchCTSubdomains(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Fallback failed: %v", err)
	}

	if len(subs) != 2 {
		t.Errorf("Expected 2 subdomains from fallback, got %d", len(subs))
	}
}

func TestFetchCTSubdomains_Errors(t *testing.T) {
	t.Parallel()
	originalCert := CertspotterURL
	originalCRT := CRTURL
	defer func() {
		CertspotterURL = originalCert
		CRTURL = originalCRT
	}()

	t.Run("All Sources Fail", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()
		CertspotterURL = ts.URL + "?domain=%s"
		CRTURL = ts.URL + "?q=%s"

		_, err := FetchCTSubdomains(context.Background(), "err.com")
		if err == nil {
			t.Error("Expected error when all sources fail")
		}
	})
}
