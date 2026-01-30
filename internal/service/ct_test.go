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
	t.Run("All Sources Fail", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()

		originalCertspotter := CertspotterURL
		originalCrtSh := CRTURL
		originalSubCenter := SubdomainCenterURL
		CertspotterURL = ts.URL + "/%s"
		CRTURL = ts.URL + "/%s"
		SubdomainCenterURL = ts.URL + "/%s"
		defer func() {
			CertspotterURL = originalCertspotter
			CRTURL = originalCrtSh
			SubdomainCenterURL = originalSubCenter
		}()

		_, err := FetchCTSubdomains(context.Background(), "error.com")
		if err == nil {
			t.Error("Expected error when all sources fail")
		}
	})

	t.Run("Subdomain Center Fallback", func(t *testing.T) {
		// Fail Certspotter and crt.sh
		tsFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer tsFail.Close()

		// Mock Subdomain Center
		tsSub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintln(w, `["sub1.example.com", "sub2.example.com"]`)
		}))
		defer tsSub.Close()

		originalCertspotter := CertspotterURL
		originalCrtSh := CRTURL
		originalSubCenter := SubdomainCenterURL
		CertspotterURL = tsFail.URL + "/%s"
		CRTURL = tsFail.URL + "/%s"
		SubdomainCenterURL = tsSub.URL + "/%s"
		defer func() {
			CertspotterURL = originalCertspotter
			CRTURL = originalCrtSh
			SubdomainCenterURL = originalSubCenter
		}()

		subs, err := FetchCTSubdomains(context.Background(), "example.com")
		if err != nil {
			t.Fatalf("Subdomain Center fallback failed: %v", err)
		}
		if len(subs) != 2 {
			t.Errorf("Expected 2 subdomains, got %d", len(subs))
		}
	})

	t.Run("Invalid JSON from Sources", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("invalid json"))
		}))
		defer ts.Close()

		originalCertspotter := CertspotterURL
		CertspotterURL = ts.URL + "/%s"
		defer func() { CertspotterURL = originalCertspotter }()

		_, _ = fetchCertspotter(context.Background(), "google.com")
	})

	t.Run("No Subdomains from crt.sh", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
		}))
		defer ts.Close()

		originalCrtSh := CRTURL
		CRTURL = ts.URL + "/%s"
		defer func() { CRTURL = originalCrtSh }()

		_, err := fetchCrtSh(context.Background(), "google.com")
		if err == nil {
			t.Error("Expected error when no subdomains found")
		}
	})

	t.Run("Invalid JSON from crt.sh", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`invalid json`))
		}))
		defer ts.Close()

		originalCrtSh := CRTURL
		CRTURL = ts.URL + "/%s"
		defer func() { CRTURL = originalCrtSh }()

		_, err := fetchCrtSh(context.Background(), "google.com")
		if err == nil {
			t.Error("Expected error for invalid JSON from crt.sh")
		}
	})
}
