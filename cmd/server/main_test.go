package main

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"whois/internal/config"
	"whois/internal/utils"

	"github.com/labstack/echo/v4"
)

func TestNewServer(t *testing.T) {
	t.Setenv("SECRET_KEY", "test-secret")
	t.Setenv("ENVIRONMENT", "development")

	// Change to project root so templates can be found
	t.Chdir("../..")

	utils.InitLogger()
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	// Use invalid redis port to fail fast
	cfg.RedisPort = "1"
	cfg.TrustedIPs = "127.0.0.1"
	cfg.TrustProxy = false

	e, closeServer := NewServer(cfg)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := closeServer(ctx); err != nil {
			t.Errorf("close server: %v", err)
		}
	})
	if e == nil {
		t.Fatal("NewServer returned nil")
	}
	if e.Server.ReadTimeout != 15*time.Second {
		t.Fatalf("ReadTimeout = %s, want 15s", e.Server.ReadTimeout)
	}
	if e.Server.MaxHeaderBytes != 64<<10 {
		t.Fatalf("MaxHeaderBytes = %d, want %d", e.Server.MaxHeaderBytes, 64<<10)
	}

	// Exercise the routed middleware without turning a unit test into a real
	// Redis timeout probe. Index rendering is covered with deterministic storage
	// doubles in the handler package.
	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	t.Run("MetricsRejectsSpoofedForwardedIP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = "198.51.100.20:1234"
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("spoofed forwarding header returned %d, want 403", rec.Code)
		}
	})

	// Test Custom Error Handler
	t.Run("HTTPErrorHandler", func(t *testing.T) {
		// Health only supports GET; CSRF is skipped for health probes.
		req := httptest.NewRequest(http.MethodPost, "/health", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected 405, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "405") {
			t.Error("error page does not contain expected status code 405")
		}
		if strings.Contains(rec.Body.String(), "&lt;no value&gt;") || strings.Contains(rec.Body.String(), "<no value>") {
			t.Fatal("error page rendered with missing shared template data")
		}
	})

	t.Run("SharedPagesReceiveHeaderContext", func(t *testing.T) {
		tests := []struct {
			name       string
			path       string
			wantMarker string
		}{
			{name: "login", path: "/login?next=https://example.invalid", wantMarker: `name="next" value="/config"`},
			{name: "scanner", path: "/scanner", wantMarker: `data-page-path="/scanner"`},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, tt.path, nil)
				rec := httptest.NewRecorder()
				e.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("GET %s = %d, want 200", tt.path, rec.Code)
				}
				body := rec.Body.String()
				if !strings.Contains(body, tt.wantMarker) {
					t.Fatalf("GET %s missing %q", tt.path, tt.wantMarker)
				}
				if strings.Contains(body, "&lt;no value&gt;") || strings.Contains(body, "<no value>") {
					t.Fatalf("GET %s rendered with missing shared template data", tt.path)
				}
			})
		}
	})

	t.Run("UnknownRouteRemainsNotFound", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/does-not-exist", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("unknown route = %d, want 404", rec.Code)
		}
	})

	t.Run("StaticHEADHasCacheAndSecurityHeadersWithoutCSRFCookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodHead, "/static/css/main.css", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("static HEAD = %d, want 200", rec.Code)
		}
		if got := rec.Header().Get(echo.HeaderCacheControl); got != "public, max-age=3600, must-revalidate" {
			t.Fatalf("Cache-Control = %q", got)
		}
		if strings.Contains(rec.Header().Get(echo.HeaderSetCookie), "_csrf=") {
			t.Fatal("static HEAD allocated a CSRF cookie")
		}
		if got := rec.Header().Get("Referrer-Policy"); got == "" {
			t.Fatal("static response missing Referrer-Policy")
		}
	})

	t.Run("CSPRejectsExecutableInlineScript", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/static/css/main.css", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		csp := rec.Header().Get(echo.HeaderContentSecurityPolicy)
		if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") || strings.Contains(csp, "'unsafe-eval'") {
			t.Fatalf("weak CSP = %q", csp)
		}
		if !strings.Contains(csp, "object-src 'none'") {
			t.Fatalf("CSP missing object-src restriction: %q", csp)
		}
		for _, source := range strings.Fields(csp) {
			source = strings.TrimSuffix(source, ";")
			if source == "ws:" || source == "wss:" {
				t.Fatalf("CSP contains an unrestricted WebSocket scheme source: %q", csp)
			}
		}
		if !strings.Contains(csp, "connect-src 'self' ws://example.com:80") {
			t.Fatalf("CSP missing exact same-origin WebSocket source: %q", csp)
		}
	})

	t.Run("BulkUploadAllowsMultipartFramingButKeepsTwoMiBFileCap", func(t *testing.T) {
		csrfRequest := httptest.NewRequest(http.MethodGet, "/login", nil)
		csrfRecorder := httptest.NewRecorder()
		e.ServeHTTP(csrfRecorder, csrfRequest)
		var csrfCookie *http.Cookie
		for _, cookie := range csrfRecorder.Result().Cookies() {
			if cookie.Name == "_csrf" {
				csrfCookie = cookie
				break
			}
		}
		if csrfCookie == nil {
			t.Fatal("login response did not issue a CSRF cookie")
		}

		tests := []struct {
			name       string
			fileSize   int
			wantStatus int
		}{
			{name: "exactly two MiB", fileSize: 2 * 1024 * 1024, wantStatus: http.StatusOK},
			{name: "one byte over two MiB", fileSize: 2*1024*1024 + 1, wantStatus: http.StatusRequestEntityTooLarge},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				body := &bytes.Buffer{}
				writer := multipart.NewWriter(body)
				part, err := writer.CreateFormFile("file", "targets.txt")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := part.Write(bytes.Repeat([]byte{' '}, tt.fileSize)); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}

				req := httptest.NewRequest(http.MethodPost, "/bulk-upload", body)
				req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
				req.Header.Set("X-CSRF-Token", csrfCookie.Value)
				req.AddCookie(csrfCookie)
				rec := httptest.NewRecorder()
				e.ServeHTTP(rec, req)
				if rec.Code != tt.wantStatus {
					t.Fatalf("status = %d, want %d: %s", rec.Code, tt.wantStatus, rec.Body.String())
				}
			})
		}
	})

	t.Run("LogoutIsPOSTAndCSRFProtected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/logout", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET /logout = %d, want 405", rec.Code)
		}

		req = httptest.NewRequest(http.MethodPost, "/logout", nil)
		rec = httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("POST /logout without CSRF = %d, want 400", rec.Code)
		}
	})
}

func TestTrustedProxyNetworksNormalizeBareAddresses(t *testing.T) {
	networks := parseTrustedNetworks("127.0.0.1,0:0:0:0:0:0:0:1,192.0.2.0/24")
	for _, address := range []string{"127.0.0.1", "::1", "192.0.2.10"} {
		if !ipInNetworks(address, networks) {
			t.Errorf("expected %s to match a trusted network", address)
		}
	}
	if ipInNetworks("198.51.100.10", networks) {
		t.Error("unexpected match for an untrusted address")
	}
}
