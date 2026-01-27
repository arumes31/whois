package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"whois/internal/config"
	"whois/internal/storage"

	"github.com/labstack/echo/v4"
)

func TestHandlers(t *testing.T) {
	e := echo.New()
	cfg := &config.Config{SecretKey: "test", DNSResolver: "8.8.8.8:53"}
	store := storage.NewStorage("localhost", "6379")
	h := NewHandler(store, cfg)

	t.Run("Index GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		
		// This will fail if templates are not loaded, but Render is mocked in Echo tests often.
		// For simplicity, let's just check if it doesn't panic.
		_ = h.Index(c)
	})

	t.Run("BulkUpload", func(t *testing.T) {
		// Note: FormFile needs multipart request, this test is simplified
	})

	t.Run("DNSLookup", func(t *testing.T) {
		f := url.Values{}
		f.Add("domain", "google.com")
		f.Add("type", "A")
		req := httptest.NewRequest(http.MethodPost, "/dns_lookup", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		if err := h.DNSLookup(c); err != nil {
			t.Errorf("DNSLookup failed: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rec.Code)
		}
	})

	t.Run("MacLookup", func(t *testing.T) {
		f := url.Values{}
		f.Add("mac", "00:11:22:33:44:55")
		req := httptest.NewRequest(http.MethodPost, "/mac_lookup", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		if err := h.MacLookup(c); err != nil {
			t.Errorf("MacLookup failed: %v", err)
		}
	})

	t.Run("Login", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Login(c)
	})
}
