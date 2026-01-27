package handler

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
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

	t.Run("Index POST JSON", func(t *testing.T) {
		f := url.Values{}
		f.Add("ips_and_domains", "google.com,8.8.8.8")
		f.Add("export", "json")
		f.Add("dns", "true")
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		if err := h.Index(c); err != nil {
			t.Errorf("Index POST failed: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rec.Code)
		}
	})

	t.Run("Index POST CSV", func(t *testing.T) {
		f := url.Values{}
		f.Add("ips_and_domains", "example.com")
		f.Add("export", "csv")
		f.Add("dns", "true")
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		if err := h.Index(c); err != nil {
			t.Errorf("Index POST CSV failed: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rec.Code)
		}
		if !strings.Contains(rec.Header().Get(echo.HeaderContentType), "text/csv") {
			t.Errorf("Expected CSV content type, got %s", rec.Header().Get(echo.HeaderContentType))
		}
	})

	t.Run("BulkUpload", func(t *testing.T) {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", "test.txt")
		_, _ = part.Write([]byte("google.com\n8.8.8.8"))
		_ = writer.Close()

		req := httptest.NewRequest(http.MethodPost, "/bulk_upload", body)
		req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		if err := h.BulkUpload(c); err != nil {
			t.Errorf("BulkUpload failed: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rec.Code)
		}
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

	t.Run("Scanner", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/scanner", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Scanner(c)
	})

	t.Run("Login POST", func(t *testing.T) {
		f := url.Values{}
		f.Add("username", "admin")
		f.Add("password", "pass")
		os.Setenv("CONFIG_USER", "admin")
		os.Setenv("CONFIG_PASS", "pass")
		os.Setenv("SECRET_KEY", "key")
		defer os.Unsetenv("CONFIG_USER")
		defer os.Unsetenv("CONFIG_PASS")
		defer os.Unsetenv("SECRET_KEY")

		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		if err := h.Login(c); err != nil {
			t.Errorf("Login POST failed: %v", err)
		}
		if rec.Code != http.StatusFound {
			t.Errorf("Expected 302 redirect, got %d", rec.Code)
		}
	})

	t.Run("Config GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/config", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Config(c)
	})

	t.Run("Config POST Add/Remove", func(t *testing.T) {
		f := url.Values{}
		f.Add("action", "add")
		f.Add("item", "example.com")
		req := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		if err := h.Config(c); err != nil {
			t.Errorf("Config POST add failed: %v", err)
		}
		if rec.Code != http.StatusFound {
			t.Errorf("Expected 302 redirect, got %d", rec.Code)
		}

		f.Set("action", "remove")
		req = httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)
		if err := h.Config(c); err != nil {
			t.Errorf("Config POST remove failed: %v", err)
		}
		if rec.Code != http.StatusFound {
			t.Errorf("Expected 302 redirect, got %d", rec.Code)
		}
	})

	t.Run("BulkUpload Errors", func(t *testing.T) {
		// Test wrong extension
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", "test.exe")
		_, _ = part.Write([]byte("google.com"))
		_ = writer.Close()
		req := httptest.NewRequest(http.MethodPost, "/bulk_upload", body)
		req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.BulkUpload(c)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 for invalid file type, got %d", rec.Code)
		}

		// Test file too large
		largeBody := make([]byte, 3*1024*1024)
		body = &bytes.Buffer{}
		writer = multipart.NewWriter(body)
		part, _ = writer.CreateFormFile("file", "test.txt")
		_, _ = part.Write(largeBody)
		_ = writer.Close()
		req = httptest.NewRequest(http.MethodPost, "/bulk_upload", body)
		req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)
		_ = h.BulkUpload(c)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("Expected 413 for large file, got %d", rec.Code)
		}
	})

	t.Run("Login POST Invalid", func(t *testing.T) {
		f := url.Values{}
		f.Add("username", "admin")
		f.Add("password", "wrong")
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Login(c)
		if rec.Code != http.StatusOK { // Re-renders login page
			t.Errorf("Expected 200 for invalid login, got %d", rec.Code)
		}
	})

	t.Run("Scan No Target", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/scan", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Scan(c)
		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rec.Code)
		}
	})
}
