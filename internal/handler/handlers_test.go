package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"whois/internal/config"
	"whois/internal/storage"
	"whois/internal/utils"

	"github.com/labstack/echo/v4"
)

func init() {
	utils.TestInitLogger()
}

func setupTestEcho() (*echo.Echo, *utils.TemplateRegistry) {
	e := echo.New()
	// Find templates directory (might need to go up levels depending on where test is run)
	path := "../../templates/*.html"
	if _, err := os.Stat("templates"); err == nil {
		path = "templates/*.html"
	} else if _, err := os.Stat("../../templates"); err == nil {
		path = "../../templates/*.html"
	}

	reg := &utils.TemplateRegistry{
		Templates: template.Must(template.New("").Funcs(template.FuncMap{
			"IsIP": utils.IsIP,
		}).ParseGlob(path)),
	}
	e.Renderer = reg
	return e, reg
}

func TestHandlers(t *testing.T) {
	e, _ := setupTestEcho()
	cfg := &config.Config{SecretKey: "test", DNSResolver: "8.8.8.8:53", EnableDNS: true}
	store := storage.NewStorage("localhost", "6379")
	h := NewHandler(store, cfg)

	t.Run("Index GET UX", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		if err := h.Index(c); err != nil {
			t.Errorf("Index GET failed: %v", err)
		}

		body := rec.Body.String()
		if !strings.Contains(body, "WHOIS") {
			t.Error("Body does not contain expected title")
		}
		if !strings.Contains(body, "targetInput") {
			t.Error("Body does not contain input field")
		}
	})

	t.Run("Index POST Result UX", func(t *testing.T) {
		t.Parallel()
		f := url.Values{}
		f.Add("ips_and_domains", "google.com")
		f.Add("dns", "true")
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		_ = h.Index(c)

		body := rec.Body.String()
		// The POST result in index.html doesn't seem to render resultCards directly but via templates if method is POST
		// Let's verify if queryItem results are in the rendered map
		if !strings.Contains(body, "google.com") {
			t.Error("Result page does not contain target domain")
		}
	})

	t.Run("DNSLookup HTMX UX", func(t *testing.T) {
		t.Parallel()
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

		body := rec.Body.String()
		if !strings.Contains(body, "glass-panel") {
			t.Error("HTMX response missing glass-panel class")
		}
		if !strings.Contains(body, "google.com") {
			t.Error("HTMX response missing resolved domain")
		}
	})

	t.Run("MacLookup", func(t *testing.T) {
		t.Parallel()
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
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Login(c)
	})

	t.Run("Scanner", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/scanner", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Scanner(c)
	})

	t.Run("Login POST", func(t *testing.T) {
		t.Parallel()
		f := url.Values{}
		f.Add("username", "admin")
		f.Add("password", "pass")
		_ = os.Setenv("CONFIG_USER", "admin")
		_ = os.Setenv("CONFIG_PASS", "pass")
		_ = os.Setenv("SECRET_KEY", "key")
		defer func() {
			_ = os.Unsetenv("CONFIG_USER")
			_ = os.Unsetenv("CONFIG_PASS")
			_ = os.Unsetenv("SECRET_KEY")
		}()

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
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/config", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Config(c)
	})

	t.Run("Config POST Add/Remove", func(t *testing.T) {
		t.Parallel()
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
		t.Parallel()
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
		t.Parallel()
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

	t.Run("Logout", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/logout", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		if err := h.Logout(c); err != nil {
			t.Errorf("Logout handler failed: %v", err)
		}
		if rec.Code != http.StatusFound {
			t.Errorf("Expected 302, got %d", rec.Code)
		}
	})

	t.Run("History UX", func(t *testing.T) {
		t.Parallel()
		target := "example.com"
		_ = store.AddDNSHistory(context.Background(), target, map[string]string{"A": "1.1.1.1"})
		_ = store.AddDNSHistory(context.Background(), target, map[string]string{"A": "2.2.2.2"})

		req := httptest.NewRequest(http.MethodGet, "/history/"+target, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/history/:item")
		c.SetParamNames("item")
		c.SetParamValues(target)

		if err := h.GetHistory(c); err != nil {
			t.Errorf("History handler failed: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Logf("Got status %d, likely due to missing Redis in this environment", rec.Code)
			return
		}

		var resp map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp != nil && resp["entries"] != nil {
			if len(resp["entries"].([]interface{})) < 2 {
				t.Error("Expected at least 2 history entries")
			}
		}
	})
	t.Run("Metrics IP Restriction", func(t *testing.T) {
		t.Parallel()
		h.AppConfig.TrustedIPs = "192.168.1.1"

		dummyHandler := func(c echo.Context) error {
			return c.String(http.StatusOK, "ok")
		}

		// Test allowed
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mw := h.Metrics(dummyHandler)
		_ = mw(c)
		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200 for trusted IP, got %d", rec.Code)
		}

		// Test forbidden
		req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = "1.1.1.1:1234"
		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)
		_ = mw(c)
		if rec.Code != http.StatusForbidden {
			t.Errorf("Expected 403 for untrusted IP, got %d", rec.Code)
		}
	})

	t.Run("Health Check", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		_ = h.Health(c)
		// We don't fail on 503 because Redis might be down in test env
		if rec.Code != http.StatusOK && rec.Code != http.StatusServiceUnavailable {
			t.Errorf("Unexpected status code %d", rec.Code)
		}
	})

	t.Run("MacLookup Error Logic", func(t *testing.T) {
		t.Parallel()
		f := url.Values{}
		f.Add("mac", "invalid-mac")
		req := httptest.NewRequest(http.MethodPost, "/mac_lookup", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		_ = h.MacLookup(c)
		// "Vendor not found" is the expected response for unknown/invalid MACs in the current service logic
		if !strings.Contains(rec.Body.String(), "Vendor not found") {
			t.Errorf("Expected 'Vendor not found' in response, got: %s", rec.Body.String())
		}
	})

	t.Run("LoginRequired Middleware", func(t *testing.T) {
		t.Parallel()
		dummy := func(c echo.Context) error { return c.String(http.StatusOK, "ok") }
		mw := h.LoginRequired(dummy)

		// No cookie
		req := httptest.NewRequest(http.MethodGet, "/config", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = mw(c)
		if rec.Code != http.StatusFound {
			t.Errorf("Expected redirect, got %d", rec.Code)
		}

		// Wrong cookie
		req = httptest.NewRequest(http.MethodGet, "/config", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "wrong"})
		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)
		_ = mw(c)
		if rec.Code != http.StatusFound {
			t.Errorf("Expected redirect for wrong session, got %d", rec.Code)
		}
	})

	t.Run("Scan No Target", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "/scan", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Scan(c)
		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rec.Code)
		}
	})
}
