package handler

import (
	"bytes"
	"context"
	"html/template"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
	"whois/internal/config"
	"whois/internal/model"
	"whois/internal/service"
	"whois/internal/storage"
	"whois/internal/utils"

	"github.com/alicebob/miniredis/v2"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

func init() {
	utils.TestInitLogger()
}

func setupTestEcho() (*echo.Echo, *utils.TemplateRegistry) {
	e := echo.New()
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

func setupMiniredisStorage(t *testing.T) *storage.Storage {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return &storage.Storage{Client: client}
}

func TestHandlers(t *testing.T) {
	e, _ := setupTestEcho()
	cfg := &config.Config{SecretKey: "test", DNSResolver: "8.8.8.8:53", EnableDNS: true, EnableGeo: true}
	store := setupMiniredisStorage(t)
	h := NewHandler(store, cfg)

	t.Run("Index GET UX", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.Index(c); err != nil {
			t.Errorf("Index GET failed: %v", err)
		}
	})

	t.Run("Index POST Result UX", func(t *testing.T) {
		f := url.Values{}
		f.Add("ips_and_domains", "google.com")
		f.Add("dns", "true")
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Index(c)
	})

	t.Run("Index POST Export CSV", func(t *testing.T) {
		f := url.Values{}
		f.Add("ips_and_domains", "google.com")
		f.Add("export", "csv")
		f.Add("dns", "true")
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.Index(c); err != nil {
			t.Fatal(err)
		}
		if rec.Header().Get("Content-Type") != "text/csv" {
			t.Errorf("Expected text/csv, got %s", rec.Header().Get("Content-Type"))
		}
	})

	t.Run("DNSLookup HTMX UX", func(t *testing.T) {
		f := url.Values{}
		f.Add("domain", "google.com")
		f.Add("type", "A")
		req := httptest.NewRequest(http.MethodPost, "/dns_lookup", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.DNSLookup(c)
	})

	t.Run("MacLookup", func(t *testing.T) {
		f := url.Values{}
		f.Add("mac", "00:11:22:33:44:55")
		req := httptest.NewRequest(http.MethodPost, "/mac_lookup", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.MacLookup(c)
	})

	t.Run("Login GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Login(c)
	})

	t.Run("Login POST Success", func(t *testing.T) {
		os.Setenv("CONFIG_USER", "admin")
		os.Setenv("CONFIG_PASS", "pass")
		os.Setenv("SECRET_KEY", "testkey")
		f := url.Values{}
		f.Add("username", "admin")
		f.Add("password", "pass")
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Login(c)
		if rec.Code != http.StatusFound {
			t.Errorf("Expected 302, got %d", rec.Code)
		}
	})

	t.Run("Config CRUD", func(t *testing.T) {
		// Add
		f := url.Values{}
		f.Add("action", "add")
		f.Add("item", "example.com")
		req := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Config(c)

		// Get
		req = httptest.NewRequest(http.MethodGet, "/config", nil)
		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)
		_ = h.Config(c)

		// Remove
		f.Set("action", "remove")
		req = httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)
		_ = h.Config(c)
	})

	t.Run("BulkUpload CSV", func(t *testing.T) {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", "targets.csv")
		_, _ = part.Write([]byte("google.com,8.8.8.8"))
		_ = writer.Close()
		req := httptest.NewRequest(http.MethodPost, "/bulk_upload", body)
		req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.BulkUpload(c)
	})

	t.Run("BulkUpload TXT", func(t *testing.T) {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", "targets.txt")
		_, _ = part.Write([]byte("google.com\n8.8.8.8"))
		_ = writer.Close()
		req := httptest.NewRequest(http.MethodPost, "/bulk_upload", body)
		req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.BulkUpload(c)
	})

	t.Run("Logout", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/logout", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Logout(c)
	})

	t.Run("History", func(t *testing.T) {
		_ = store.AddDNSHistory(context.Background(), "test.com", "data")
		req := httptest.NewRequest(http.MethodGet, "/history/test.com", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("item")
		c.SetParamValues("test.com")
		_ = h.GetHistory(c)
	})

	t.Run("Metrics", func(t *testing.T) {
		h.AppConfig.TrustedIPs = "127.0.0.1"
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		mw := h.Metrics(func(c echo.Context) error { return c.String(200, "ok") })
		_ = mw(c)
	})

	t.Run("Health", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Health(c)
		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200 for healthy redis, got %d", rec.Code)
		}
	})

	t.Run("Health Error", func(t *testing.T) {
		// Create a separate handler with broken storage
		badStore := storage.NewStorage("localhost", "1") // Wrong port
		badH := NewHandler(badStore, cfg)

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = badH.Health(c)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("Expected 503 for broken redis, got %d", rec.Code)
		}
	})

	t.Run("Scanner", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/scanner", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Scanner(c)
	})

	t.Run("Scan", func(t *testing.T) {
		f := url.Values{}
		f.Add("target", "127.0.0.1")
		f.Add("ports", "80,443")
		req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Scan(c)
	})

	t.Run("Scan Empty Target", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/scan", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Scan(c)
	})

	t.Run("Metrics Forbidden", func(t *testing.T) {
		h.AppConfig.TrustedIPs = "192.168.1.1"
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = "1.1.1.1:1234"
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		mw := h.Metrics(func(c echo.Context) error { return nil })
		_ = mw(c)
		if rec.Code != http.StatusForbidden {
			t.Errorf("Expected 403, got %d", rec.Code)
		}
	})

	t.Run("Login Invalid", func(t *testing.T) {
		f := url.Values{}
		f.Add("username", "admin")
		f.Add("password", "wrong")
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Login(c)
		if rec.Code != http.StatusOK { // Re-renders page
			t.Errorf("Expected 200, got %d", rec.Code)
		}
	})

	t.Run("History Error", func(t *testing.T) {
		// Redis error case
		badStore := storage.NewStorage("localhost", "1")
		badH := NewHandler(badStore, cfg)
		req := httptest.NewRequest(http.MethodGet, "/history/test.com", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("item")
		c.SetParamValues("test.com")
		_ = badH.GetHistory(c)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("Expected 500, got %d", rec.Code)
		}
	})

	t.Run("queryItem Cache Hit", func(t *testing.T) {
		ctx := context.Background()
		target := "cache.com"
		res := model.QueryResult{Whois: "cached"}
		cacheKey := "query:cache.com:false:true:false:false:false:false"
		_ = store.SetCache(ctx, cacheKey, res, time.Hour)

		h.queryItem(ctx, target, false, true, false, false, false, false)
	})

	t.Run("exportCSV Full", func(t *testing.T) {
		results := map[string]model.QueryResult{
			"test.com": {
				Whois: "some whois",
				DNS:   map[string]interface{}{"A": []string{"1.2.3.4"}},
				CT:    map[string]interface{}{"sub": "data"},
			},
		}
		rec := httptest.NewRecorder()
		c := e.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), rec)
		_ = h.exportCSV(c, results)
	})

	t.Run("Index POST Full Features", func(t *testing.T) {
		f := url.Values{}
		f.Add("ips_and_domains", "8.8.8.8,google.com")
		f.Add("whois", "true")
		f.Add("dns", "true")
		f.Add("ct", "true")
		f.Add("ssl", "true")
		f.Add("http", "true")
		f.Add("geo", "true")
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Index(c)
	})

	t.Run("queryItem IP CT Branch", func(t *testing.T) {
		ctx := context.Background()
		h.queryItem(ctx, "8.8.8.8", false, false, true, false, false, false)
	})

	t.Run("MacLookup Error", func(t *testing.T) {
		originalURL := service.MacVendorsURL
		service.MacVendorsURL = "http://invalid-url/%s"
		service.OUIPath = "non_existent_file.txt"
		defer func() {
			service.MacVendorsURL = originalURL
			service.OUIPath = "data/oui.txt"
		}()

		f := url.Values{}
		f.Add("mac", "00:11:22:33:44:55")
		req := httptest.NewRequest(http.MethodPost, "/mac_lookup", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.MacLookup(c)
	})

	t.Run("LoginRequired Empty Cookie", func(t *testing.T) {
		mw := h.LoginRequired(func(c echo.Context) error { return nil })
		req := httptest.NewRequest(http.MethodGet, "/config", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: ""})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = mw(c)
		if rec.Code != http.StatusFound {
			t.Errorf("Expected redirect for empty cookie, got %d", rec.Code)
		}
	})

	t.Run("DNSLookup Empty", func(t *testing.T) {
		f := url.Values{}
		f.Add("domain", "non-existent.test")
		f.Add("type", "AAAA")
		req := httptest.NewRequest(http.MethodPost, "/dns_lookup", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.DNSLookup(c)
	})

	t.Run("MacLookup Found", func(t *testing.T) {
		ctx := context.Background()
		_ = store.SetCache(ctx, "mac:00:11:22:33:44:55", "Test Vendor", time.Hour)
		f := url.Values{}
		f.Add("mac", "00:11:22:33:44:55")
		req := httptest.NewRequest(http.MethodPost, "/mac_lookup", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.MacLookup(c)
	})

	t.Run("queryItem CT Cache Hit", func(t *testing.T) {
		ctx := context.Background()
		target := "ct-cache.com"
		_ = store.SetCache(ctx, "ct:"+target, map[string]string{"sub": "cached"}, time.Hour)
		h.queryItem(ctx, target, false, false, true, false, false, false)
	})

	t.Run("queryItem CT Error", func(t *testing.T) {
		// Mock CT error by setting an unreachable URL
		originalURL := service.CRTURL
		service.CRTURL = "http://invalid-url/%s"
		defer func() { service.CRTURL = originalURL }()

		h.queryItem(context.Background(), "error-ct.com", false, false, true, false, false, false)
	})

	t.Run("queryItem Geo Error", func(t *testing.T) {
		h.queryItem(context.Background(), "invalid-ip", false, false, false, false, false, true)
	})

	t.Run("BulkUpload Invalid CSV", func(t *testing.T) {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", "bad.csv")
		// Force CSV reader error by having unquoted quote
		_, _ = part.Write([]byte("a,\"b,c"))
		_ = writer.Close()
		req := httptest.NewRequest(http.MethodPost, "/bulk_upload", body)
		req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.BulkUpload(c)
	})

	t.Run("queryItem Cache Decode Error", func(t *testing.T) {
		ctx := context.Background()
		target := "bad-cache.com"
		cacheKey := "query:bad-cache.com:false:true:false:false:false:false"
		_ = store.SetCache(ctx, cacheKey, "not json", time.Hour)
		h.queryItem(ctx, target, false, true, false, false, false, false)
	})

	t.Run("LoginRequired No Cookie", func(t *testing.T) {
		mw := h.LoginRequired(func(c echo.Context) error { return nil })
		req := httptest.NewRequest(http.MethodGet, "/config", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = mw(c)
		if rec.Code != http.StatusFound {
			t.Errorf("Expected redirect, got %d", rec.Code)
		}
	})

	t.Run("DNSLookup Error", func(t *testing.T) {
		f := url.Values{}
		f.Add("domain", "invalid..domain")
		req := httptest.NewRequest(http.MethodPost, "/dns_lookup", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.DNSLookup(c)
	})

	t.Run("UpdateGeoDB Error", func(t *testing.T) {
		h.AppConfig.MaxMindLicenseKey = ""
		// We need to ensure service.geoLicenseKey is also empty
		// But handler uses service.ManualUpdateGeoDB() which checks it.
		req := httptest.NewRequest(http.MethodPost, "/update-geo", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.UpdateGeoDB(c)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("Expected 500 for missing key, got %d", rec.Code)
		}
	})

	t.Run("LoginRequired Wrong Cookie", func(t *testing.T) {
		mw := h.LoginRequired(func(c echo.Context) error { return nil })
		req := httptest.NewRequest(http.MethodGet, "/config", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "wrong"})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = mw(c)
		if rec.Code != http.StatusFound {
			t.Errorf("Expected redirect for wrong cookie, got %d", rec.Code)
		}
	})

	t.Run("Index POST Export JSON", func(t *testing.T) {
		f := url.Values{}
		f.Add("ips_and_domains", "google.com")
		f.Add("export", "json")
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Index(c)
		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rec.Code)
		}
	})

	t.Run("BulkUpload Empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/bulk_upload", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.BulkUpload(c)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("Expected 400, got %d", rec.Code)
		}
	})

	t.Run("BulkUpload CSV Read Error", func(t *testing.T) {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", "error.csv")
		_, _ = part.Write([]byte("unclosed,\"quote"))
		_ = writer.Close()
		req := httptest.NewRequest(http.MethodPost, "/bulk_upload", body)
		req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.BulkUpload(c)
	})

	t.Run("MacLookup Cache Decode Error", func(t *testing.T) {
		ctx := context.Background()
		_ = store.SetCache(ctx, "mac:FF:FF:FF:FF:FF:FF", 123, time.Hour) // Non-string data
		f := url.Values{}
		f.Add("mac", "FF:FF:FF:FF:FF:FF")
		req := httptest.NewRequest(http.MethodPost, "/mac_lookup", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.MacLookup(c)
	})

	t.Run("UpdateGeoDB Success", func(t *testing.T) {
		// Mock UpdateGeoDB logic
		_ = h.UpdateGeoDB(e.NewContext(httptest.NewRequest(http.MethodPost, "/update-geo", nil), httptest.NewRecorder()))
	})
}
