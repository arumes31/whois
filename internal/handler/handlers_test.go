package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
		_ = os.Setenv("CONFIG_USER", "admin")
		_ = os.Setenv("CONFIG_PASS", "pass")
		_ = os.Setenv("SECRET_KEY", "testkey")
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

	t.Run("Logout", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/logout", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Logout(c)
	})

	t.Run("History", func(t *testing.T) {
		ctx := context.Background()
		target := "test-history.com"
		_ = store.AddDNSHistory(ctx, target, map[string]string{"A": "1.2.3.4"})
		time.Sleep(10 * time.Millisecond)
		_ = store.AddDNSHistory(ctx, target, map[string]string{"A": "1.2.3.5"})

		req := httptest.NewRequest(http.MethodGet, "/history/"+target, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("item")
		c.SetParamValues(target)

		if err := h.GetHistory(c); err != nil {
			t.Fatalf("GetHistory handler failed: %v", err)
		}

		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rec.Code)
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to unmarshal response: %v", err)
		}

		entries := resp["entries"].([]interface{})
		if len(entries) != 2 {
			t.Errorf("Expected 2 history entries, got %d", len(entries))
		}

		diffs := resp["diffs"].([]interface{})
		if len(diffs) != 1 {
			t.Errorf("Expected 1 diff, got %d", len(diffs))
		}
	})

	t.Run("History Error", func(t *testing.T) {
		badStore := storage.NewStorage("localhost", "1")
		badH := NewHandler(badStore, cfg)
		req := httptest.NewRequest(http.MethodGet, "/history/test.com", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("item")
		c.SetParamValues("test.com")
		_ = badH.GetHistory(c)
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
	})

	t.Run("Health Error", func(t *testing.T) {
		badStore := storage.NewStorage("localhost", "1")
		badH := NewHandler(badStore, cfg)
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = badH.Health(c)
	})

	t.Run("UpdateGeoDB Success", func(t *testing.T) {
		// Mock UpdateGeoDB logic via Service setting
		service.InitializeGeoDB("test", "test")
		req := httptest.NewRequest(http.MethodPost, "/update-geo", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.UpdateGeoDB(c)
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
		f.Add("ports", "80")
		req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
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
	})

	t.Run("Metrics Throttle", func(t *testing.T) {
		h.AppConfig.TrustedIPs = "127.0.0.1"
		mw := h.Metrics(func(c echo.Context) error { return c.String(200, "ok") })

		// Send 6 requests, the 6th should be delayed
		for i := 1; i <= 6; i++ {
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			req.RemoteAddr = "127.0.0.1:1234"
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			start := time.Now()
			_ = mw(c)
			elapsed := time.Since(start)

			if i > 5 {
				// Should have at least 500ms delay
				if elapsed < 400*time.Millisecond {
					t.Errorf("Expected delay for request %d, but took only %v", i, elapsed)
				}
			}
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
	})

	t.Run("History Error", func(t *testing.T) {
		badStore := storage.NewStorage("localhost", "1")
		badH := NewHandler(badStore, cfg)
		req := httptest.NewRequest(http.MethodGet, "/history/test.com", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("item")
		c.SetParamValues("test.com")
		_ = badH.GetHistory(c)
	})

	t.Run("queryItem Cache Hit", func(t *testing.T) {
		ctx := context.Background()
		res := model.QueryResult{Whois: "cached"}
		cacheKey := "query:cache.com:false:true:false:false:false:false"
		_ = store.SetCache(ctx, cacheKey, res, time.Hour)
		h.queryItem(ctx, "cache.com", false, true, false, false, false, false)
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

	t.Run("LoginRequired Logic Exhaustive", func(t *testing.T) {
		mw := h.LoginRequired(func(c echo.Context) error { return c.String(200, "ok") })
		_ = os.Setenv("SECRET_KEY", "test")
		expected := fmt.Sprintf("%x", "test")

		tests := []struct {
			name   string
			cookie *http.Cookie
			code   int
		}{
			{"No Cookie", nil, 302},
			{"Empty Cookie", &http.Cookie{Name: "session_id", Value: ""}, 302},
			{"Wrong Cookie", &http.Cookie{Name: "session_id", Value: "wrong"}, 302},
			{"Valid Cookie", &http.Cookie{Name: "session_id", Value: expected}, 200},
		}

		for _, tt := range tests {
			req := httptest.NewRequest(http.MethodGet, "/config", nil)
			if tt.cookie != nil {
				req.AddCookie(tt.cookie)
			}
			rec := httptest.NewRecorder()
			_ = mw(e.NewContext(req, rec))
			if rec.Code != tt.code {
				t.Errorf("%s: expected %d, got %d", tt.name, tt.code, rec.Code)
			}
		}
	})

	t.Run("queryItem CT Fail", func(t *testing.T) {
		oldURL := service.CRTURL
		service.CRTURL = "http://invalid-url"
		defer func() { service.CRTURL = oldURL }()
		h.queryItem(context.Background(), "fail-ct.com", false, false, true, false, false, false)
	})

	t.Run("UpdateGeoDB Error Path", func(t *testing.T) {
		// Set empty key to trigger ManualUpdateGeoDB error
		service.InitializeGeoDB("", "")
		req := httptest.NewRequest(http.MethodPost, "/update-geo", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.UpdateGeoDB(c)
	})
}
