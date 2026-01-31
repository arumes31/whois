package handler

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
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

type mockGeoTransport struct{}

func (t *mockGeoTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	content := []byte("fake mmdb")
	header := &tar.Header{Name: "GeoLite2-City.mmdb", Size: int64(len(content))}
	_ = tw.WriteHeader(header)
	_, _ = tw.Write(content)
	_ = tw.Close()
	_ = gw.Close()

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(buf.Bytes())),
	}, nil
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

	t.Run("Scan Empty Target", func(t *testing.T) {
		f := url.Values{}
		f.Add("target", "")
		f.Add("ports", "80")
		req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		req.RemoteAddr = "1.2.3.4:1234"
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Scan(c)
	})

	t.Run("DNSLookup HTMX UX No Records", func(t *testing.T) {
		f := url.Values{}
		f.Add("domain", "nonexistent.test")
		f.Add("type", "AAAA")
		req := httptest.NewRequest(http.MethodPost, "/dns_lookup", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		_ = h.DNSLookup(e.NewContext(req, rec))
		if !strings.Contains(rec.Body.String(), "No AAAA records found") {
			t.Error("Expected warning for no records")
		}
	})

	t.Run("UpdateGeoDB Success UX", func(t *testing.T) {
		oldClient := service.GeoHTTPClient
		defer func() { service.GeoHTTPClient = oldClient }()
		service.GeoHTTPClient = &http.Client{
			Transport: &mockGeoTransport{},
		}

		service.InitializeGeoDB("test", "test")

		req := httptest.NewRequest(http.MethodPost, "/config/update-geo", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.UpdateGeoDB(c); err != nil {
			t.Fatalf("UpdateGeoDB handler returned error: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d. Body: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("UpdateGeoDB Error Path", func(t *testing.T) {
		// Set empty key to trigger ManualUpdateGeoDB error
		service.InitializeGeoDB("", "")
		req := httptest.NewRequest(http.MethodPost, "/update-geo", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.UpdateGeoDB(c)
	})

	t.Run("Robots", func(t *testing.T) {
		h.AppConfig.SEOEnabled = false
		req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.Robots(c)
		if !strings.Contains(rec.Body.String(), "Disallow: /") {
			t.Error("Expected Disallow: / when SEO disabled")
		}

		h.AppConfig.SEOEnabled = true
		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)
		_ = h.Robots(c)
		if !strings.Contains(rec.Body.String(), "Allow: /") {
			t.Error("Expected Allow: / when SEO enabled")
		}
	})

	t.Run("BulkUpload Errors", func(t *testing.T) {
		// Invalid file type
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", "test.exe")
		_, _ = part.Write([]byte("google.com"))
		_ = writer.Close()
		req := httptest.NewRequest(http.MethodPost, "/bulk_upload", body)
		req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
		rec := httptest.NewRecorder()
		_ = h.BulkUpload(e.NewContext(req, rec))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 for .exe file, got %d", rec.Code)
		}
	})

	t.Run("BulkUpload CSV Invalid", func(t *testing.T) {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", "targets.csv")
		_, _ = part.Write([]byte("unclosed \"quote"))
		_ = writer.Close()
		req := httptest.NewRequest(http.MethodPost, "/bulk_upload", body)
		req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
		rec := httptest.NewRecorder()
		_ = h.BulkUpload(e.NewContext(req, rec))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 for invalid CSV, got %d", rec.Code)
		}
	})

	t.Run("BulkUpload TXT", func(t *testing.T) {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, _ := writer.CreateFormFile("file", "targets.txt")
		_, _ = part.Write([]byte("google.com,8.8.8.8\nexample.com"))
		_ = writer.Close()
		req := httptest.NewRequest(http.MethodPost, "/bulk_upload", body)
		req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
		rec := httptest.NewRecorder()
		_ = h.BulkUpload(e.NewContext(req, rec))
		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200 for TXT, got %d", rec.Code)
		}
	})

	t.Run("MacLookup Cache Hit", func(t *testing.T) {
		ctx := context.Background()
		mac := "00:AA:BB:CC:DD:EE"
		_ = store.SetCache(ctx, "mac:"+mac, "Cached Vendor", time.Hour)
		req := httptest.NewRequest(http.MethodPost, "/mac_lookup?mac="+mac, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.MacLookup(c)
		if !strings.Contains(rec.Body.String(), "Cached Vendor") {
			t.Error("Expected cached vendor in response")
		}
	})

	t.Run("Index POST JSON Export", func(t *testing.T) {
		f := url.Values{}
		f.Add("ips_and_domains", "google.com")
		f.Add("export", "json")
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		_ = h.Index(e.NewContext(req, rec))
		if !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
			t.Errorf("Expected application/json, got %s", rec.Header().Get("Content-Type"))
		}
	})

	t.Run("queryItem CT Cache Hit", func(t *testing.T) {
		ctx := context.Background()
		ctData := map[string]interface{}{"sub.test.com": map[string]interface{}{}}
		_ = store.SetCache(ctx, "ct:test.com", ctData, time.Hour)
		res := h.queryItem(ctx, "test.com", false, false, true, false, false, false)
		if res.CT == nil {
			t.Error("Expected CT results from cache")
		}
	})

	t.Run("Index POST Export CSV Full", func(t *testing.T) {
		results := map[string]model.QueryResult{
			"google.com": {
				Whois: service.WhoisInfo{Raw: "raw info", Registrar: "Google"},
				DNS:   map[string]interface{}{"A": []string{"1.2.3.4"}},
				CT:    map[string]interface{}{"sub.google.com": map[string]interface{}{}},
			},
			"only-string": {
				Whois: "raw string",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/?export=csv", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.exportCSV(c, results); err != nil {
			t.Fatal(err)
		}
		if rec.Header().Get("Content-Type") != "text/csv" {
			t.Errorf("Expected text/csv, got %s", rec.Header().Get("Content-Type"))
		}
	})

	t.Run("queryItem All Enabled", func(t *testing.T) {
		ctx := context.Background()
		h.queryItem(ctx, "google.com", true, true, true, true, true, true)
		h.queryItem(ctx, "8.8.8.8", true, true, true, true, true, true)
	})

	t.Run("BulkUpload Empty/Invalid", func(t *testing.T) {
		// No file
		req := httptest.NewRequest(http.MethodPost, "/bulk_upload", nil)
		rec := httptest.NewRecorder()
		_ = h.BulkUpload(e.NewContext(req, rec))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 for no file, got %d", rec.Code)
		}
	})
}
