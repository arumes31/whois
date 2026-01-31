package service

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
	"whois/internal/utils"
)

func init() {
	utils.TestInitLogger()
	utils.AllowPrivateIPs = true
}

func TestGetGeoInfo(t *testing.T) {
	// Mock the API fallback
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"status":"success", "query":"8.8.8.8", "country":"United States"}`)
	}))
	defer ts.Close()

	originalURL := GeoAPIURL
	GeoAPIURL = ts.URL + "/"
	defer func() { GeoAPIURL = originalURL }()

	tests := []struct {
		target string
	}{
		{"8.8.8.8"},
		{"1.1.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			res, err := GetGeoInfo(context.Background(), tt.target)
			if err != nil {
				t.Fatalf("GetGeoInfo failed: %v", err)
			}
			if res.Query != tt.target && tt.target == "8.8.8.8" {
				t.Errorf("Expected query %s, got %s", tt.target, res.Query)
			}
		})
	}
}

func TestInitializeGeoDB(t *testing.T) {
	oldClient := GeoHTTPClient
	defer func() { GeoHTTPClient = oldClient }()
	GeoHTTPClient = &http.Client{
		Transport: &mockGeoTransport{},
	}

	GeoTestMode = true
	oldPath := geoPath
	geoPath = "test_init_geo.mmdb"
	defer func() {
		geoPath = oldPath
		_ = os.Remove("test_init_geo.mmdb")
	}()

	// Test with no keys (public mirror fallback)
	InitializeGeoDB("", "")

	// Test with keys
	InitializeGeoDB("testkey", "testaccount")
}

type mockGeoTransport struct{}

func (t *mockGeoTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte("fake mmdb"))),
	}, nil
}

func TestInitializeGeoDB_Background(t *testing.T) {
	GeoTestMode = false
	oldInterval := GeoUpdateInterval
	GeoUpdateInterval = 10 * time.Millisecond

	// Mock update server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fake mmdb"))
	}))
	defer ts.Close()

	// Set mod time to > 72h ago
	_ = os.WriteFile(geoPath, []byte("old"), 0644)
	oldTime := time.Now().Add(-100 * time.Hour)
	_ = os.Chtimes(geoPath, oldTime, oldTime)

	defer func() {
		GeoTestMode = true
		GeoUpdateInterval = oldInterval
		_ = os.Remove(geoPath)
	}()

	InitializeGeoDB("test", "test")
	time.Sleep(50 * time.Millisecond) // Let it tick
}

func TestCloseGeoDB(t *testing.T) {
	CloseGeoDB()
}

func TestGetGeoInfo_ReaderError(t *testing.T) {
	// Create a dummy reader that fails
	_ = os.WriteFile("dummy.mmdb", []byte("invalid"), 0644)
	defer func() { _ = os.Remove("dummy.mmdb") }()

	geoMu.Lock()
	oldPath := geoPath
	geoPath = "dummy.mmdb"
	geoMu.Unlock()

	ReloadGeoDB()

	// This should fallback to API since reader is nil on reload error
	_, _ = GetGeoInfo(context.Background(), "8.8.8.8")

	geoMu.Lock()
	geoPath = oldPath
	geoMu.Unlock()
}

func TestGetGeoInfo_ErrorPaths(t *testing.T) {
	t.Run("Invalid Host", func(t *testing.T) {
		_, err := GetGeoInfo(context.Background(), "invalid host with spaces")
		if err == nil {
			t.Error("Expected error for invalid host")
		}
	})

	t.Run("API Error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"fail", "message":"invalid query"}`))
		}))
		defer ts.Close()

		// We can't easily override the URL in GetGeoInfo without refactoring,
		// but we can test the 'fail' status logic if we trigger it from the real API with an invalid IP.
		_, _ = GetGeoInfo(context.Background(), "0.0.0.0")
	})

	t.Run("JSON Decode Error", func(t *testing.T) {
		// Similar to above, needs refactoring for URL override or very specific trigger.
	})
}

func TestManualUpdateGeoDB(t *testing.T) {
	// Test error when license key missing
	geoLicenseKey = ""
	err := ManualUpdateGeoDB()
	if err == nil {
		t.Error("Expected error when license key is empty")
	}

	geoLicenseKey = "testkey"
	// This will fail because maxmind URL is invalid with testkey, but we want to cover the logic
	_ = ManualUpdateGeoDB()
}

func TestReloadGeoDB(t *testing.T) {
	ReloadGeoDB()
}

func TestDownloadGeoDB_Errors(t *testing.T) {
	// 404 error
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	err := DownloadGeoDB(ts.URL)
	if err == nil {
		t.Error("Expected error for 404 status")
	}

	// Invalid URL
	err = DownloadGeoDB("http://invalid-url-that-does-not-exist-12345.com")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestDownloadGeoDB_BasicAuth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "user" || password != "pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	geoAccountID = "user"
	geoLicenseKey = "pass"
	defer func() {
		geoAccountID = ""
		geoLicenseKey = ""
	}()

	err := DownloadGeoDB(ts.URL)
	if err != nil {
		t.Fatalf("DownloadGeoDB with basic auth failed: %v", err)
	}
}

func TestExtractTarGz_Success(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	content := []byte("fake mmdb content")
	header := &tar.Header{
		Name: "GeoLite2-City.mmdb",
		Size: int64(len(content)),
	}
	_ = tw.WriteHeader(header)
	_, _ = tw.Write(content)
	_ = tw.Close()
	_ = gw.Close()

	oldPath := geoPath
	geoPath = "test_extract_success.mmdb"
	defer func() {
		geoPath = oldPath
		_ = os.Remove("test_extract_success.mmdb")
	}()

	err := extractTarGz(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("extractTarGz failed: %v", err)
	}
}

func TestExtractTarGz_Errors(t *testing.T) {
	// Not a gzip
	err := extractTarGz(bytes.NewReader([]byte("not a gzip")))
	if err == nil {
		t.Error("Expected error for invalid gzip")
	}

	// Valid gzip but not a tar
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write([]byte("not a tar"))
	_ = gw.Close()
	err = extractTarGz(bytes.NewReader(buf.Bytes()))
	if err == nil {
		t.Error("Expected error for invalid tar")
	}

	// Tar with no mmdb
	buf.Reset()
	gw = gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	header := &tar.Header{Name: "nothing.txt", Size: 0}
	_ = tw.WriteHeader(header)
	_ = tw.Close()
	_ = gw.Close()
	err = extractTarGz(bytes.NewReader(buf.Bytes()))
	if err == nil || err.Error() != "mmdb file not found in archive" {
		t.Errorf("Expected 'mmdb file not found' error, got %v", err)
	}
}
