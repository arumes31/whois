package service

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"whois/internal/utils"
)

func init() {
	utils.TestInitLogger()
}

func TestGetGeoInfo(t *testing.T) {
	t.Parallel()
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
				t.Logf("GetGeoInfo failed (expected if offline): %v", err)
				return
			}
			if res.Query != tt.target {
				t.Errorf("Expected query %s, got %s", tt.target, res.Query)
			}
		})
	}
}

func TestInitializeGeoDB(t *testing.T) {
	oldPath := geoPath
	geoPath = "test_init_geo.mmdb"
	defer func() {
		geoPath = oldPath
		_ = os.Remove("test_init_geo.mmdb")
	}()

	// Test with no keys (public mirror fallback)
	// We use a small file to avoid long downloads if it actually triggers
	InitializeGeoDB("", "")
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
