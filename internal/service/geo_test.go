package service

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

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
			res, err := GetGeoInfo(tt.target)
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

func TestDownloadGeoDB(t *testing.T) {
	// Create a fake tar.gz with an .mmdb file
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	content := []byte("fake mmdb content")
	header := &tar.Header{
		Name: "test.mmdb",
		Size: int64(len(content)),
	}
	_ = tw.WriteHeader(header)
	_, _ = tw.Write(content)
	_ = tw.Close()
	_ = gw.Close()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	}))
	defer ts.Close()

	// Temporary path for test
	oldPath := geoPath
	geoPath = "test_geo.mmdb"
	defer func() {
		geoPath = oldPath
		_ = os.Remove("test_geo.mmdb")
	}()

	err := DownloadGeoDB(ts.URL + "/test.tar.gz")
	if err != nil {
		t.Fatalf("DownloadGeoDB failed: %v", err)
	}

	if _, err := os.Stat(geoPath); os.IsNotExist(err) {
		t.Error("File was not downloaded/extracted")
	}
}
