package service

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
	"whois/internal/utils"

	"github.com/oschwald/geoip2-golang"
)

func init() {
	utils.TestInitLogger()
	utils.SetAllowPrivateIPs(true)
}

func TestGetGeoInfo(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		resolvedIP string
	}{
		{name: "IP address bypasses resolver", target: "8.8.8.8", resolvedIP: "8.8.8.8"},
		{name: "hostname resolves before lookup", target: "example.test", resolvedIP: "203.0.113.10"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolverCalls := 0
			resolve := func(ctx context.Context, host string) ([]net.IPAddr, error) {
				resolverCalls++
				if host != tt.target {
					t.Fatalf("resolver target = %q, want %q", host, tt.target)
				}
				return []net.IPAddr{{IP: net.ParseIP(tt.resolvedIP)}}, nil
			}
			lookup := func(ip net.IP) (*geoip2.City, error) {
				if got := ip.String(); got != tt.resolvedIP {
					t.Fatalf("GeoIP lookup address = %q, want %q", got, tt.resolvedIP)
				}
				record := &geoip2.City{}
				record.Country.Names = map[string]string{"en": "Example Country"}
				record.Country.IsoCode = "AT"
				record.City.Names = map[string]string{"en": "Vienna"}
				record.Postal.Code = "1010"
				record.Location.TimeZone = "Europe/Vienna"
				return record, nil
			}

			res, err := getGeoInfo(context.Background(), tt.target, resolve, lookup)
			if err != nil {
				t.Fatalf("GetGeoInfo failed: %v", err)
			}
			if res.Query != tt.target || res.CountryCode != "AT" || res.City != "Vienna" || res.Zip != "1010" {
				t.Fatalf("unexpected GeoIP result: %+v", res)
			}
			if tt.target == tt.resolvedIP && resolverCalls != 0 {
				t.Fatalf("literal IP unexpectedly used resolver %d times", resolverCalls)
			}
			if tt.target != tt.resolvedIP && resolverCalls != 1 {
				t.Fatalf("hostname resolver calls = %d, want 1", resolverCalls)
			}
		})
	}
}

func TestInitializeGeoDB(t *testing.T) {
	StopGeoDBUpdater()
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

type mockGeoTransport struct {
	called chan<- struct{}
}

func (t *mockGeoTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.called != nil {
		select {
		case t.called <- struct{}{}:
		default:
		}
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte("fake mmdb"))),
	}, nil
}

func TestInitializeGeoDB_Background(t *testing.T) {
	StopGeoDBUpdater()
	oldPath := geoPath
	geoPath = t.TempDir() + "/GeoLite2-City.mmdb"
	GeoTestMode = false
	oldInterval := GeoUpdateInterval
	GeoUpdateInterval = 10 * time.Millisecond
	oldClient := GeoHTTPClient
	updated := make(chan struct{}, 1)
	GeoHTTPClient = &http.Client{Transport: &mockGeoTransport{called: updated}}

	// Set mod time to > 72h ago
	_ = os.WriteFile(geoPath, []byte("old"), 0644)
	oldTime := time.Now().Add(-100 * time.Hour)
	_ = os.Chtimes(geoPath, oldTime, oldTime)

	defer func() {
		StopGeoDBUpdater()
		GeoTestMode = true
		GeoUpdateInterval = oldInterval
		GeoHTTPClient = oldClient
		geoPath = oldPath
	}()

	InitializeGeoDB("test", "test")
	select {
	case <-updated:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for GeoIP background update")
	}
}

func TestGeoDBUpdater_StopCancelsInFlightUpdate(t *testing.T) {
	StopGeoDBUpdater()
	started := make(chan struct{})
	finished := make(chan struct{})

	startGeoDBUpdater(time.Millisecond, func(ctx context.Context) {
		close(started)
		<-ctx.Done()
		close(finished)
	})
	t.Cleanup(StopGeoDBUpdater)

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for GeoIP updater to start")
	}

	StopGeoDBUpdater()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("GeoIP updater did not finish after cancellation")
	}
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

	if _, err := GetGeoInfo(context.Background(), "8.8.8.8"); !errors.Is(err, errGeoDBUnavailable) {
		t.Fatalf("expected local database unavailable error, got %v", err)
	}

	geoMu.Lock()
	geoPath = oldPath
	geoMu.Unlock()
}

func TestGetGeoInfo_ErrorPaths(t *testing.T) {
	resolverErr := errors.New("resolver failed")
	_, err := getGeoInfo(context.Background(), "invalid host", func(context.Context, string) ([]net.IPAddr, error) {
		return nil, resolverErr
	}, func(net.IP) (*geoip2.City, error) {
		t.Fatal("lookup called after resolver error")
		return nil, nil
	})
	if !errors.Is(err, resolverErr) {
		t.Fatalf("expected resolver error, got %v", err)
	}

	_, err = getGeoInfo(context.Background(), "empty.test", func(context.Context, string) ([]net.IPAddr, error) {
		return nil, nil
	}, func(net.IP) (*geoip2.City, error) {
		t.Fatal("lookup called without resolved addresses")
		return nil, nil
	})
	if err == nil {
		t.Fatal("expected error for hostname without addresses")
	}

	_, err = getGeoInfo(context.Background(), "192.0.2.1", nil, func(net.IP) (*geoip2.City, error) {
		return nil, errGeoRecordNotFound
	})
	if !errors.Is(err, errGeoRecordNotFound) {
		t.Fatalf("expected missing record error, got %v", err)
	}
}

func TestManualUpdateGeoDB(t *testing.T) {
	StopGeoDBUpdater()
	oldClient := GeoHTTPClient
	oldPath := geoPath
	GeoHTTPClient = &http.Client{Transport: &mockGeoTransport{}}
	geoPath = t.TempDir() + "/GeoLite2-City.mmdb"
	defer func() {
		GeoHTTPClient = oldClient
		geoPath = oldPath
	}()

	// Test error when license key missing
	geoLicenseKey = ""
	err := ManualUpdateGeoDB()
	if err == nil {
		t.Error("Expected error when license key is empty")
	}

	geoLicenseKey = "testkey"
	// The injected transport keeps this path deterministic and offline.
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
	err = DownloadGeoDB("://invalid-url")
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
