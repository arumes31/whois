package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"whois/internal/utils"
)

func init() {
	utils.TestInitLogger()
	utils.SetAllowPrivateIPs(true)
}

func TestLookupMacVendor(t *testing.T) {
	oldPath := OUIPath
	OUIPath = t.TempDir() + "/oui.txt"
	defer func() { OUIPath = oldPath }()
	if err := os.WriteFile(OUIPath, []byte("001122     (base 16)    Local Test Vendor\n"), 0600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		mac  string
	}{
		{name: "colon format", mac: "00:11:22:33:44:55"},
		{name: "hyphen format", mac: "00-11-22-33-44-55"},
		{name: "Cisco format", mac: "0011.2233.4455"},
		{name: "EUI-64 format", mac: "00:11:22:33:44:55:66:77"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vendor, err := LookupMacVendor(context.Background(), tt.mac)
			if err != nil {
				t.Fatalf("LookupMacVendor failed: %v", err)
			}
			if vendor != "Local Test Vendor" {
				t.Fatalf("vendor = %q, want Local Test Vendor", vendor)
			}
		})
	}

	vendor, err := LookupMacVendor(context.Background(), "AA:BB:CC:DD:EE:FF")
	if err != nil {
		t.Fatalf("unknown local OUI returned error: %v", err)
	}
	if vendor != "Vendor not found" {
		t.Fatalf("vendor = %q, want Vendor not found", vendor)
	}

	if _, err := LookupMacVendor(context.Background(), "not-a-mac"); err == nil {
		t.Fatal("expected invalid MAC error")
	}
}

func TestLookupMacVendor_MissingOUIDatabase(t *testing.T) {
	oldPath := OUIPath
	OUIPath = t.TempDir() + "/missing-oui.txt"
	defer func() { OUIPath = oldPath }()

	if _, err := LookupMacVendor(context.Background(), "00:11:22:33:44:55"); err == nil {
		t.Fatal("expected missing local OUI database error")
	}
}

func TestMACService(t *testing.T) {
	StopMACService()
	TestMode = true
	// We run these serially because they all touch OUIPath

	t.Run("InitializeMACService", func(t *testing.T) {
		oldPath := OUIPath
		OUIPath = t.TempDir() + "/oui.txt"
		oldURL := OUIURL
		oldClient := MacHTTPClient
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("initial oui data"))
		}))
		OUIURL = server.URL
		MacHTTPClient = server.Client()
		defer func() {
			server.Close()
			MacHTTPClient = oldClient
			OUIURL = oldURL
			OUIPath = oldPath
		}()
		InitializeMACService()
		if _, err := os.Stat(OUIPath); err != nil {
			t.Fatalf("InitializeMACService did not download OUI data: %v", err)
		}
	})

	t.Run("InitializeMACService_Background", func(t *testing.T) {
		StopMACService()
		oldPath := OUIPath
		OUIPath = t.TempDir() + "/oui.txt"
		_ = os.WriteFile(OUIPath, []byte("old"), 0644)
		// Set mod time to > 72h ago
		oldTime := time.Now().Add(-100 * time.Hour)
		_ = os.Chtimes(OUIPath, oldTime, oldTime)

		oldInterval := UpdateInterval
		UpdateInterval = 10 * time.Millisecond
		oldURL := OUIURL
		updated := make(chan struct{}, 1)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case updated <- struct{}{}:
			default:
			}
			_, _ = w.Write([]byte("new"))
		}))
		OUIURL = ts.URL
		TestMode = false

		defer func() {
			StopMACService()
			UpdateInterval = oldInterval
			OUIURL = oldURL
			TestMode = true
			ts.Close()
			OUIPath = oldPath
		}()

		InitializeMACService()
		select {
		case <-updated:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for OUI background update")
		}
	})

	t.Run("DownloadOUI", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("fake oui content"))
		}))
		defer ts.Close()

		oldURL := OUIURL
		OUIURL = ts.URL
		oldPath := OUIPath
		OUIPath = "test_download_oui_unique.txt"
		defer func() {
			OUIURL = oldURL
			OUIPath = oldPath
			_ = os.Remove("test_download_oui_unique.txt")
		}()

		err := DownloadOUI()
		if err != nil {
			t.Fatalf("DownloadOUI failed: %v", err)
		}
	})

	t.Run("DownloadOUI_Error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()

		oldURL := OUIURL
		OUIURL = ts.URL
		defer func() { OUIURL = oldURL }()

		err := DownloadOUI()
		if err == nil {
			t.Error("Expected error for 500 status")
		}
	})

	t.Run("DownloadOUI_RequestError", func(t *testing.T) {
		oldTransport := MacHTTPClient.Transport
		defer func() { MacHTTPClient.Transport = oldTransport }()

		MacHTTPClient.Transport = &mockErrorTransport{}

		err := DownloadOUI()
		if err == nil {
			t.Fatalf("Expected error for network failure")
		}
		if !strings.Contains(err.Error(), "mock error") {
			t.Errorf("Expected error message to contain 'mock error', got: %v", err)
		}
	})

	t.Run("LocalOUILookup_Missing", func(t *testing.T) {
		oldPath := OUIPath
		OUIPath = "totally_missing_oui_file_unique_v2.txt"
		_ = os.Remove(OUIPath)
		defer func() { OUIPath = oldPath }()

		_, err := localOUILookup("00:11:22")
		if err == nil {
			t.Error("Expected error for missing file")
		}
	})

	t.Run("LookupMacVendor_Invalid_Context", func(t *testing.T) {
		oldOUI := OUIPath
		OUIPath = "non_existent_file_v4.txt"
		defer func() { OUIPath = oldOUI }()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := LookupMacVendor(ctx, "DD:11:22:33:44:55")
		if err == nil {
			t.Error("Expected error for cancelled context")
		}
	})

	t.Run("LocalOUILookup_Success", func(t *testing.T) {
		oldPath := OUIPath
		OUIPath = "test_success_oui_unique.txt"
		defer func() {
			OUIPath = oldPath
			_ = os.Remove("test_success_oui_unique.txt")
		}()

		content := "001122     (base 16)    Local Test Vendor\n"
		_ = os.WriteFile(OUIPath, []byte(content), 0644)

		vendor, err := localOUILookup("00:11:22:33:44:55")
		if err != nil {
			t.Fatalf("localOUILookup failed: %v", err)
		}
		if vendor != "Local Test Vendor" {
			t.Errorf("Expected Local Test Vendor, got %s", vendor)
		}

		vendor, _ = localOUILookup("FFFFFF")
		if vendor != "" {
			t.Errorf("Expected empty vendor for unknown prefix, got %s", vendor)
		}
	})

	t.Run("LocalOUILookup_ScannerError", func(t *testing.T) {
		oldPath := OUIPath
		OUIPath = t.TempDir() + "/oversized-oui.txt"
		defer func() { OUIPath = oldPath }()
		if err := os.WriteFile(OUIPath, []byte(strings.Repeat("A", 70*1024)), 0600); err != nil {
			t.Fatal(err)
		}

		if _, err := localOUILookup("00:11:22:33:44:55"); err == nil || !strings.Contains(err.Error(), "scan OUI database") {
			t.Fatalf("expected scanner error, got %v", err)
		}
	})
}

func TestMACUpdater_StopCancelsInFlightUpdate(t *testing.T) {
	StopMACService()
	started := make(chan struct{})
	finished := make(chan struct{})

	startMACUpdater(time.Millisecond, func(ctx context.Context) {
		close(started)
		<-ctx.Done()
		close(finished)
	})
	t.Cleanup(StopMACService)

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for OUI updater to start")
	}

	StopMACService()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("OUI updater did not finish after cancellation")
	}
}

func TestLocalOUILookup(t *testing.T) {
	// Wrapper for legacy if any, though subtests cover it.
}

type mockErrorTransport struct{}

func (m *mockErrorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("mock error")
}
