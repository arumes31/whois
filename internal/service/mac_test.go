package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"whois/internal/utils"
)

func init() {
	utils.TestInitLogger()
}

func TestLookupMacVendor(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "AA1122") || strings.Contains(r.URL.Path, "AA:11:22") {
			_, _ = fmt.Fprint(w, "API Test Vendor")
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	originalURL := MacVendorsURL
	MacVendorsURL = server.URL + "/%s"
	defer func() { MacVendorsURL = originalURL }()

	// Use AA:11:22 which is NOT in the fake local file created by TestLocalOUILookup_Success
	vendor, err := LookupMacVendor(context.Background(), "AA:11:22:33:44:55")
	if err != nil {
		t.Fatalf("LookupMacVendor failed: %v", err)
	}
	if vendor != "API Test Vendor" {
		t.Errorf("Expected API Test Vendor, got %s", vendor)
	}

	vendor, _ = LookupMacVendor(context.Background(), "00:00:00:00:00:00")
	if vendor != "Vendor not found" {
		t.Errorf("Expected Vendor not found, got %s", vendor)
	}
}

func TestMACService(t *testing.T) {
	TestMode = true
	// We run these serially because they all touch OUIPath

	t.Run("InitializeMACService", func(t *testing.T) {
		oldPath := OUIPath
		OUIPath = "test_init_oui_unique.txt"
		defer func() {
			OUIPath = oldPath
			_ = os.Remove("test_init_oui_unique.txt")
		}()
		InitializeMACService()
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

	t.Run("LookupMacVendor_API", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cleanPath := strings.ReplaceAll(r.URL.Path, ":", "")
			if strings.Contains(cleanPath, "BB1122") {
				_, _ = fmt.Fprint(w, "API Test BB")
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		oldURL := MacVendorsURL
		MacVendorsURL = server.URL + "/%s"
		oldOUI := OUIPath
		OUIPath = "force_api_bb_unique.txt"
		_ = os.Remove(OUIPath)

		defer func() {
			MacVendorsURL = oldURL
			OUIPath = oldOUI
		}()

		// Use BB:11:22
		vendor, err := LookupMacVendor(context.Background(), "BB:11:22:33:44:55")
		if err != nil {
			t.Fatalf("LookupMacVendor failed: %v", err)
		}
		if vendor != "API Test BB" {
			t.Errorf("Expected API Test BB, got %s", vendor)
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

	t.Run("LookupMacVendor_API_Fail", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		oldURL := MacVendorsURL
		MacVendorsURL = server.URL + "/%s"
		oldOUI := OUIPath
		OUIPath = "non_existent_file_v3.txt"
		defer func() {
			MacVendorsURL = oldURL
			OUIPath = oldOUI
		}()

		_, err := LookupMacVendor(context.Background(), "CC:11:22:33:44:55")
		if err == nil {
			t.Error("Expected error for 500 status from API")
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
}

func TestLocalOUILookup(t *testing.T) {
	// Wrapper for legacy if any, though subtests cover it.
}
