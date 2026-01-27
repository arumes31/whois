package service

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetHTTPInfo(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	// ts.URL will be like http://127.0.0.1:12345
	host := strings.TrimPrefix(ts.URL, "http://")
	
	info := GetHTTPInfo(host)
	if info.Error != "" {
		t.Fatalf("GetHTTPInfo failed: %s", info.Error)
	}

	if info.Status != "200 OK" {
		t.Errorf("Expected 200 OK, got %s", info.Status)
	}

	if info.Security["X-Frame-Options"] != "DENY" {
		t.Errorf("Expected X-Frame-Options DENY, got %s", info.Security["X-Frame-Options"])
	}
}
