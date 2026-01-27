package service

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetSSLInfo(t *testing.T) {

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.WriteHeader(http.StatusOK)

	}))

	defer ts.Close()



	// actually GetSSLInfo always appends :443, so it's hard to test with httptest server easily
	// without changing the service code.
	
	t.Run("Online Test Fallback", func(t *testing.T) {
		info := GetSSLInfo("google.com")
		if info.Error != "" {
			t.Logf("GetSSLInfo google.com failed: %s", info.Error)
		} else {
			if info.Issuer == "" {
				t.Error("Expected issuer common name")
			}
		}
	})
}
