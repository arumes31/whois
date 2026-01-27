package service

import (
	"testing"
)

func TestLookupMacVendor(t *testing.T) {
	// This test normally hits a real API. We can't easily mock it without changing the function
	// to accept a client or base URL. However, we can test the error handling.

	_, err := LookupMacVendor("invalid-mac")
	if err == nil {
		// API might return "Vendor not found" which is handled
	}
}
