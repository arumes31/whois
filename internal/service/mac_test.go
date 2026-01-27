package service

import (
	"testing"
)

func TestLookupMacVendor(t *testing.T) {
	// This test normally hits a real API. We can't easily mock it without changing the function
	// to accept a client or base URL. However, we can test the error handling.

	_, _ = LookupMacVendor("invalid-mac")
	// Just ensuring it doesn't panic for now
}
