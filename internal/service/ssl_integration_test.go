//go:build integration

package service

import (
	"context"
	"testing"
	"time"
)

func TestGetSSLInfo_Online(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	info := GetSSLInfo(ctx, "google.com")
	if info.Error != "" {
		t.Fatalf("online TLS inspection failed: %s", info.Error)
	}
	if info.Issuer == "" || !info.Verified || len(info.Chain) == 0 {
		t.Fatalf("online certificate was not fully verified: %#v", info)
	}
}
