package utils

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
)

// These cases cover every allocation in the IANA IPv4 and IPv6 special-purpose
// registries as of 2026-10-09, plus neighboring prefixes and mapped addresses.
// Private, loopback, and link-local allocations retain their existing flags;
// other explicitly non-global allocations use the existing reserved category.
func TestIANASpecialPurposeClassification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		address string
		scope   string
	}{
		{"0.0.0.0", "reserved"},
		{"0.1.2.3", "reserved"},
		{"0.255.255.255", "reserved"},
		{"1.0.0.0", "global"},
		{"10.0.0.1", "private"},
		{"100.64.0.1", "carrier-grade NAT"},
		{"127.0.0.1", "loopback"},
		{"169.254.1.1", "link-local"},
		{"172.16.0.1", "private"},
		{"192.0.0.1", "reserved"},
		{"192.0.0.8", "reserved"},
		{"192.0.0.9", "global"},
		{"192.0.0.10", "global"},
		{"192.0.0.11", "reserved"},
		{"192.0.0.170", "reserved"},
		{"192.0.0.171", "reserved"},
		{"192.0.0.255", "reserved"},
		{"192.0.1.0", "global"},
		{"192.0.2.1", "documentation"},
		{"192.31.196.1", "global"},
		{"192.52.193.1", "global"},
		// RFC 7526 removes the /24's reachability value, without requiring
		// filtering. Only the more specific /32 is explicitly non-global.
		{"192.88.99.1", "global"},
		{"192.88.99.2", "reserved"},
		{"192.88.99.3", "global"},
		{"192.168.0.1", "private"},
		{"192.175.48.1", "global"},
		{"198.18.0.1", "reserved"},
		{"198.51.100.1", "documentation"},
		{"203.0.113.1", "documentation"},
		{"240.0.0.1", "reserved"},
		{"255.255.255.255", "reserved"},
		{"::", "reserved"},
		{"::1", "loopback"},
		{"::ffff:192.0.0.9", "global"},
		{"::ffff:0.1.2.3", "reserved"},
		{"::ffff:10.0.0.1", "private"},
		{"64:ff9b::808:808", "global"},
		{"64:ff9b:1::1", "reserved"},
		{"64:ff9b:2::1", "global"},
		{"100::1", "reserved"},
		{"100:0:0:1::1", "reserved"},
		{"100:0:0:2::1", "global"},
		// Teredo and 6to4 have conditional/N/A reachability, not False.
		{"2001::1", "global"},
		{"2001:0:ffff::1", "global"},
		{"2001:1::", "reserved"},
		{"2001:1::1", "global"},
		{"2001:1::2", "global"},
		{"2001:1::3", "global"},
		{"2001:1::4", "reserved"},
		{"2001:2::1", "reserved"},
		{"2001:3::1", "global"},
		{"2001:4:111::1", "reserved"},
		{"2001:4:112::1", "global"},
		{"2001:4:113::1", "reserved"},
		{"2001:10::1", "reserved"},
		{"2001:1f:ffff::1", "reserved"},
		{"2001:20::1", "global"},
		{"2001:2f:ffff::1", "global"},
		{"2001:30::1", "global"},
		{"2001:3f:ffff::1", "global"},
		{"2001:40::1", "reserved"},
		{"2001:1ff:ffff::1", "reserved"},
		{"2001:200::1", "global"},
		{"2001:db8::1", "documentation"},
		{"2002::1", "global"},
		{"2620:4f:8000::1", "global"},
		{"3fff::1", "documentation"},
		{"3fff:fff:ffff::1", "documentation"},
		{"3fff:1000::1", "global"},
		{"5f00::1", "reserved"},
		{"5f01::1", "global"},
		{"fc00::1", "private"},
		{"fe80::1", "link-local"},
		{"224.0.0.1", "link-local"},
		{"ff02::1", "link-local"},
		{"ff0e::1", "multicast"},
	}
	for _, tc := range tests {
		t.Run(tc.address, func(t *testing.T) {
			t.Parallel()
			profile := NormalizeTarget(tc.address)
			if !profile.Valid || len(profile.IPs) != 1 {
				t.Fatalf("invalid profile: %+v", profile)
			}
			meta := profile.IPs[0]
			if meta.Scope != tc.scope || meta.IsBogon != (tc.scope != "global") {
				t.Errorf("classification = %+v; want scope %q, bogon %v", meta, tc.scope, tc.scope != "global")
			}
			if got := IsPublicIP(net.ParseIP(tc.address)); got != (tc.scope == "global") {
				t.Errorf("IsPublicIP = %v; want %v", got, tc.scope == "global")
			}
			if meta.IsDocumentation != (tc.scope == "documentation") {
				t.Errorf("documentation flag = %v; scope %q", meta.IsDocumentation, tc.scope)
			}
		})
	}
}

func TestSpecialPurposeOutboundValidation(t *testing.T) {
	oldPrivate := GetAllowPrivateIPs()
	oldLoopback, oldLinkLocal := atomic.LoadInt32(&allowLoopbackIPs), atomic.LoadInt32(&allowLinkLocalIPs)
	t.Cleanup(func() {
		SetAllowPrivateIPs(oldPrivate)
		SetAllowLoopbackIPs(oldLoopback != 0)
		SetAllowLinkLocalIPs(oldLinkLocal != 0)
	})
	for _, override := range []bool{false, true} {
		SetAllowPrivateIPs(override)
		SetAllowLoopbackIPs(override)
		SetAllowLinkLocalIPs(override)
		for _, tc := range []struct {
			address string
			allowed bool
		}{
			{"0.1.2.3", false}, {"3fff::1", false}, {"100::1", false},
			{"64:ff9b:1::1", false}, {"2001:2::1", false}, {"5f00::1", false},
			{"192.0.0.9", true}, {"192.0.0.10", true}, {"2001:1::1", true},
			{"10.0.0.1", override}, {"127.0.0.1", override}, {"fe80::1", override},
		} {
			if got := IsValidTarget(tc.address); got != tc.allowed {
				t.Errorf("IsValidTarget(%s), override %v = %v; want %v", tc.address, override, got, tc.allowed)
			}
			_, err := ValidateResolvedHost(context.Background(), tc.address)
			if (err == nil) != tc.allowed {
				t.Errorf("ValidateResolvedHost(%s), override %v: %v; allowed %v", tc.address, override, err, tc.allowed)
			}
			wantPublic := NormalizeTarget(tc.address).IPs[0].Scope == "global"
			if got := IsPublicIP(net.ParseIP(tc.address)); got != wantPublic {
				t.Errorf("IsPublicIP(%s), override %v = %v; want %v", tc.address, override, got, wantPublic)
			}
		}
	}
}
