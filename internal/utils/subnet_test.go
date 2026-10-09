package utils

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"whois/internal/model"
)

func TestCalculateSubnetIPv4(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, input, cidr, network, last, mask, wildcard, broadcast, firstUsable, lastUsable, count, usable string
	}{
		{"host bits", "192.168.1.129/24", "192.168.1.0/24", "192.168.1.0", "192.168.1.255", "255.255.255.0", "0.0.0.255", "192.168.1.255", "192.168.1.1", "192.168.1.254", "256", "254"},
		{"non-octet boundary", "172.16.31.255/20", "172.16.16.0/20", "172.16.16.0", "172.16.31.255", "255.255.240.0", "0.0.15.255", "172.16.31.255", "172.16.16.1", "172.16.31.254", "4096", "4094"},
		{"four addresses", "203.0.113.7/30", "203.0.113.4/30", "203.0.113.4", "203.0.113.7", "255.255.255.252", "0.0.0.3", "203.0.113.7", "203.0.113.5", "203.0.113.6", "4", "2"},
		{"point to point", "203.0.113.7/31", "203.0.113.6/31", "203.0.113.6", "203.0.113.7", "255.255.255.254", "0.0.0.1", "", "203.0.113.6", "203.0.113.7", "2", "2"},
		{"single host", "192.0.2.1/32", "192.0.2.1/32", "192.0.2.1", "192.0.2.1", "255.255.255.255", "0.0.0.0", "", "192.0.2.1", "192.0.2.1", "1", "1"},
		{"maximum host", "255.255.255.255/32", "255.255.255.255/32", "255.255.255.255", "255.255.255.255", "255.255.255.255", "0.0.0.0", "", "255.255.255.255", "255.255.255.255", "1", "1"},
		{"whole address space", "8.8.8.8/0", "0.0.0.0/0", "0.0.0.0", "255.255.255.255", "0.0.0.0", "255.255.255.255", "255.255.255.255", "0.0.0.1", "255.255.255.254", "4294967296", "4294967294"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := CalculateSubnet(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if got.Version != 4 || got.CIDR != tc.cidr || got.Network != tc.network || got.LastAddress != tc.last ||
				got.Netmask != tc.mask || got.WildcardMask != tc.wildcard || got.Broadcast != tc.broadcast ||
				got.FirstUsable != tc.firstUsable || got.LastUsable != tc.lastUsable || got.AddressCount != tc.count || got.UsableCount != tc.usable {
				t.Fatalf("CalculateSubnet(%q) = %+v", tc.input, got)
			}
			inputPrefix := netip.MustParsePrefix(tc.input)
			if got.InputAddress != inputPrefix.Addr().String() || got.PrefixLength != inputPrefix.Bits() || len(got.Notes) == 0 {
				t.Fatalf("missing original address/prefix explanation: %+v", got)
			}
			if inputPrefix.Bits() == 31 && !strings.Contains(strings.Join(got.Notes, " "), "point-to-point") {
				t.Fatalf("/31 use not explained: %+v", got.Notes)
			}
		})
	}
}

func TestCalculateSubnetIPv6(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, input, network, last, count string }{
		{"subnet", "2001:db8:abcd:1234::beef/64", "2001:db8:abcd:1234::", "2001:db8:abcd:1234:ffff:ffff:ffff:ffff", "18446744073709551616"},
		{"non-octet boundary", "2001:db8:abcd:1234:ffff::1/65", "2001:db8:abcd:1234:8000::", "2001:db8:abcd:1234:ffff:ffff:ffff:ffff", "9223372036854775808"},
		{"two addresses", "2001:db8::1/127", "2001:db8::", "2001:db8::1", "2"},
		{"single address", "2001:db8::1/128", "2001:db8::1", "2001:db8::1", "1"},
		{"maximum address", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "1"},
		{"whole address space", "::1/0", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "340282366920938463463374607431768211456"},
		{"IPv4 mapped remains IPv6 prefix", "::ffff:192.0.2.7/120", "::ffff:192.0.2.0", "::ffff:192.0.2.255", "256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := CalculateSubnet(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			prefix := netip.MustParsePrefix(tc.input)
			if got.Version != 6 || got.Network != tc.network || got.LastAddress != tc.last || got.AddressCount != tc.count || got.CIDR != prefix.Masked().String() || got.InputAddress != prefix.Addr().String() {
				t.Fatalf("CalculateSubnet(%q) = %+v", tc.input, got)
			}
			if got.Broadcast != "" || got.Netmask != "" || got.WildcardMask != "" || got.FirstUsable != "" || got.LastUsable != "" || got.UsableCount != "" {
				t.Fatalf("IPv6 result implies IPv4 broadcast/usable semantics: %+v", got)
			}
			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(encoded), `"address_count":"`+tc.count+`"`) || strings.Contains(string(encoded), `"broadcast"`) || strings.Contains(string(encoded), `"usable_count"`) {
				t.Fatalf("wire result loses integer precision or asserts usability: %s", encoded)
			}
			if !strings.Contains(strings.Join(got.Notes, " "), "no broadcast") {
				t.Fatalf("missing IPv6 explanation: %+v", got.Notes)
			}
		})
	}
}

func TestCalculateSubnetRejectsInvalidCIDR(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"", "192.0.2.1", "example.com/24", "192.0.2.1/33", "192.0.2.1/-1", "::1/129", "::1/-1", "fe80::1%eth0/64", "192.0.2.1/255.255.255.0", "https://192.0.2.1/24", "192.0.2.999/24"} {
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			if got, err := CalculateSubnet(input); err == nil || got != nil {
				t.Fatalf("CalculateSubnet(%q) = %+v, %v; want error", input, got, err)
			}
		})
	}
}

type subnetNetworkGuard struct{ t *testing.T }

func (r subnetNetworkGuard) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.t.Fatal("subnet calculation attempted a forward DNS lookup")
	return nil, nil
}

func (r subnetNetworkGuard) LookupAddr(context.Context, string) ([]string, error) {
	r.t.Fatal("subnet calculation attempted a reverse DNS lookup")
	return nil, nil
}

func TestNormalizeTargetIncludesLocalSubnetCalculation(t *testing.T) {
	t.Parallel()
	for _, input := range []string{" 192.0.2.25/24 ", "2001:db8::1234/64", "::ffff:192.0.2.7/120"} {
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			got := enrichTarget(context.Background(), input, subnetNetworkGuard{t}, time.Second)
			wantPrefix := netip.MustParsePrefix(strings.TrimSpace(input))
			if !got.Valid || got.Networkable || got.Kind != model.TargetKindCIDR || got.Input != input || got.Subnet == nil || got.Subnet.CIDR != wantPrefix.Masked().String() || got.Subnet.InputAddress != wantPrefix.Addr().String() {
				t.Fatalf("CIDR normalization lost local calculation: %+v", got)
			}
			if got.Prefix != got.Subnet.CIDR || got.Normalized != got.Subnet.CIDR {
				t.Fatalf("existing normalization differs from calculator: %+v", got)
			}
		})
	}
	if got := NormalizeTarget("192.0.2.1"); got.Subnet != nil {
		t.Fatalf("plain host acquired a guessed subnet: %+v", got)
	}
}

func TestNormalizeTargetRejectsInvalidCIDR(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"8.8.8.8/33", "8.8.8.8/032", "8.8.8.8/-1", "8.8.8.8/abc", "8.8.8.8/", "2001:4860:4860::8888/129", "2001:4860:4860::8888/abc", "[2001:4860:4860::8888]/64"} {
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			got := enrichTarget(context.Background(), input, subnetNetworkGuard{t}, time.Second)
			if got.Valid || got.Networkable || got.Subnet != nil || got.Error == "" {
				t.Fatalf("invalid CIDR fell back to network target: %+v", got)
			}
		})
	}
}

func TestNormalizeTargetPreservesExplicitIPAndDomainURLs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		input string
		host  string
	}{
		{"https://8.8.8.8/33", "8.8.8.8"},
		{"http://8.8.8.8/abc", "8.8.8.8"},
		{"https://[2001:4860:4860::8888]/129", "2001:4860:4860::8888"},
		{"example.com/path", "example.com"},
		{"example.com/33", "example.com"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := NormalizeTarget(tc.input)
			if !got.Valid || !got.Networkable || got.Host != tc.host || got.Subnet != nil {
				t.Fatalf("URL normalization changed: %+v", got)
			}
		})
	}
}

func TestSubnetCalculatorAccuracy10000(t *testing.T) {
	t.Parallel()
	const cases = 10000
	random := rand.New(rand.NewPCG(20261009, 3021))
	started := time.Now()
	for index := range cases {
		width := 32
		if index%2 != 0 {
			width = 128
		}
		address := make([]byte, width/8)
		if width == 32 {
			binary.BigEndian.PutUint32(address, random.Uint32())
		} else {
			binary.BigEndian.PutUint64(address[:8], random.Uint64())
			binary.BigEndian.PutUint64(address[8:], random.Uint64())
			if index%127 == 0 {
				clear(address[:10])
				address[10], address[11] = 255, 255
			}
		}
		prefixLength := (index / 2) % (width + 1)
		inputAddress, _ := netip.AddrFromSlice(address)
		input := inputAddress.String() + "/" + strconv.Itoa(prefixLength)
		got, err := CalculateSubnet(input)
		if err != nil {
			t.Fatalf("case %d %s: %v", index, input, err)
		}
		// Independent byte-mask oracle: the implementation sets individual
		// host bits and shifts a count; this calculates both bounds with masks
		// and derives the count by subtracting their integer values.
		mask := net.CIDRMask(prefixLength, width)
		networkBytes, lastBytes := make([]byte, len(address)), make([]byte, len(address))
		for i, value := range address {
			networkBytes[i] = value & mask[i]
			lastBytes[i] = value | ^mask[i]
		}
		network, _ := netip.AddrFromSlice(networkBytes)
		last, _ := netip.AddrFromSlice(lastBytes)
		count := new(big.Int).Sub(new(big.Int).SetBytes(lastBytes), new(big.Int).SetBytes(networkBytes))
		count.Add(count, big.NewInt(1))
		prefix := netip.PrefixFrom(network, prefixLength)
		if got.Network != network.String() || got.LastAddress != last.String() || got.CIDR != prefix.String() ||
			got.AddressCount != count.String() || got.InputAddress != inputAddress.String() || got.PrefixLength != prefixLength {
			t.Fatalf("case %d %s: wrong bounds/count/input preservation: %+v", index, input, got)
		}
		if !prefix.Contains(inputAddress) || !prefix.Contains(network) || !prefix.Contains(last) ||
			(network.Prev().IsValid() && prefix.Contains(network.Prev())) || (last.Next().IsValid() && prefix.Contains(last.Next())) {
			t.Fatalf("case %d %s: incorrect inclusive boundaries %s..%s", index, input, network, last)
		}
		profile := NormalizeTarget(input)
		if profile.Kind != model.TargetKindCIDR || !profile.Valid || profile.Networkable || profile.Subnet == nil ||
			profile.Subnet.InputAddress != inputAddress.String() || profile.Subnet.CIDR != got.CIDR {
			t.Fatalf("case %d %s: target integration lost host bits or CIDR semantics: %+v", index, input, profile)
		}
		if width == 128 {
			if got.Version != 6 || got.Broadcast != "" || got.UsableCount != "" || got.FirstUsable != "" || got.LastUsable != "" {
				t.Fatalf("case %d %s: invented IPv6 usability/broadcast: %+v", index, input, got)
			}
			continue
		}
		firstUsable, lastUsable, broadcast := network, last, ""
		if prefixLength < 31 {
			firstUsable, lastUsable, broadcast = network.Next(), last.Prev(), last.String()
			count.Sub(count, big.NewInt(2))
		}
		maskAddress, _ := netip.AddrFromSlice(mask)
		wildcard := make([]byte, len(mask))
		for i, value := range mask {
			wildcard[i] = ^value
		}
		wildcardAddress, _ := netip.AddrFromSlice(wildcard)
		if got.Version != 4 || got.FirstUsable != firstUsable.String() || got.LastUsable != lastUsable.String() ||
			got.Broadcast != broadcast || got.UsableCount != count.String() || got.Netmask != maskAddress.String() || got.WildcardMask != wildcardAddress.String() {
			t.Fatalf("case %d %s: incorrect IPv4 mask or host range: %+v", index, input, got)
		}
	}
	t.Logf("validated %d deterministic prefixes (5000 IPv4, 5000 IPv6), all prefix lengths, exact spans/counts and normalization in %s", cases, time.Since(started))
}
