package utils

import (
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"

	"whois/internal/model"
)

// CalculateSubnet returns exact bounds and counts for an IPv4 or IPv6 CIDR.
// It performs no network requests and does not enumerate addresses.
func CalculateSubnet(input string) (*model.SubnetInfo, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(input))
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}
	return calculateSubnet(prefix), nil
}

func calculateSubnet(input netip.Prefix) *model.SubnetInfo {
	prefix := input.Masked()
	network := prefix.Addr()
	addressBits := network.BitLen()
	hostBits := addressBits - prefix.Bits()
	count := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	lastBytes := network.AsSlice()
	for bit := prefix.Bits(); bit < addressBits; bit++ {
		lastBytes[bit/8] |= 1 << (7 - bit%8)
	}
	last, _ := netip.AddrFromSlice(lastBytes)
	info := &model.SubnetInfo{
		Version: 6, CIDR: prefix.String(), PrefixLength: prefix.Bits(),
		InputAddress: input.Addr().String(), Network: network.String(),
		LastAddress: last.String(), AddressCount: count.String(),
	}
	if !network.Is4() {
		info.Notes = []string{
			"IPv6 has no broadcast address. Address count covers the full prefix; assignable addresses depend on subnet use and reserved addresses.",
		}
		return info
	}
	info.Version = 4
	mask := net.CIDRMask(prefix.Bits(), 32)
	info.Netmask = netip.AddrFrom4([4]byte(mask)).String()
	info.WildcardMask = netip.AddrFrom4([4]byte{^mask[0], ^mask[1], ^mask[2], ^mask[3]}).String()
	info.Notes = []string{"Usable counts describe subnet host positions; special-purpose address reservations may further restrict assignment."}
	switch prefix.Bits() {
	case 31:
		// RFC 3021 sections 2.1 and 2.2: both addresses are hosts on a
		// point-to-point link, with no directed-broadcast address.
		info.FirstUsable, info.LastUsable, info.UsableCount = network.String(), last.String(), "2"
		info.Notes = append(info.Notes, "An IPv4 /31 uses both addresses on a point-to-point link (RFC 3021); it has no directed-broadcast address.")
	case 32:
		info.FirstUsable, info.LastUsable, info.UsableCount = network.String(), network.String(), "1"
		info.Notes = append(info.Notes, "An IPv4 /32 is a single host address; it has no separate network or directed-broadcast address.")
	default:
		info.Broadcast = last.String()
		info.FirstUsable, info.LastUsable = network.Next().String(), last.Prev().String()
		info.UsableCount = new(big.Int).Sub(count, big.NewInt(2)).String()
		info.Notes = append(info.Notes, "The IPv4 usable range excludes the subnet network and directed-broadcast addresses.")
	}
	return info
}
