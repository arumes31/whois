package utils

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"whois/internal/model"
)

var asnPattern = regexp.MustCompile(`(?i)^AS([0-9]{1,10})$`)

var specialPrefixes = []struct {
	prefix netip.Prefix
	kind   string
}{
	{netip.MustParsePrefix("100.64.0.0/10"), "carrier-grade NAT"},
	{netip.MustParsePrefix("192.0.2.0/24"), "documentation"},
	{netip.MustParsePrefix("198.51.100.0/24"), "documentation"},
	{netip.MustParsePrefix("203.0.113.0/24"), "documentation"},
	{netip.MustParsePrefix("2001:db8::/32"), "documentation"},
	{netip.MustParsePrefix("192.0.0.0/24"), "reserved"},
	{netip.MustParsePrefix("198.18.0.0/15"), "benchmark"},
	{netip.MustParsePrefix("240.0.0.0/4"), "reserved"},
	{netip.MustParsePrefix("2001:10::/28"), "reserved"},
}

// NormalizeTarget recognizes user input and returns a canonical host-oriented target.
func NormalizeTarget(input string) model.TargetInfo {
	info := model.TargetInfo{Input: input, Kind: model.TargetKindUnknown}
	raw := strings.TrimSpace(input)
	if raw == "" {
		info.Error = "target is empty"
		return info
	}

	if match := asnPattern.FindStringSubmatch(raw); match != nil {
		asn, err := strconv.ParseUint(match[1], 10, 32)
		if err != nil || asn == 0 {
			info.Error = "invalid autonomous system number"
			return info
		}
		info.Kind = model.TargetKindASN
		info.ASN = uint32(asn)
		info.Normalized = fmt.Sprintf("AS%d", asn)
		info.Valid = true
		info.Warnings = []string{"ASN intelligence requires a routing data source and is not queried in provider-free mode"}
		return info
	}

	if prefix, err := netip.ParsePrefix(raw); err == nil {
		prefix = prefix.Masked()
		info.Kind = model.TargetKindCIDR
		info.Prefix = prefix.String()
		info.Normalized = prefix.String()
		info.Valid = true
		info.IPs = []model.IPMetadata{classifyIP(prefix.Addr())}
		info.Warnings = []string{"CIDR ranges are classified locally but are not sent to single-host network services"}
		return info
	}

	host, port, scheme, err := splitTarget(raw)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	info.Host, info.Port, info.Scheme = host, port, scheme

	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		info.Host = addr.String()
		info.Normalized = info.Host
		if port != "" {
			info.Normalized = net.JoinHostPort(info.Host, port)
		}
		if addr.Is4() {
			info.Kind = model.TargetKindIPv4
		} else {
			info.Kind = model.TargetKindIPv6
		}
		info.IPs = []model.IPMetadata{classifyIP(addr)}
		info.Valid = true
		info.Networkable = true
		return info
	}

	if !isValidHostname(host) {
		info.Error = "invalid target host"
		return info
	}
	info.Kind = model.TargetKindDomain
	info.Host = strings.ToLower(strings.TrimSuffix(host, "."))
	info.Normalized = info.Host
	if port != "" {
		info.Normalized = net.JoinHostPort(info.Host, port)
	}
	info.Valid = true
	info.Networkable = true
	return info
}

func splitTarget(raw string) (host, port, scheme string, err error) {
	candidate := raw
	if strings.HasPrefix(candidate, "//") {
		candidate = "http:" + candidate
	} else if strings.Contains(candidate, "://") {
		// already an absolute URL
	} else if strings.ContainsAny(candidate, "/?#") {
		candidate = "http://" + candidate
	}

	if strings.Contains(candidate, "://") {
		u, parseErr := url.Parse(candidate)
		if parseErr != nil || u.Hostname() == "" {
			return "", "", "", fmt.Errorf("invalid target url")
		}
		if u.User != nil {
			return "", "", "", fmt.Errorf("url credentials are not accepted")
		}
		host, port, scheme = u.Hostname(), u.Port(), strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" {
			return "", "", "", fmt.Errorf("unsupported url scheme")
		}
		return host, port, scheme, nil
	}

	if parsedHost, parsedPort, splitErr := net.SplitHostPort(raw); splitErr == nil {
		if _, portErr := strconv.ParseUint(parsedPort, 10, 16); portErr != nil || parsedPort == "0" {
			return "", "", "", fmt.Errorf("invalid target port")
		}
		return strings.Trim(parsedHost, "[]"), parsedPort, "", nil
	}
	return strings.Trim(raw, "[]"), "", "", nil
}

func isValidHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '-' {
				return false
			}
		}
	}
	return true
}

func classifyIP(addr netip.Addr) model.IPMetadata {
	addr = addr.Unmap()
	meta := model.IPMetadata{
		Address: addr.String(), Version: 6, IsPrivate: addr.IsPrivate(), IsLoopback: addr.IsLoopback(),
		IsLinkLocal: addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast(), IsMulticast: addr.IsMulticast(),
		IsUnspecified: addr.IsUnspecified(), Scope: "global",
	}
	if addr.Is4() {
		meta.Version = 4
	}
	for _, item := range specialPrefixes {
		if item.prefix.Contains(addr) {
			switch item.kind {
			case "carrier-grade NAT":
				meta.IsCGNAT = true
			case "documentation":
				meta.IsDocumentation = true
			default:
				meta.IsReserved = true
			}
		}
	}
	if meta.IsPrivate {
		meta.Scope = "private"
	} else if meta.IsLoopback {
		meta.Scope = "loopback"
	} else if meta.IsLinkLocal {
		meta.Scope = "link-local"
	} else if meta.IsCGNAT {
		meta.Scope = "carrier-grade NAT"
	} else if meta.IsDocumentation {
		meta.Scope = "documentation"
	} else if meta.IsReserved || meta.IsUnspecified {
		meta.Scope = "reserved"
	} else if meta.IsMulticast {
		meta.Scope = "multicast"
	}
	meta.IsBogon = !addr.IsGlobalUnicast() || meta.IsPrivate || meta.IsCGNAT || meta.IsDocumentation || meta.IsReserved
	return meta
}

// EnrichTarget resolves addresses and reverse names without using an external data provider.
func EnrichTarget(ctx context.Context, input string) model.TargetInfo {
	info := NormalizeTarget(input)
	if !info.Valid || !info.Networkable {
		return info
	}
	if info.Kind == model.TargetKindDomain {
		resolutionStart := time.Now()
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", info.Host)
		info.ResolutionMS = time.Since(resolutionStart).Milliseconds()
		if err != nil {
			info.Warnings = append(info.Warnings, "DNS resolution failed: "+err.Error())
			return info
		}
		info.IPs = make([]model.IPMetadata, 0, len(addrs))
		for _, addr := range addrs {
			info.IPs = append(info.IPs, classifyIP(addr))
		}
	}
	for i := range info.IPs {
		names, err := net.DefaultResolver.LookupAddr(ctx, info.IPs[i].Address)
		if err == nil {
			for j := range names {
				names[j] = strings.TrimSuffix(names[j], ".")
			}
			info.IPs[i].ReverseDNS = names
		}
	}
	return info
}

// ValidateResolvedHost blocks unsafe addresses, including addresses learned after DNS resolution.
func ValidateResolvedHost(ctx context.Context, host string) ([]net.IPAddr, error) {
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve target: %w", err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("target resolved to no addresses")
	}
	for _, address := range addresses {
		addr, ok := netip.AddrFromSlice(address.IP)
		if !ok {
			return nil, fmt.Errorf("target resolved to an invalid address")
		}
		meta := classifyIP(addr)
		if !GetAllowPrivateIPs() && meta.IsBogon {
			return nil, fmt.Errorf("target resolves to disallowed %s address", meta.Scope)
		}
		if meta.IsMulticast || meta.IsUnspecified {
			return nil, fmt.Errorf("target resolves to disallowed %s address", meta.Scope)
		}
	}
	return addresses, nil
}

// DialTarget resolves once, validates every result, then connects to a validated address.
func DialTarget(ctx context.Context, network, host, port string, timeout time.Duration) (net.Conn, string, error) {
	addresses, err := ValidateResolvedHost(ctx, host)
	if err != nil {
		return nil, "", err
	}
	dialer := &net.Dialer{Timeout: timeout}
	var lastErr error
	for _, address := range addresses {
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(address.IP.String(), port))
		if dialErr == nil {
			return conn, address.IP.String(), nil
		}
		lastErr = dialErr
	}
	return nil, "", fmt.Errorf("connect target: %w", lastErr)
}
