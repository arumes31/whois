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

const (
	maxReverseDNSLookups   = 8
	maxReverseDNSNames     = 8
	reverseDNSTotalTimeout = 2 * time.Second
)

type targetResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
	LookupAddr(context.Context, string) ([]string, error)
}

// Special-purpose allocations not already identified by netip's private,
// loopback, link-local, multicast, and unspecified predicates. Reviewed against
// https://www.iana.org/assignments/iana-ipv4-special-registry/ and
// https://www.iana.org/assignments/iana-ipv6-special-registry/ on 2026-10-09.
// "reserved" retains this application's category for non-global destinations;
// it is not the registry's narrower Reserved-by-Protocol column.
var specialPrefixes = []struct {
	prefix netip.Prefix
	kind   string
}{
	{netip.MustParsePrefix("0.0.0.0/8"), "reserved"},
	{netip.MustParsePrefix("100.64.0.0/10"), "carrier-grade NAT"},
	{netip.MustParsePrefix("192.0.0.0/24"), "reserved"},
	{netip.MustParsePrefix("192.0.0.9/32"), "global"},
	{netip.MustParsePrefix("192.0.0.10/32"), "global"},
	{netip.MustParsePrefix("192.0.2.0/24"), "documentation"},
	// RFC 7526 removed the /24's reachability values, not its usability.
	// Only this more specific allocation is explicitly non-global.
	{netip.MustParsePrefix("192.88.99.2/32"), "reserved"},
	{netip.MustParsePrefix("198.18.0.0/15"), "benchmark"},
	{netip.MustParsePrefix("198.51.100.0/24"), "documentation"},
	{netip.MustParsePrefix("203.0.113.0/24"), "documentation"},
	{netip.MustParsePrefix("240.0.0.0/4"), "reserved"},
	{netip.MustParsePrefix("64:ff9b:1::/48"), "reserved"},
	{netip.MustParsePrefix("100::/64"), "reserved"},
	{netip.MustParsePrefix("100:0:0:1::/64"), "reserved"},
	{netip.MustParsePrefix("2001::/23"), "reserved"},
	// Teredo has conditional reachability (N/A), not an explicit False.
	// Retain its existing policy, just as for 6to4 outside this parent block.
	{netip.MustParsePrefix("2001::/32"), "global"},
	{netip.MustParsePrefix("2001:1::1/128"), "global"},
	{netip.MustParsePrefix("2001:1::2/128"), "global"},
	{netip.MustParsePrefix("2001:1::3/128"), "global"},
	{netip.MustParsePrefix("2001:2::/48"), "benchmark"},
	{netip.MustParsePrefix("2001:3::/32"), "global"},
	{netip.MustParsePrefix("2001:4:112::/48"), "global"},
	{netip.MustParsePrefix("2001:10::/28"), "reserved"},
	{netip.MustParsePrefix("2001:20::/28"), "global"},
	{netip.MustParsePrefix("2001:30::/28"), "global"},
	{netip.MustParsePrefix("2001:db8::/32"), "documentation"},
	{netip.MustParsePrefix("3fff::/20"), "documentation"},
	{netip.MustParsePrefix("5f00::/16"), "reserved"},
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

	canonicalHost := strings.TrimSuffix(host, ".")
	if addr, err := netip.ParseAddr(canonicalHost); err == nil {
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
	info.Host = strings.ToLower(canonicalHost)
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
		if strings.HasSuffix(u.Host, ":") || (port != "" && !validTargetPort(port)) {
			return "", "", "", fmt.Errorf("invalid target port")
		}
		return host, port, scheme, nil
	}

	if parsedHost, parsedPort, splitErr := net.SplitHostPort(raw); splitErr == nil {
		if !validTargetPort(parsedPort) {
			return "", "", "", fmt.Errorf("invalid target port")
		}
		return strings.Trim(parsedHost, "[]"), parsedPort, "", nil
	}
	return strings.Trim(raw, "[]"), "", "", nil
}

func validTargetPort(port string) bool {
	value, err := strconv.ParseUint(port, 10, 16)
	return err == nil && value > 0
}

func isValidHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	// A trailing root label must not be the only dot. Validate the canonical
	// form so every accepted hostname remains valid after normalization.
	if host == "" || !strings.Contains(host, ".") {
		return false
	}
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
	// More specific allocations override their parent, including public
	// exceptions inside a non-global block. Table order must not change policy.
	kind, matchedBits := "", -1
	for _, item := range specialPrefixes {
		if item.prefix.Bits() > matchedBits && item.prefix.Contains(addr) {
			kind, matchedBits = item.kind, item.prefix.Bits()
		}
	}
	switch kind {
	case "carrier-grade NAT":
		meta.IsCGNAT = true
	case "documentation":
		meta.IsDocumentation = true
	case "reserved", "benchmark":
		meta.IsReserved = true
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
	return enrichTarget(ctx, input, net.DefaultResolver, reverseDNSTotalTimeout)
}

func enrichTarget(ctx context.Context, input string, resolver targetResolver, reverseTimeout time.Duration) model.TargetInfo {
	info := NormalizeTarget(input)
	if !info.Valid || !info.Networkable {
		return info
	}
	if info.Kind == model.TargetKindDomain {
		resolutionStart := time.Now()
		addrs, err := resolver.LookupNetIP(ctx, "ip", info.Host)
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
	reverseLimit := min(len(info.IPs), maxReverseDNSLookups)
	if len(info.IPs) > reverseLimit {
		info.Warnings = append(info.Warnings, fmt.Sprintf("Reverse DNS lookups limited to the first %d addresses", reverseLimit))
	}
	reverseCtx, cancel := context.WithTimeout(ctx, reverseTimeout)
	defer cancel()
	for i := range reverseLimit {
		if reverseCtx.Err() != nil {
			info.Warnings = append(info.Warnings, "Reverse DNS lookup stopped: "+reverseCtx.Err().Error())
			break
		}
		names, err := resolver.LookupAddr(reverseCtx, info.IPs[i].Address)
		if err == nil {
			if len(names) > maxReverseDNSNames {
				names = names[:maxReverseDNSNames]
			}
			for j := range names {
				names[j] = strings.TrimSuffix(names[j], ".")
			}
			info.IPs[i].ReverseDNS = names
		} else if reverseCtx.Err() != nil {
			info.Warnings = append(info.Warnings, "Reverse DNS lookup stopped: "+reverseCtx.Err().Error())
			break
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
		if !addressAllowed(meta) {
			return nil, fmt.Errorf("target resolves to disallowed %s address", meta.Scope)
		}
	}
	return addresses, nil
}

// ResolveValidatedTarget returns one validated, numeric address suitable for
// passing to an operating-system command. Using the numeric address prevents a
// second DNS lookup from changing the destination after policy validation.
func ResolveValidatedTarget(ctx context.Context, target string) (string, error) {
	info := NormalizeTarget(target)
	if !info.Valid || !info.Networkable || info.Host == "" {
		return "", fmt.Errorf("invalid target")
	}
	addresses, err := ValidateResolvedHost(ctx, info.Host)
	if err != nil {
		return "", err
	}
	return addresses[0].IP.String(), nil
}

// DialTarget resolves once, validates every result, then connects to a validated address.
func DialTarget(ctx context.Context, network, host, port string, timeout time.Duration) (net.Conn, string, error) {
	addresses, err := ValidateResolvedHost(ctx, host)
	if err != nil {
		return nil, "", err
	}
	return DialResolvedTarget(ctx, network, addresses, port, timeout)
}

// DialResolvedTarget connects only to a previously validated address snapshot.
// Keeping resolution separate lets callers such as the port scanner avoid a DNS
// lookup for every connection while preventing DNS rebinding between attempts.
func DialResolvedTarget(ctx context.Context, network string, addresses []net.IPAddr, port string, timeout time.Duration) (net.Conn, string, error) {
	if len(addresses) == 0 {
		return nil, "", fmt.Errorf("connect target: no validated addresses")
	}
	dialCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		dialCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	dialer := &net.Dialer{}
	var lastErr error
	for _, address := range addresses {
		if err := dialCtx.Err(); err != nil {
			lastErr = err
			break
		}
		conn, dialErr := dialer.DialContext(dialCtx, network, net.JoinHostPort(address.IP.String(), port))
		if dialErr == nil {
			return conn, address.IP.String(), nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no connection attempts were made")
	}
	return nil, "", fmt.Errorf("connect target: %w", lastErr)
}
