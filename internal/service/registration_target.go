package service

import (
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// registrationTarget uses registry boundaries, not private hosting boundaries
// (for example github.io). Unknown suffixes retain the full query.
func registrationTarget(target string) string {
	if ip, err := netip.ParseAddr(target); err == nil {
		return ip.Unmap().String()
	}
	domain, err := idna.Lookup.ToASCII(strings.TrimSuffix(target, "."))
	if err != nil {
		return target
	}
	domain = strings.ToLower(domain)
	for candidate := domain; ; {
		suffix, icann := publicsuffix.PublicSuffix(candidate)
		if icann {
			if domain == suffix {
				return domain
			}
			prefix := strings.TrimSuffix(domain, "."+suffix)
			return prefix[strings.LastIndexByte(prefix, '.')+1:] + "." + suffix
		}
		_, parent, found := strings.Cut(candidate, ".")
		if !found {
			return domain
		}
		candidate = parent
	}
}
