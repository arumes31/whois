package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"
	"whois/internal/utils"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/openrdap/rdap"
)

type WhoisInfo struct {
	Raw       string `json:"raw"`
	Registrar string `json:"registrar,omitempty"`
	Expiry    string `json:"expiry,omitempty"`
	Created   string `json:"created,omitempty"`
}

// WhoisFunc is the function type for WHOIS lookups, matching the signature of whois.Whois.
var WhoisFunc = func(target string, servers ...string) (string, error) {
	return whois.NewClient().SetTimeout(8*time.Second).Whois(target, servers...)
}

var WhoisServerValidator = validateWhoisServer

var RdapLookupFunc = rdapLookup

type whoisResult struct {
	raw string
	err error
}

func callWithContext(ctx context.Context, lookup func() (string, error)) (string, error) {
	result := make(chan whoisResult, 1)
	go func() {
		raw, err := lookup()
		result <- whoisResult{raw: raw, err: err}
	}()
	select {
	case response := <-result:
		return response.raw, response.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func callWhois(ctx context.Context, target string, servers ...string) (string, error) {
	for _, server := range servers {
		if err := WhoisServerValidator(ctx, server); err != nil {
			return "", err
		}
	}
	return callWithContext(ctx, func() (string, error) { return WhoisFunc(target, servers...) })
}

func validateWhoisServer(ctx context.Context, server string) error {
	server = strings.TrimSpace(server)
	if server == "" {
		return fmt.Errorf("WHOIS server is empty")
	}
	if strings.Contains(server, "://") {
		parsed, err := url.Parse(server)
		if err != nil || parsed.Hostname() == "" {
			return fmt.Errorf("invalid WHOIS server")
		}
		server = parsed.Hostname()
	} else if host, _, err := net.SplitHostPort(server); err == nil {
		server = host
	}
	server = strings.Trim(strings.TrimSuffix(server, "."), "[]")

	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, server)
	if err != nil {
		return fmt.Errorf("resolve WHOIS server: %w", err)
	}
	if len(addresses) == 0 {
		return fmt.Errorf("WHOIS server resolved to no addresses")
	}
	for _, address := range addresses {
		if !utils.IsPublicIP(address.IP) {
			return fmt.Errorf("WHOIS server resolves to a non-public address")
		}
	}
	return nil
}

func Whois(ctx context.Context, target string) interface{} {
	if !utils.IsValidTarget(target) {
		return "Error: invalid target for WHOIS"
	}

	raw, err := callWhois(ctx, target)
	if ctx.Err() != nil {
		return fmt.Sprintf("WHOIS error: %v", ctx.Err())
	}

	// Determine TLD
	tld := ""
	parts := strings.Split(target, ".")
	if len(parts) > 1 {
		tld = strings.ToLower(parts[len(parts)-1])
	}

	// Expanded fallback map with multiple servers per TLD
	fallbacks := map[string][]string{
		"info":   {"whois.nic.info", "whois.afilias.net", "whois.identity.digital"},
		"biz":    {"whois.nic.biz", "whois.neulevel.biz", "whois.biz"},
		"mobi":   {"whois.dotmobi.net", "whois.afilias.net"},
		"online": {"whois.nic.online", "whois.centralnic.com"},
		"site":   {"whois.nic.site", "whois.centralnic.com"},
		"top":    {"whois.nic.top", "whois.centralnic.com"},
		"xyz":    {"whois.nic.xyz", "whois.centralnic.com", "whois.nic.gmo"},
		"shop":   {"whois.nic.shop", "whois.gmo-registry.com"},
		"cloud":  {"whois.nic.cloud", "whois.centralnic.com"},
		"tech":   {"whois.nic.tech", "whois.centralnic.com"},
		"vip":    {"whois.nic.vip", "whois.centralnic.com"},
		"icu":    {"whois.nic.icu", "whois.centralnic.com"},
		"club":   {"whois.nic.club", "whois.centralnic.com"},
		"me":     {"whois.nic.me", "whois.meregistry.net"},
		"io":     {"whois.nic.io", "whois.io-registry.net"},
		"co":     {"whois.nic.co", "whois.cointernet.co"},
		"tv":     {"whois.nic.tv", "whois.verisign-grs.com"},
		"cc":     {"whois.nic.cc", "whois.verisign-grs.com"},
		"us":     {"whois.nic.us", "whois.neustar.us"},
	}

	isErrorResponse := func(r string) bool {
		rLower := strings.ToLower(r)
		return len(r) < 100 ||
			strings.Contains(rLower, "tld is not supported") ||
			strings.Contains(rLower, "invalid tld") ||
			strings.Contains(rLower, "no whois server found")
	}

	// If primary failed or returned error, try fallbacks
	if err != nil || isErrorResponse(raw) {
		if servers, ok := fallbacks[tld]; ok {
			shuffled := make([]string, len(servers))
			copy(shuffled, servers)
			for i := len(shuffled) - 1; i > 0; i-- {
				n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
				if err != nil {
					continue
				}
				j := int(n.Int64())
				shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
			}

			for _, s := range shuffled {
				rRaw, rErr := callWhois(ctx, target, s)
				if rErr == nil && !isErrorResponse(rRaw) {
					raw = rRaw
					err = nil
					break
				}
			}
		}

		// Still no good result? Try recursive IANA lookup
		if err != nil || isErrorResponse(raw) {
			ianaRaw, ianaErr := callWhois(ctx, target, "whois.iana.org")
			if ianaErr == nil {
				lines := strings.Split(ianaRaw, "\n")
				for _, line := range lines {
					lowerLine := strings.ToLower(strings.TrimSpace(line))
					if strings.HasPrefix(lowerLine, "whois:") || strings.HasPrefix(lowerLine, "refer:") {
						rParts := strings.Split(line, ":")
						if len(rParts) > 1 {
							server := strings.TrimSpace(rParts[1])
							if server != "" {
								ianaResultRaw, ianaResultErr := callWhois(ctx, target, server)
								if ianaResultErr == nil && !isErrorResponse(ianaResultRaw) {
									raw = ianaResultRaw
									err = nil
									break
								}
							}
						}
					}
				}
			}
		}

		// FINAL FALLBACK: RDAP (Modern replacement for WHOIS)
		if err != nil || isErrorResponse(raw) {
			rdapRaw, rdapErr := callWithContext(ctx, func() (string, error) { return RdapLookupFunc(target) })
			if rdapErr == nil && rdapRaw != "" {
				raw = rdapRaw
				err = nil
			}
		}
	}

	if err != nil {
		return fmt.Sprintf("WHOIS error: %v", err)
	}

	// Follow registrar referral if present in registry output
	if strings.Contains(raw, "Registrar WHOIS Server:") {
		lines := strings.Split(raw, "\n")
		for _, line := range lines {
			if strings.Contains(line, "Registrar WHOIS Server:") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					refServer := strings.TrimSpace(parts[1])
					if refServer != "" {
						refRaw, refErr := callWhois(ctx, target, refServer)
						if refErr == nil && len(refRaw) > len(raw)/2 {
							raw = refRaw
						}
						break
					}
				}
			}
		}
	}

	// Filter raw lines - only skip if the line STARTS with % or # (comments)
	lines := strings.Split(raw, "\n")
	var filtered []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "%") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == "" && (len(filtered) == 0 || filtered[len(filtered)-1] == "") {
			continue
		}
		filtered = append(filtered, line)
	}
	raw = strings.Join(filtered, "\n")

	result, err := whoisparser.Parse(raw)
	if err != nil {
		return WhoisInfo{Raw: raw}
	}

	info := WhoisInfo{Raw: raw}
	if result.Registrar != nil {
		info.Registrar = result.Registrar.Name
	}
	if result.Domain != nil {
		info.Expiry = result.Domain.ExpirationDate
		info.Created = result.Domain.CreatedDate
	}

	return info
}

func rdapLookup(target string) (string, error) {
	client := &rdap.Client{}
	domain, err := client.QueryDomain(target)
	if err != nil {
		return "", err
	}

	resp := &rdap.Response{Object: domain}
	whoisStyle := resp.ToWhoisStyleResponse()

	var sb strings.Builder
	sb.WriteString("RDAP SOURCE DATA (Converted to WHOIS Style)\n")
	sb.WriteString(strings.Repeat("-", 40) + "\n")
	for _, key := range whoisStyle.KeyDisplayOrder {
		values := whoisStyle.Data[key]
		for _, value := range values {
			fmt.Fprintf(&sb, "%s: %s\n", key, value)
		}
	}
	return sb.String(), nil
}
