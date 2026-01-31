package service

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
	"whois/internal/utils"

	"github.com/likexian/whois"
	"github.com/likexian/whois-parser"
	"github.com/openrdap/rdap"
)

type WhoisInfo struct {
	Raw       string `json:"raw"`
	Registrar string `json:"registrar,omitempty"`
	Expiry    string `json:"expiry,omitempty"`
	Created   string `json:"created,omitempty"`
}

var WhoisFunc = whois.Whois

var RdapLookupFunc = rdapLookup

func Whois(target string) interface{} {
	if !utils.IsValidTarget(target) {
		return "Error: invalid target for WHOIS"
	}

	// Try primary lookup
	raw, err := WhoisFunc(target)

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
			r := rand.New(rand.NewSource(time.Now().UnixNano()))
			r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

			for _, s := range shuffled {
				rRaw, rErr := WhoisFunc(target, s)
				if rErr == nil && !isErrorResponse(rRaw) {
					raw = rRaw
					err = nil
					break
				}
			}
		}

		// Still no good result? Try recursive IANA lookup
		if err != nil || isErrorResponse(raw) {
			ianaRaw, ianaErr := WhoisFunc(target, "whois.iana.org")
			if ianaErr == nil {
				lines := strings.Split(ianaRaw, "\n")
				for _, line := range lines {
					lowerLine := strings.ToLower(strings.TrimSpace(line))
					if strings.HasPrefix(lowerLine, "whois:") || strings.HasPrefix(lowerLine, "refer:") {
						rParts := strings.Split(line, ":")
						if len(rParts) > 1 {
							server := strings.TrimSpace(rParts[1])
							if server != "" {
								ianaResultRaw, ianaResultErr := WhoisFunc(target, server)
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
			rdapRaw, rdapErr := RdapLookupFunc(target)
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
						refRaw, refErr := WhoisFunc(target, refServer)
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
			sb.WriteString(fmt.Sprintf("%s: %s\n", key, value))
		}
	}
	return sb.String(), nil
}
