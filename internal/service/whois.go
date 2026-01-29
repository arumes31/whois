package service

import (
	"fmt"
	"github.com/likexian/whois"
	"github.com/likexian/whois-parser"
	"math/rand"
	"strings"
	"time"
)

type WhoisInfo struct {
	Raw       string `json:"raw"`
	Registrar string `json:"registrar,omitempty"`
	Expiry    string `json:"expiry,omitempty"`
	Created   string `json:"created,omitempty"`
}

func Whois(target string) interface{} {
	// Try primary lookup
	raw, err := whois.Whois(target)

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

	// If primary failed or returned suspiciously little data, try fallbacks in random order
	if err != nil || len(raw) < 100 {
		if servers, ok := fallbacks[tld]; ok {
			// Create a copy to shuffle
			shuffled := make([]string, len(servers))
			copy(shuffled, servers)
			r := rand.New(rand.NewSource(time.Now().UnixNano()))
			r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

			for _, s := range shuffled {
				rRaw, rErr := whois.Whois(target, s)
				if rErr == nil && len(rRaw) > 100 {
					raw = rRaw
					err = nil
					break
				}
			}
		}

		// Still no good result? Try recursive IANA lookup
		if err != nil || len(raw) < 100 {
			ianaRaw, ianaErr := whois.Whois(target, "whois.iana.org")
			if ianaErr == nil {
				lines := strings.Split(ianaRaw, "\n")
				for _, line := range lines {
					lowerLine := strings.ToLower(strings.TrimSpace(line))
					if strings.HasPrefix(lowerLine, "whois:") || strings.HasPrefix(lowerLine, "refer:") {
						rParts := strings.Split(line, ":")
						if len(rParts) > 1 {
							server := strings.TrimSpace(rParts[1])
							if server != "" {
								raw, err = whois.Whois(target, server)
								break
							}
						}
					}
				}
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
						refRaw, refErr := whois.Whois(target, refServer)
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
