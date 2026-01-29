package service

import (
	"fmt"
	"github.com/likexian/whois"
	"github.com/likexian/whois-parser"
	"strings"
)

type WhoisInfo struct {
	Raw       string `json:"raw"`
	Registrar string `json:"registrar,omitempty"`
	Expiry    string `json:"expiry,omitempty"`
	Created   string `json:"created,omitempty"`
}

func Whois(target string) interface{} {
	raw, err := whois.Whois(target)
	if err != nil && strings.Contains(err.Error(), "no whois server found") {
		// Manual fallbacks for common TLDs that might be missing in the library or IANA
		tld := ""
		parts := strings.Split(target, ".")
		if len(parts) > 1 {
			tld = strings.ToLower(parts[len(parts)-1])
		}

		fallbacks := map[string]string{
			"info": "whois.nic.info",
			"biz":  "whois.nic.biz",
			"mobi": "whois.dotmobi.net",
		}

		if server, ok := fallbacks[tld]; ok {
			raw, err = whois.Whois(target, server)
		}

		if err != nil || raw == "" {
			// Fallback to IANA to find the correct referral server
			ianaRaw, ianaErr := whois.Whois(target, "whois.iana.org")
			if ianaErr == nil {
				// Find "whois: " or "refer: " line
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
