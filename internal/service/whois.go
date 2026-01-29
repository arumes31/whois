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
	if err != nil {
		return fmt.Sprintf("WHOIS error: %v", err)
	}

	// Filter raw lines
	lines := strings.Split(raw, "\n")
	var filtered []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "%") || strings.Contains(trimmed, "#") {
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
