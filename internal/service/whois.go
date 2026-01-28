package service

import (
	"fmt"
	"github.com/likexian/whois"
	"github.com/likexian/whois-parser"
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
