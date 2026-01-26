package service

import (
	"fmt"
	"github.com/likexian/whois"
)

func Whois(target string) string {
	result, err := whois.Whois(target)
	if err != nil {
		return fmt.Sprintf("WHOIS error: %v", err)
	}
	return result
}
