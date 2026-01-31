package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"whois/internal/utils"
)

var (
	CRTURL             = "https://crt.sh/"
	CertspotterURL     = "https://api.certspotter.com/v1/issuances"
	SubdomainCenterURL = "https://api.subdomain.center/"
)

func FetchCTSubdomains(ctx context.Context, domain string) (map[string]interface{}, error) {
	if !utils.IsValidTarget(domain) {
		return nil, fmt.Errorf("invalid target domain: %s", domain)
	}

	var allErrors []string

	// 1. Try Certspotter (usually fastest and most reliable)
	results, err := fetchCertspotter(ctx, domain)
	if err == nil && len(results) > 0 {
		return results, nil
	}
	if err != nil {
		allErrors = append(allErrors, fmt.Sprintf("Certspotter: %v", err))
	}

	// 2. Fallback to crt.sh
	results, err = fetchCrtSh(ctx, domain)
	if err == nil && len(results) > 0 {
		return results, nil
	}
	if err != nil {
		allErrors = append(allErrors, fmt.Sprintf("crt.sh: %v", err))
	}

	// 3. Fallback to Subdomain Center
	results, err = fetchSubdomainCenter(ctx, domain)
	if err == nil && len(results) > 0 {
		return results, nil
	}
	if err != nil {
		allErrors = append(allErrors, fmt.Sprintf("SubdomainCenter: %v", err))
	}

	if len(allErrors) > 0 {
		return nil, fmt.Errorf("All CT sources failed: %s", strings.Join(allErrors, "; "))
	}

	return nil, fmt.Errorf("No subdomains found from any source")
}

func fetchSubdomainCenter(ctx context.Context, domain string) (map[string]interface{}, error) {
	u, err := url.Parse(SubdomainCenterURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("domain", domain)
	u.RawQuery = q.Encode()

	client := &http.Client{Timeout: 15 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var data []string
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	subdomains := make(map[string]interface{})
	for _, sub := range data {
		sub = strings.TrimSpace(sub)
		sub = strings.TrimPrefix(sub, "*.")
		if sub != "" && sub != domain && strings.HasSuffix(sub, "."+domain) {
			subdomains[sub] = map[string]interface{}{}
		}
	}
	return subdomains, nil
}

func fetchCertspotter(ctx context.Context, domain string) (map[string]interface{}, error) {
	u, err := url.Parse(CertspotterURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("domain", domain)
	q.Set("include_subdomains", "true")
	q.Set("expand", "dns_names")
	u.RawQuery = q.Encode()

	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Certspotter error: %d", resp.StatusCode)
	}

	var data []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	subdomains := make(map[string]interface{})
	for _, entry := range data {
		for _, name := range entry.DNSNames {
			name = strings.TrimPrefix(name, "*.")
			if name != domain && strings.HasSuffix(name, "."+domain) {
				subdomains[name] = map[string]interface{}{}
			}
		}
	}
	return subdomains, nil
}

func fetchCrtSh(ctx context.Context, domain string) (map[string]interface{}, error) {
	u, err := url.Parse(CRTURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("q", domain)
	q.Set("output", "json")
	u.RawQuery = q.Encode()

	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("crt.sh HTTP %d", resp.StatusCode)
	}

	var data []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("Invalid JSON from crt.sh: %v", err)
	}

	subdomains := make(map[string]interface{})
	for _, entry := range data {
		for _, sub := range strings.Split(entry.NameValue, "\n") {
			sub = strings.TrimSpace(sub)
			sub = strings.TrimPrefix(sub, "*.")
			if sub != "" && sub != domain && strings.HasSuffix(sub, "."+domain) {
				subdomains[sub] = map[string]interface{}{}
			}
		}
	}

	if len(subdomains) == 0 {
		return nil, fmt.Errorf("No subdomains found")
	}

	return subdomains, nil
}
