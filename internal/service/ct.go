package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var (
	CRTURL        = "https://crt.sh/?q=%s&output=json"
	CertspotterURL = "https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names"
)

func FetchCTSubdomains(ctx context.Context, domain string) (map[string]interface{}, error) {
	// Try Certspotter first (usually much faster)
	results, err := fetchCertspotter(ctx, domain)
	if err == nil && len(results) > 0 {
		return results, nil
	}

	// Fallback to crt.sh
	return fetchCrtSh(ctx, domain)
}

func fetchCertspotter(ctx context.Context, domain string) (map[string]interface{}, error) {
	url := fmt.Sprintf(CertspotterURL, domain)
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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
	url := fmt.Sprintf(CRTURL, domain)
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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
