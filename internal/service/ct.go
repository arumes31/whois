package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func FetchCTSubdomains(domain string) (map[string]interface{}, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)
	client := &http.Client{Timeout: 60 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("CT request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var data []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("Invalid JSON: %v", err)
	}

	subdomains := make(map[string]interface{})
	for _, entry := range data {
		name := strings.TrimSpace(entry.NameValue)
		if name == "" {
			continue
		}
		for _, sub := range strings.Split(name, "\n") {
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
