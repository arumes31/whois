package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var CTURL = "https://crt.sh/?q=%s&output=json"

func FetchCTSubdomains(ctx context.Context, domain string) (map[string]interface{}, error) {
	url := fmt.Sprintf(CTURL, domain)
	client := &http.Client{Timeout: 60 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CT request failed: %v", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

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
