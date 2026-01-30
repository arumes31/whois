package service

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)
...
func LookupMacVendor(ctx context.Context, mac string) (string, error) {
	// Try local lookup first
	if vendor, err := localOUILookup(mac); err == nil && vendor != "" {
		return vendor, nil
	}

	escapedMac := url.PathEscape(mac)
	url := fmt.Sprintf(MacVendorsURL, escapedMac)
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 200 {
		return string(body), nil
	} else if resp.StatusCode == 404 {
		return "Vendor not found", nil
	}
	return "", fmt.Errorf("API Error: %d", resp.StatusCode)
}

func localOUILookup(mac string) (string, error) {
	if _, err := os.Stat(OUIPath); os.IsNotExist(err) {
		return "", fmt.Errorf("OUI database missing")
	}

	file, err := os.Open(OUIPath)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()

	prefix := strings.ReplaceAll(strings.ToUpper(mac), ":", "")
	if len(prefix) > 6 {
		prefix = prefix[:6]
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "(base 16)") && strings.HasPrefix(line, prefix) {
			parts := strings.Split(line, "(base 16)")
			if len(parts) > 1 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}
	return "", nil
}
