package service

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var MacVendorsURL = "https://api.macvendors.com/%s"

func LookupMacVendor(mac string) (string, error) {
	// Try local lookup first
	if vendor, err := localOUILookup(mac); err == nil && vendor != "" {
		return vendor, nil
	}

	url := fmt.Sprintf(MacVendorsURL, mac)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
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
	file, err := os.Open("data/oui.txt")
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
