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
	"whois/internal/utils"
)

var (
	MacVendorsURL = "https://api.macvendors.com/%s"
	OUIURL        = "https://standards-oui.ieee.org/oui/oui.txt"
	OUIPath       = "data/oui.txt"
	TestMode      = false
)

func InitializeMACService() {
	// Ensure data directory exists
	_ = os.MkdirAll("data", 0755)

	// Initial download if missing
	if _, err := os.Stat(OUIPath); os.IsNotExist(err) {
		_ = DownloadOUI()
	}

	if TestMode {
		return
	}

	// Start background watcher for 72h updates
	go func() {
		ticker := time.NewTicker(12 * time.Hour)
		for range ticker.C {
			if stat, err := os.Stat(OUIPath); err == nil {
				if time.Since(stat.ModTime()) > 72*time.Hour {
					_ = DownloadOUI()
				}
			}
		}
	}()
}

func DownloadOUI() error {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(OUIURL)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(OUIPath)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	_, err = io.Copy(out, resp.Body)
	return err
}

func LookupMacVendor(ctx context.Context, mac string) (string, error) {
	if !utils.IsValidMAC(mac) {
		return "", fmt.Errorf("invalid MAC address format")
	}

	// Try local lookup first
	if vendor, err := localOUILookup(mac); err == nil && vendor != "" {
		return vendor, nil
	}

	escapedMac := url.PathEscape(mac)
	targetURL := fmt.Sprintf(MacVendorsURL, escapedMac)
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
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