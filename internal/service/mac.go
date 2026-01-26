package service

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

func LookupMacVendor(mac string) (string, error) {
	url := fmt.Sprintf("https://api.macvendors.com/%s", mac)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 200 {
		return string(body), nil
	} else if resp.StatusCode == 404 {
		return "Vendor not found", nil
	}
	return "", fmt.Errorf("API Error: %d", resp.StatusCode)
}
