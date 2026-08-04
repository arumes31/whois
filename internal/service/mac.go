package service

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	macMu          sync.RWMutex
	macFileMu      sync.RWMutex
	macUpdaterMu   sync.Mutex
	macUpdaterStop context.CancelFunc
	macUpdaterDone chan struct{}
	OUIURL         = "https://standards-oui.ieee.org/oui/oui.txt"
	OUIPath        = "data/oui.txt"
	TestMode       = false
	UpdateInterval = 12 * time.Hour
	MacHTTPClient  = &http.Client{Timeout: 5 * time.Minute}
)

const maxOUIDownloadBytes = 32 * 1024 * 1024

func InitializeMACService() {
	StopMACService()

	macMu.RLock()
	path := OUIPath
	ouiURL := OUIURL
	client := MacHTTPClient
	testMode := TestMode
	updateInterval := UpdateInterval
	macMu.RUnlock()

	// Ensure data directory exists
	_ = os.MkdirAll("data", 0750)

	// Initial download if missing
	if _, err := os.Stat(path); os.IsNotExist(err) {
		_ = downloadOUI(context.Background(), client, ouiURL, path)
	}

	if testMode {
		return
	}

	startMACUpdater(updateInterval, func(ctx context.Context) {
		if stat, err := os.Stat(path); err == nil && time.Since(stat.ModTime()) > 72*time.Hour {
			_ = downloadOUI(ctx, client, ouiURL, path)
		}
	})
}

func startMACUpdater(interval time.Duration, update func(context.Context)) {
	macUpdaterMu.Lock()
	defer macUpdaterMu.Unlock()

	stopMACUpdaterLocked()
	if interval <= 0 {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	macUpdaterStop = cancel
	macUpdaterDone = done

	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				update(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// StopMACService stops the periodic OUI updater and waits for any in-flight
// update to finish. It is safe to call when no updater is running.
func StopMACService() {
	macUpdaterMu.Lock()
	defer macUpdaterMu.Unlock()
	stopMACUpdaterLocked()
}

func stopMACUpdaterLocked() {
	if macUpdaterStop == nil {
		return
	}

	macUpdaterStop()
	<-macUpdaterDone
	macUpdaterStop = nil
	macUpdaterDone = nil
}

func DownloadOUI() error {
	macMu.RLock()
	client := MacHTTPClient
	ouiURL := OUIURL
	path := OUIPath
	macMu.RUnlock()
	return downloadOUI(context.Background(), client, ouiURL, path)
}

func downloadOUI(ctx context.Context, client *http.Client, ouiURL, path string) error {
	macFileMu.Lock()
	defer macFileMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ouiURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	return writeFileAtomically(path, resp.Body, maxOUIDownloadBytes)
}

func LookupMacVendor(ctx context.Context, mac string) (string, error) {
	hardwareAddr, err := net.ParseMAC(mac)
	if err != nil || len(hardwareAddr) < 3 {
		return "", fmt.Errorf("invalid mac address format")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	macMu.RLock()
	path := OUIPath
	macMu.RUnlock()

	vendor, err := localOUILookupAt(hardwareAddr, path)
	if err != nil {
		return "", err
	}
	if vendor == "" {
		return "Vendor not found", nil
	}
	return vendor, nil
}

func localOUILookup(mac string) (string, error) {
	hardwareAddr, err := net.ParseMAC(mac)
	if err != nil || len(hardwareAddr) < 3 {
		return "", fmt.Errorf("invalid mac address format")
	}
	macMu.RLock()
	path := OUIPath
	macMu.RUnlock()
	return localOUILookupAt(hardwareAddr, path)
}

func localOUILookupAt(hardwareAddr net.HardwareAddr, path string) (string, error) {
	macFileMu.RLock()
	defer macFileMu.RUnlock()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "", fmt.Errorf("OUI database missing")
	}

	// #nosec G304 -- path is an internal OUI database path, never request input.
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()

	prefix := fmt.Sprintf("%02X%02X%02X", hardwareAddr[0], hardwareAddr[1], hardwareAddr[2])

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
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scan OUI database: %w", err)
	}
	return "", nil
}
