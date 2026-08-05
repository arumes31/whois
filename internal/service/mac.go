package service

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"whois/internal/utils"
)

var (
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

// MACDatabaseAvailable reports whether the local OUI database is present and
// non-empty. Lookups remain network-free and fail closed when it is absent.
func MACDatabaseAvailable() bool {
	info, err := os.Stat(OUIPath)
	return err == nil && !info.IsDir() && info.Size() > 0
}

func InitializeMACService() {
	InitializeMACServiceContext(context.Background())
}

// InitializeMACServiceContext loads local OUI data, optionally downloads a
// missing copy, and starts periodic updates unless the lifecycle is canceled.
func InitializeMACServiceContext(ctx context.Context) {
	StopMACService()

	path := OUIPath
	ouiURL := OUIURL
	client := MacHTTPClient
	testMode := TestMode
	updateInterval := UpdateInterval

	// Initial download if missing
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := downloadOUI(ctx, client, ouiURL, path); err != nil && ctx.Err() == nil {
			utils.Log.Error("failed to download OUI database", utils.Field("error", err.Error()))
		}
	}

	if testMode || ctx.Err() != nil {
		return
	}

	startMACUpdater(updateInterval, func(ctx context.Context) {
		if ctx.Err() != nil {
			return
		}
		if stat, err := os.Stat(path); err == nil && time.Since(stat.ModTime()) > 72*time.Hour {
			if err := downloadOUI(ctx, client, ouiURL, path); err != nil && ctx.Err() == nil {
				utils.Log.Error("failed to update OUI database", utils.Field("error", err.Error()))
			}
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
				if ctx.Err() != nil {
					return
				}
				update(ctx)
				if ctx.Err() != nil {
					return
				}
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
	client := MacHTTPClient
	ouiURL := OUIURL
	path := OUIPath
	return downloadOUI(context.Background(), client, ouiURL, path)
}

func downloadOUI(ctx context.Context, client *http.Client, ouiURL, path string) error {
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

	stagedPath, err := stageOUIDownload(path, resp.Body)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(stagedPath) }()
	if err := ctx.Err(); err != nil {
		return err
	}

	macFileMu.Lock()
	defer macFileMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(stagedPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", filepath.Base(path), err)
	}
	return nil
}

func stageOUIDownload(path string, source io.Reader) (string, error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return "", err
	}
	placeholder, err := os.CreateTemp(directory, ".oui-stage-*")
	if err != nil {
		return "", err
	}
	stagedPath := placeholder.Name()
	if err := placeholder.Close(); err != nil {
		_ = os.Remove(stagedPath)
		return "", err
	}
	if err := os.Remove(stagedPath); err != nil {
		return "", err
	}
	if err := writeFileAtomically(stagedPath, source, maxOUIDownloadBytes); err != nil {
		return "", err
	}
	return stagedPath, nil
}

func LookupMacVendor(ctx context.Context, mac string) (string, error) {
	hardwareAddr, err := net.ParseMAC(mac)
	if err != nil || len(hardwareAddr) < 3 {
		return "", fmt.Errorf("invalid mac address format")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	path := OUIPath

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
	path := OUIPath
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
