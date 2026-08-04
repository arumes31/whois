package service

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"whois/internal/utils"

	"github.com/oschwald/geoip2-golang"
)

var (
	geoReader         *geoip2.Reader
	geoMu             sync.RWMutex
	geoUpdateMu       sync.Mutex
	geoUpdaterMu      sync.Mutex
	geoUpdaterStop    context.CancelFunc
	geoUpdaterDone    chan struct{}
	geoPath           = "data/GeoLite2-City.mmdb"
	geoAccountID      string
	geoLicenseKey     string
	GeoTestMode       = false
	GeoUpdateInterval = 6 * time.Hour
)

type GeoInfo struct {
	Country      string  `json:"country"`
	CountryCode  string  `json:"countryCode"`
	CountryEmoji string  `json:"country_emoji"`
	RegionName   string  `json:"regionName"`
	City         string  `json:"city"`
	Zip          string  `json:"zip"`
	Lat          float64 `json:"lat"`
	Lon          float64 `json:"lon"`
	Timezone     string  `json:"timezone"`
	ISP          string  `json:"isp"`
	Org          string  `json:"org"`
	AS           string  `json:"as"`
	Query        string  `json:"query"`
	Status       string  `json:"status"`
	Message      string  `json:"message,omitempty"`
}

var (
	errGeoDBUnavailable  = errors.New("local GeoIP database is unavailable")
	errGeoRecordNotFound = errors.New("local GeoIP record not found")
)

func getFlagEmoji(countryCode string) string {
	if len(countryCode) != 2 {
		return ""
	}
	countryCode = strings.ToUpper(countryCode)
	// Regional Indicator Symbol Letter A is 127462 (0x1F1E6)
	// 'A' is 65
	const offset = 127397
	return string(rune(countryCode[0])+offset) + string(rune(countryCode[1])+offset)
}

func InitializeGeoDB(licenseKey, accountID string) {
	StopGeoDBUpdater()

	geoMu.Lock()
	geoAccountID = accountID
	geoLicenseKey = licenseKey
	path := geoPath
	testMode := GeoTestMode
	updateInterval := GeoUpdateInterval
	client := GeoHTTPClient
	geoMu.Unlock()

	// Ensure data directory exists
	_ = os.MkdirAll("data", 0750)

	updateURL := ""
	if licenseKey != "" {
		// Using the direct download URL for GeoLite2-City
		updateURL = fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=%s&suffix=tar.gz", licenseKey)
	} else {
		// Fallback to a common public mirror if no key is provided (behavior like rauth)
		updateURL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
	}

	_, err := os.Stat(path)
	shouldUpdate := false

	if os.IsNotExist(err) {
		utils.Log.Info("GeoIP database missing, downloading...")
		shouldUpdate = true
	}

	geoUpdateMu.Lock()
	if shouldUpdate && updateURL != "" {
		if err := downloadGeoDB(context.Background(), updateURL, path, client, accountID, licenseKey); err != nil {
			utils.Log.Error("failed to download GeoIP DB", utils.Field("error", err.Error()))
		}
	}

	reloadGeoDB(path)
	geoUpdateMu.Unlock()

	if testMode {
		return
	}

	startGeoDBUpdater(updateInterval, func(ctx context.Context) {
		geoUpdateMu.Lock()
		defer geoUpdateMu.Unlock()

		if updateURL == "" {
			return
		}
		if stat, err := os.Stat(path); err == nil && time.Since(stat.ModTime()) > 72*time.Hour {
			utils.Log.Info("GeoIP database older than 72h, performing periodic update...")
			_ = downloadGeoDB(ctx, updateURL, path, client, accountID, licenseKey)
			reloadGeoDB(path)
		}
	})
}

func startGeoDBUpdater(interval time.Duration, update func(context.Context)) {
	geoUpdaterMu.Lock()
	defer geoUpdaterMu.Unlock()

	stopGeoDBUpdaterLocked()
	if interval <= 0 {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	geoUpdaterStop = cancel
	geoUpdaterDone = done

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

// StopGeoDBUpdater stops the periodic database updater and waits for any
// in-flight update to finish. It is safe to call when no updater is running.
func StopGeoDBUpdater() {
	geoUpdaterMu.Lock()
	defer geoUpdaterMu.Unlock()
	stopGeoDBUpdaterLocked()
}

func stopGeoDBUpdaterLocked() {
	if geoUpdaterStop == nil {
		return
	}

	geoUpdaterStop()
	<-geoUpdaterDone
	geoUpdaterStop = nil
	geoUpdaterDone = nil
}

func ManualUpdateGeoDB() error {
	geoMu.RLock()
	licenseKey := geoLicenseKey
	accountID := geoAccountID
	path := geoPath
	client := GeoHTTPClient
	geoMu.RUnlock()

	if licenseKey == "" {
		return fmt.Errorf("MAXMIND_LICENSE_KEY is not set")
	}
	url := fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=%s&suffix=tar.gz", licenseKey)
	geoUpdateMu.Lock()
	defer geoUpdateMu.Unlock()

	// Close the reader before downloading to avoid file locking on Windows
	CloseGeoDB()

	err := downloadGeoDB(context.Background(), url, path, client, accountID, licenseKey)
	reloadGeoDB(path)
	return err
}

func CloseGeoDB() {
	geoMu.Lock()
	defer geoMu.Unlock()
	if geoReader != nil {
		_ = geoReader.Close()
		geoReader = nil
	}
}

func ReloadGeoDB() {
	geoMu.RLock()
	path := geoPath
	geoMu.RUnlock()
	geoUpdateMu.Lock()
	defer geoUpdateMu.Unlock()
	reloadGeoDB(path)
}

func reloadGeoDB(path string) {
	geoMu.Lock()
	defer geoMu.Unlock()

	if geoReader != nil {
		_ = geoReader.Close()
	}

	reader, err := geoip2.Open(path)
	if err == nil {
		geoReader = reader
		utils.Log.Info("GeoIP database loaded successfully.")
	} else {
		geoReader = nil
	}
}

var GeoHTTPClient = &http.Client{Timeout: 5 * time.Minute}

const maxGeoDBDownloadBytes = 150 * 1024 * 1024

func DownloadGeoDB(url string) error {
	geoMu.RLock()
	client := GeoHTTPClient
	path := geoPath
	accountID := geoAccountID
	licenseKey := geoLicenseKey
	geoMu.RUnlock()
	geoUpdateMu.Lock()
	defer geoUpdateMu.Unlock()
	return downloadGeoDB(context.Background(), url, path, client, accountID, licenseKey)
}

func downloadGeoDB(ctx context.Context, url, path string, client *http.Client, accountID, licenseKey string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	// If license_key is not in the URL, try using Basic Auth
	if !strings.Contains(url, "license_key=") && accountID != "" && licenseKey != "" {
		req.SetBasicAuth(accountID, licenseKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// MaxMind often provides .tar.gz
	if strings.HasSuffix(url, ".tar.gz") {
		return extractTarGzTo(resp.Body, path)
	}

	// Preserve the live database if the update is interrupted or oversized.
	return writeFileAtomically(path, resp.Body, maxGeoDBDownloadBytes)
}

func extractTarGz(r io.Reader) error {
	geoMu.RLock()
	path := geoPath
	geoMu.RUnlock()
	geoUpdateMu.Lock()
	defer geoUpdateMu.Unlock()
	return extractTarGzTo(r, path)
}

func extractTarGzTo(r io.Reader, path string) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer func() {
		_ = gzr.Close()
	}()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Skip directories
		if header.Typeflag == tar.TypeDir {
			continue
		}

		// Look specifically for the City database filename
		if strings.HasSuffix(header.Name, "GeoLite2-City.mmdb") {
			if header.Size < 0 || header.Size > maxGeoDBDownloadBytes {
				return fmt.Errorf("GeoIP archive entry exceeds download limit")
			}
			return writeFileAtomically(path, tr, maxGeoDBDownloadBytes)
		}
	}
	return fmt.Errorf("mmdb file not found in archive")
}

// GeoAPIURL remains for source compatibility with older integrations. GeoIP
// lookups are local-only and never send targets to this URL.
var GeoAPIURL string

func GetGeoInfo(ctx context.Context, target string) (*GeoInfo, error) {
	return getGeoInfo(ctx, target, net.DefaultResolver.LookupIPAddr, lookupLocalGeo)
}

type geoResolverFunc func(context.Context, string) ([]net.IPAddr, error)
type geoLookupFunc func(net.IP) (*geoip2.City, error)

func getGeoInfo(ctx context.Context, target string, resolve geoResolverFunc, lookup geoLookupFunc) (*GeoInfo, error) {
	target = strings.TrimSpace(target)
	addresses, err := resolveGeoAddresses(ctx, target, resolve)
	if err != nil {
		return nil, err
	}

	var lookupErr error
	for _, address := range addresses {
		record, err := lookup(address.IP)
		if err != nil {
			lookupErr = err
			continue
		}
		if record == nil {
			lookupErr = errGeoRecordNotFound
			continue
		}

		regionName := ""
		if len(record.Subdivisions) > 0 {
			regionName = record.Subdivisions[0].Names["en"]
		}

		return &GeoInfo{
			Country:      record.Country.Names["en"],
			CountryCode:  record.Country.IsoCode,
			CountryEmoji: getFlagEmoji(record.Country.IsoCode),
			RegionName:   regionName,
			City:         record.City.Names["en"],
			Zip:          record.Postal.Code,
			Lat:          record.Location.Latitude,
			Lon:          record.Location.Longitude,
			Timezone:     record.Location.TimeZone,
			Status:       "success",
			Query:        target,
		}, nil
	}

	if lookupErr != nil {
		return nil, lookupErr
	}
	return nil, errGeoRecordNotFound
}

func resolveGeoAddresses(ctx context.Context, target string, resolve geoResolverFunc) ([]net.IPAddr, error) {
	if ip := net.ParseIP(target); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}

	addresses, err := resolve(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("resolve GeoIP target %q: %w", target, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolve GeoIP target %q: no addresses", target)
	}
	return addresses, nil
}

func lookupLocalGeo(ip net.IP) (*geoip2.City, error) {
	geoMu.RLock()
	defer geoMu.RUnlock()
	if geoReader == nil {
		return nil, errGeoDBUnavailable
	}
	record, err := geoReader.City(ip)
	if err != nil {
		return nil, err
	}
	if record.Country.IsoCode == "" && len(record.City.Names) == 0 && record.Location.TimeZone == "" {
		return nil, errGeoRecordNotFound
	}
	return record, nil
}
