package service

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
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
	geoReader     *geoip2.Reader
	geoMu         sync.RWMutex
	geoPath       = "data/GeoLite2-City.mmdb"
	geoAccountID  string
	geoLicenseKey string
	GeoTestMode   = false
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
	geoAccountID = accountID
	geoLicenseKey = licenseKey

	// Ensure data directory exists
	_ = os.MkdirAll("data", 0755)

	updateURL := ""
	if licenseKey != "" {
		// Using the direct download URL for GeoLite2-City
		updateURL = fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=%s&suffix=tar.gz", licenseKey)
	} else {
		// Fallback to a common public mirror if no key is provided (behavior like rauth)
		updateURL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
	}

	_, err := os.Stat(geoPath)
	shouldUpdate := false

	if os.IsNotExist(err) {
		utils.Log.Info("GeoIP database missing, downloading...")
		shouldUpdate = true
	}

	if shouldUpdate && updateURL != "" {
		if err := DownloadGeoDB(updateURL); err != nil {
			utils.Log.Error("failed to download GeoIP DB", utils.Field("error", err.Error()))
		}
	}

	ReloadGeoDB()

	if GeoTestMode {
		return
	}

	// Start background watcher for 72h updates
	go func() {
		ticker := time.NewTicker(6 * time.Hour) // Check every 6h instead of 1h to be more efficient
		for range ticker.C {
			if updateURL == "" {
				continue
			}
			if stat, err := os.Stat(geoPath); err == nil {
				if time.Since(stat.ModTime()) > 72*time.Hour {
					utils.Log.Info("GeoIP database older than 72h, performing periodic update...")
					_ = DownloadGeoDB(updateURL)
					ReloadGeoDB()
				}
			}
		}
	}()
}

func ManualUpdateGeoDB() error {
	if geoLicenseKey == "" {
		return fmt.Errorf("MAXMIND_LICENSE_KEY is not set")
	}
	url := fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=%s&suffix=tar.gz", geoLicenseKey)
	err := DownloadGeoDB(url)
	if err == nil {
		ReloadGeoDB()
	}
	return err
}

func ReloadGeoDB() {
	geoMu.Lock()
	defer geoMu.Unlock()

	if geoReader != nil {
		_ = geoReader.Close()
	}

	reader, err := geoip2.Open(geoPath)
	if err == nil {
		geoReader = reader
		utils.Log.Info("GeoIP database loaded successfully.")
	}
}

func DownloadGeoDB(url string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	// If license_key is not in the URL, try using Basic Auth
	if !strings.Contains(url, "license_key=") && geoAccountID != "" && geoLicenseKey != "" {
		req.SetBasicAuth(geoAccountID, geoLicenseKey)
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
		return extractTarGz(resp.Body)
	}

	// Assume direct .mmdb if not tar.gz
	out, err := os.Create(geoPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = out.Close()
	}()
	_, err = io.Copy(out, resp.Body)
	return err
}

func extractTarGz(r io.Reader) error {
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
			out, err := os.Create(geoPath)
			if err != nil {
				return err
			}
			_, err = io.Copy(out, tr)
			_ = out.Close()
			return err
		}
	}
	return fmt.Errorf("mmdb file not found in archive")
}

func GetGeoInfo(ctx context.Context, target string) (*GeoInfo, error) {
	geoMu.RLock()
	reader := geoReader
	geoMu.RUnlock()

	if reader != nil {
		ip := net.ParseIP(target)
		record, err := reader.City(ip)
		if err == nil {
			return &GeoInfo{
				Country:      record.Country.Names["en"],
				CountryCode:  record.Country.IsoCode,
				CountryEmoji: getFlagEmoji(record.Country.IsoCode),
				City:         record.City.Names["en"],
				Lat:          record.Location.Latitude,
				Lon:          record.Location.Longitude,
				Timezone:     record.Location.TimeZone,
				Status:       "success",
				Query:        target,
			}, nil
		}
...
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}

	info.CountryEmoji = getFlagEmoji(info.CountryCode)

	if info.Status == "fail" {
		return nil, fmt.Errorf("%s", info.Message)
	}

	return &info, nil
}
