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
)

type GeoInfo struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Query       string  `json:"query"`
	Status      string  `json:"status"`
	Message     string  `json:"message,omitempty"`
}

func InitializeGeoDB(licenseKey, accountID string) {
	geoAccountID = accountID
	geoLicenseKey = licenseKey

	updateURL := ""
	if licenseKey != "" {
		updateURL = fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=%s&suffix=tar.gz", licenseKey)
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

	if geoAccountID != "" && geoLicenseKey != "" {
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

		if strings.HasSuffix(header.Name, ".mmdb") {
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
				Country:     record.Country.Names["en"],
				CountryCode: record.Country.IsoCode,
				City:        record.City.Names["en"],
				Lat:         record.Location.Latitude,
				Lon:         record.Location.Longitude,
				Timezone:    record.Location.TimeZone,
				Status:      "success",
				Query:       target,
			}, nil
		}
	}

	// Fallback to API
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query", target)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var info GeoInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}

	if info.Status == "fail" {
		return nil, fmt.Errorf("%s", info.Message)
	}

	return &info, nil
}
