package service

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

var (
	geoReader *geoip2.Reader
	geoMu     sync.RWMutex
	geoPath   = "data/GeoLite2-City.mmdb"
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

func InitializeGeoDB(updateURL string) {
	info, err := os.Stat(geoPath)
	shouldUpdate := false

	if os.IsNotExist(err) {
		fmt.Println("GeoIP database missing, downloading...")
		shouldUpdate = true
	} else if err == nil {
		// Check age - update if older than 72 hours
		if time.Since(info.ModTime()) > 72*time.Hour {
			fmt.Println("GeoIP database older than 72h, queueing update...")
			shouldUpdate = true
		}
	}

	if shouldUpdate && updateURL != "" {
		if err := DownloadGeoDB(updateURL); err != nil {
			fmt.Printf("Failed to update GeoIP DB: %v\n", err)
		}
	}

	ReloadGeoDB()

	// Start background watcher for 72h updates
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		for range ticker.C {
			if updateURL == "" {
				continue
			}
			if stat, err := os.Stat(geoPath); err == nil {
				if time.Since(stat.ModTime()) > 72*time.Hour {
					DownloadGeoDB(updateURL)
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
		geoReader.Close()
	}

	reader, err := geoip2.Open(geoPath)
	if err == nil {
		geoReader = reader
		fmt.Println("GeoIP database loaded successfully.")
	}
}

func DownloadGeoDB(url string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

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
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func extractTarGz(r io.Reader) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()

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
			out.Close()
			return err
		}
	}
	return fmt.Errorf("mmdb file not found in archive")
}

func GetGeoInfo(target string) (*GeoInfo, error) {
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
	
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var info GeoInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}

	if info.Status == "fail" {
		return nil, fmt.Errorf("%s", info.Message)
	}

	return &info, nil
}

func localGeoLookup(target string) (*GeoInfo, error) {
	// Obsolete but keeping for signature consistency if needed elsewhere
	return nil, fmt.Errorf("use GetGeoInfo")
}
