package service

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/oschwald/geoip2-golang"
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

func GetGeoInfo(target string) (*GeoInfo, error) {
	// Try local lookup first
	if info, err := localGeoLookup(target); err == nil && info != nil {
		return info, nil
	}

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
	db, err := geoip2.Open("data/GeoLite2-City.mmdb")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	ip := net.ParseIP(target)
	record, err := db.City(ip)
	if err != nil {
		return nil, err
	}

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
