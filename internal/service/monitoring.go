package service

import (
	"context"
	"log"
	"net"
	"sync"
	"whois/internal/model"
	"whois/internal/storage"
)

type MonitorService struct {
	Storage *storage.Storage
	DNS     *DNSService
}

func NewMonitorService(s *storage.Storage, resolver string) *MonitorService {
	return &MonitorService{
		Storage: s,
		DNS:     NewDNSService(resolver),
	}
}

func (m *MonitorService) RunCheck(ctx context.Context, item string) {
	log.Printf("[MONITOR] Running scheduled check for %s", item)

	isIP := net.ParseIP(item) != nil
	res := model.QueryResult{}
	var wg sync.WaitGroup

	// WHOIS
	wg.Add(1)
	go func() {
		defer wg.Done()
		w := Whois(item)
		res.Whois = &w
	}()

	// DNS
	wg.Add(1)
	go func() {
		defer wg.Done()
		d, err := m.DNS.Lookup(item, isIP)
		if err == nil {
			res.DNS = d
			_ = m.Storage.AddDNSHistory(ctx, item, d)
		}
	}()

	// CT
	if !isIP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := FetchCTSubdomains(item)
			if err == nil {
				res.CT = c
			}
		}()
	}

	wg.Wait()
	log.Printf("[MONITOR] Finished check for %s", item)
}
