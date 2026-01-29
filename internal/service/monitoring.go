package service

import (
	"context"
	"net"
	"sync"
	"whois/internal/model"
	"whois/internal/storage"
	"whois/internal/utils"
)

type MonitorService struct {
	Storage *storage.Storage
	DNS     *DNSService
}

func NewMonitorService(s *storage.Storage, resolvers string, bootstrap string) *MonitorService {
	return &MonitorService{
		Storage: s,
		DNS:     NewDNSService(resolvers, bootstrap),
	}
}

func (m *MonitorService) RunCheck(ctx context.Context, item string) {
	utils.Log.Info("running scheduled check", utils.Field("item", item))

	isIP := net.ParseIP(item) != nil
	res := model.QueryResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	// WHOIS
	wg.Add(1)
	go func() {
		defer wg.Done()
		w := Whois(item)
		mu.Lock()
		res.Whois = w
		mu.Unlock()
	}()

	// DNS
	wg.Add(1)
	go func() {
		defer wg.Done()
		d, err := m.DNS.Lookup(ctx, item, isIP)
		if err == nil {
			mu.Lock()
			res.DNS = d
			mu.Unlock()
			_ = m.Storage.AddDNSHistory(ctx, item, d)
		}
	}()

	// CT
	if !isIP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := FetchCTSubdomains(ctx, item)
			if err == nil {
				mu.Lock()
				res.CT = c
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	utils.Log.Info("finished check", utils.Field("item", item))
}
