package service

import (
	"context"
	"net"
	"whois/internal/storage"
	"whois/internal/utils"
)

type DNSInterface interface {
	Lookup(ctx context.Context, target string, isIP bool) (map[string]interface{}, error)
}

type MonitorService struct {
	Storage *storage.Storage
	DNS     DNSInterface
}

func NewMonitorService(s *storage.Storage, resolvers string, bootstrap string) *MonitorService {
	return &MonitorService{
		Storage: s,
		DNS:     NewDNSService(resolvers, bootstrap),
	}
}

func (m *MonitorService) RunCheck(ctx context.Context, item string) {
	if !utils.IsValidTarget(item) {
		utils.Log.Warn("invalid target for scheduled check", utils.Field("item", item))
		return
	}
	utils.Log.Info("running scheduled check", utils.Field("item", item))

	isIP := net.ParseIP(item) != nil
	dnsResult, err := m.DNS.Lookup(ctx, item, isIP)
	if err != nil {
		utils.Log.Warn("scheduled DNS check failed", utils.Field("item", item), utils.Field("error", err.Error()))
		return
	}
	if err := m.Storage.AddDNSHistory(ctx, item, dnsResult); err != nil {
		utils.Log.Error("failed to store scheduled DNS result", utils.Field("item", item), utils.Field("error", err.Error()))
		return
	}

	utils.Log.Info("finished check", utils.Field("item", item))
}
