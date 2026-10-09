package service

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"whois/internal/model"
	"whois/internal/storage"
	"whois/internal/utils"

	"github.com/alicebob/miniredis/v2"
	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

func init() {
	utils.TestInitLogger()
}

func setupMiniredisStorage(t *testing.T) *storage.Storage {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return &storage.Storage{Client: client}
}

type mockDNS struct{}

func (m *mockDNS) LookupDetailed(ctx context.Context, target string, isIP bool) (map[string]interface{}, model.DNSDetails, error) {
	if isIP {
		return map[string]interface{}{"PTR": []string{"host.example.test"}}, completeDNSDetails(true), nil
	}
	return map[string]interface{}{"A": []string{"1.2.3.4"}}, completeDNSDetails(false), nil
}

func completeDNSDetails(isIP bool) model.DNSDetails {
	if isIP {
		return model.DNSDetails{"PTR": {Status: "answer"}}
	}
	details := model.DNSDetails{"DMARC": {Status: "nodata"}}
	for _, qtype := range dnsProfileTypes {
		details[dns.TypeToString[qtype]] = model.DNSQueryDetail{Status: "nodata"}
	}
	details["A"] = model.DNSQueryDetail{Status: "answer"}
	return details
}

func TestMonitorService(t *testing.T) {
	s := setupMiniredisStorage(t)
	ctx := context.Background()

	m := &MonitorService{
		Storage: s,
		DNS:     &mockDNS{},
	}
	m.RunCheck(ctx, "example.com")

	// Check if history was added
	history, err := s.GetDNSHistory(ctx, "example.com")
	if err != nil || len(history) == 0 {
		t.Errorf("Monitor check did not add history: %v", err)
	}
}

func TestMonitorService_IP(t *testing.T) {
	s := setupMiniredisStorage(t)
	ctx := context.Background()

	m := &MonitorService{
		Storage: s,
		DNS:     &mockDNS{},
	}
	target := "8.8.8.8"
	m.RunCheck(ctx, target)

	// Check if history was added for IP
	history, err := s.GetDNSHistory(ctx, target)
	if err != nil || len(history) == 0 {
		t.Errorf("Monitor check did not add history for IP: %v", err)
	}
}

func TestMonitorService_ErrorPaths(t *testing.T) {
	s := setupMiniredisStorage(t)
	ctx := context.Background()

	m := &MonitorService{
		Storage: s,
		DNS:     &mockDNS{},
	}

	t.Run("Invalid Target", func(t *testing.T) {
		m.RunCheck(ctx, "invalid..domain")
	})

	t.Run("Storage Error", func(t *testing.T) {
		m.RunCheck(ctx, "google.com")
	})
}

func TestMonitorServicePartialFailurePreservesHistory(t *testing.T) {
	var failAAAA atomic.Bool
	resolver := startMockDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		question := request.Question[0]
		hdr := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 60}
		switch question.Qtype {
		case dns.TypeA:
			reply.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.ParseIP("192.0.2.1")}}
		case dns.TypeAAAA:
			if failAAAA.Load() {
				reply.Rcode = dns.RcodeServerFailure
			} else {
				reply.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.ParseIP("2001:db8::1")}}
			}
		}
		_ = w.WriteMsg(reply)
	}), "udp")
	store := setupMiniredisStorage(t)
	monitor := NewMonitorService(store, resolver, "")
	monitor.RunCheck(context.Background(), "history.example.test")
	failAAAA.Store(true)
	monitor.RunCheck(context.Background(), "history.example.test")
	history, diffs, err := store.GetHistoryWithDiffs(context.Background(), "history.example.test")
	if err != nil || len(history) != 1 || len(diffs) != 0 || !strings.Contains(history[0].Result, "AAAA") {
		t.Fatalf("partial monitored failure became record removal: history=%+v diffs=%v error=%v", history, diffs, err)
	}
}

func TestDNSProfileCompleteRequiresEveryRequestedType(t *testing.T) {
	if !DNSProfileComplete(completeDNSDetails(false), false) || !DNSProfileComplete(completeDNSDetails(true), true) {
		t.Fatal("complete domain/PTR evidence was rejected")
	}
	for _, missing := range []string{"A", "AAAA", "DMARC", "DNSKEY"} {
		t.Run(missing, func(t *testing.T) {
			details := completeDNSDetails(false)
			delete(details, missing)
			if DNSProfileComplete(details, false) {
				t.Fatalf("profile missing %s accepted as complete", missing)
			}
			details["UNREQUESTED"] = model.DNSQueryDetail{Status: "answer"}
			if DNSProfileComplete(details, false) {
				t.Fatalf("unrequested result hid missing %s query", missing)
			}
		})
	}
	if DNSProfileComplete(nil, false) || DNSProfileComplete(completeDNSDetails(false), true) || DNSProfileComplete(completeDNSDetails(true), false) {
		t.Fatal("missing or wrong-profile evidence accepted")
	}
}
