package handler

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"whois/internal/config"
	"whois/internal/service"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

func startDNSDetailsFixture(t *testing.T, handler dns.Handler) string {
	t.Helper()
	packets, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	server := &dns.Server{PacketConn: packets, Handler: handler, NotifyStartedFunc: func() { close(ready) }}
	go func() { _ = server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = server.Shutdown() })
	return packets.LocalAddr().String()
}

func useLocalTargetEnrichment(t *testing.T) {
	t.Helper()
	resolver := startDNSDetailsFixture(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		_ = w.WriteMsg(reply)
	}))
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, resolver)
	}}
	t.Cleanup(func() { net.DefaultResolver = previous })
}

func TestQueryItemDNSCacheUsesEvidenceTTL(t *testing.T) {
	useLocalTargetEnrichment(t)
	for _, tc := range []struct {
		name       string
		positive   uint32
		negative   uint32
		partial    bool
		unknownTTL bool
		wantCache  bool
	}{
		{name: "positive and negative TTL", positive: 60, negative: 10, wantCache: true},
		{name: "zero positive TTL", positive: 0, negative: 10},
		{name: "zero negative TTL", positive: 60, negative: 0},
		{name: "unknown negative TTL", positive: 60, unknownTTL: true},
		{name: "partial failure", positive: 60, negative: 10, partial: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var queries atomic.Int64
			resolver := startDNSDetailsFixture(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
				queries.Add(1)
				reply := new(dns.Msg)
				reply.SetReply(request)
				question := request.Question[0]
				if question.Qtype == dns.TypeA {
					reply.Answer = []dns.RR{&dns.A{
						Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: tc.positive},
						A:   net.ParseIP("192.0.2.10"),
					}}
				} else if tc.partial && question.Qtype == dns.TypeAAAA {
					reply.Rcode = dns.RcodeServerFailure
				} else if !tc.unknownTTL {
					reply.Ns = []dns.RR{&dns.SOA{
						Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
						Ns:  "ns.example.test.", Mbox: "admin.example.test.", Minttl: tc.negative,
					}}
				}
				_ = w.WriteMsg(reply)
			}))
			store := setupMiniredisStorage(t)
			h := NewHandler(store, &config.Config{MaxTargetConcurrency: 1, MaxServiceConcurrency: 1})
			h.DNS = service.NewDNSService(resolver, "")
			first := h.queryItem(context.Background(), "evidence.example.test", true, false, false, false, false, false)
			if len(first.DNSDetails) != 12 || first.DNS["A"] == nil || first.DNS["error"] != nil {
				t.Fatalf("query evidence/legacy result = %+v", first)
			}
			before := queries.Load()
			second := h.queryItem(context.Background(), "evidence.example.test", true, false, false, false, false, false)
			if (queries.Load() == before) != tc.wantCache {
				t.Fatalf("query count before/after = %d/%d, want cache %v", before, queries.Load(), tc.wantCache)
			}
			if len(second.DNSDetails) != 12 || second.DNS["A"] == nil {
				t.Fatalf("second response lost data/evidence: %+v", second)
			}
			if tc.wantCache {
				key := "query:evidence.example.test:true:false:false:false:false:false"
				ttl, err := store.Client.(*redis.Client).TTL(context.Background(), key).Result()
				if err != nil || ttl <= 0 || ttl > 10*time.Second {
					t.Fatalf("stored TTL = %v, error=%v; want bounded by 10s negative TTL", ttl, err)
				}
			}
		})
	}
}

func TestHandleWSDNSDetailsPreservesPartialRecordSnapshot(t *testing.T) {
	useLocalTargetEnrichment(t)
	resolver := startDNSDetailsFixture(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		question := request.Question[0]
		if question.Qtype == dns.TypeA {
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")}}
		} else if question.Qtype == dns.TypeAAAA {
			reply.Rcode = dns.RcodeServerFailure
		}
		_ = w.WriteMsg(reply)
	}))
	h := NewHandler(setupMiniredisStorage(t), &config.Config{EnableDNS: true})
	h.DNS = service.NewDNSService(resolver, "")
	ws := dialHandlerWebSocket(t, h)
	if err := ws.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := ws.WriteJSON(map[string]interface{}{"targets": []string{"evidence.example.test"}, "config": map[string]bool{"dns": true}}); err != nil {
		t.Fatal(err)
	}
	var last WSMessage
	for {
		var message WSMessage
		if err := ws.ReadJSON(&message); err != nil {
			t.Fatal(err)
		}
		if message.Type == "result" && message.Service == "dns" {
			last = message
			data := message.Data.(map[string]interface{})
			if data["dns_details"] != nil {
				t.Fatal("metadata inserted into legacy record map")
			}
			if _, hasA := message.DNSDetails["A"]; hasA && data["A"] == nil {
				t.Fatalf("evidence snapshot lost the corresponding A array: %+v", message)
			}
		}
		if message.Type == "done" && message.Service == "dns" {
			break
		}
	}
	if len(last.DNSDetails) != 12 || last.DNSDetails["AAAA"].Status != "error" || last.DNSDetails["A"].Status != "answer" || last.Data.(map[string]interface{})["A"] == nil {
		t.Fatalf("final partial DNS snapshot = %+v", last)
	}
}

func TestQueryItemKeepsDNSRecordsReturnedWithCancellation(t *testing.T) {
	useLocalTargetEnrichment(t)
	previous := service.DNSLookupFunc
	service.DNSLookupFunc = func(context.Context, string, bool) (map[string]interface{}, error) {
		return map[string]interface{}{"A": []string{"192.0.2.1"}}, context.Canceled
	}
	t.Cleanup(func() { service.DNSLookupFunc = previous })
	h := NewHandler(setupMiniredisStorage(t), &config.Config{})
	result := h.queryItem(context.Background(), "evidence.example.test", true, false, false, false, false, false)
	if result.DNS["A"] == nil || result.DNS["error"] != context.Canceled.Error() {
		t.Fatalf("partial DNS records lost on cancellation: %+v", result.DNS)
	}
}
