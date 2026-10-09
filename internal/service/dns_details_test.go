package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"whois/internal/model"

	"github.com/miekg/dns"
)

func evidenceRR(t *testing.T, text string) dns.RR {
	t.Helper()
	record, err := dns.NewRR(text)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestDNSDetailsDistinguishAnswersAndNegativeResponses(t *testing.T) {
	soa := evidenceRR(t, "example.test. 90 IN SOA ns.example.test. admin.example.test. 1 60 60 60 30")
	alias := evidenceRR(t, "alias.example.test. 15 IN CNAME missing.example.test.")
	ns := evidenceRR(t, "example.test. 90 IN NS ns.example.test.")
	zero := evidenceRR(t, "answer.example.test. 0 IN A 192.0.2.1")
	positive := evidenceRR(t, "answer.example.test. 120 IN A 192.0.2.2")
	resolver := startMockDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		switch request.Question[0].Name {
		case "answer.example.test.":
			reply.Answer = []dns.RR{zero, positive}
		case "missing.example.test.":
			reply.Rcode, reply.Ns = dns.RcodeNameError, []dns.RR{soa}
		case "alias.example.test.":
			reply.Rcode, reply.Answer, reply.Ns = dns.RcodeNameError, []dns.RR{alias}, []dns.RR{soa}
		case "nodata.example.test.":
			reply.Ns = []dns.RR{soa, ns}
		case "referral.example.test.":
			reply.Ns = []dns.RR{ns}
		case "failed.example.test.":
			reply.Rcode = dns.RcodeServerFailure
		case "contradictory.example.test.":
			reply.Rcode, reply.Answer = dns.RcodeNameError, []dns.RR{positive}
		}
		_ = w.WriteMsg(reply)
	}), "udp")

	for _, tc := range []struct {
		name, status, rcode string
		records, aliases    int
		negativeTTL         bool
		wantError           bool
	}{
		{"answer", "answer", "NOERROR", 2, 0, false, false},
		{"missing", "nxdomain", "NXDOMAIN", 0, 0, true, false},
		{"alias", "nxdomain", "NXDOMAIN", 0, 1, true, false},
		{"nodata", "nodata", "NOERROR", 0, 0, true, false},
		{"empty", "nodata", "NOERROR", 0, 0, false, false},
		{"referral", "error", "NOERROR", 0, 0, false, true},
		{"failed", "error", "SERVFAIL", 0, 0, false, true},
		{"contradictory", "error", "NXDOMAIN", 0, 0, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := NewDNSService(resolver, "")
			before := time.Now()
			detail, err := service.LookupTypeDetailed(context.Background(), tc.name+".example.test", "A", false)
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, want error %v", err, tc.wantError)
			}
			if detail.Status != tc.status || detail.Rcode != tc.rcode || len(detail.Records) != tc.records || len(detail.Aliases) != tc.aliases {
				t.Fatalf("unexpected detail: %+v", detail)
			}
			if detail.QueryName != tc.name+".example.test." || detail.QueryType != "A" || detail.Resolver != resolver || detail.Transport != "udp" {
				t.Fatalf("incorrect query provenance: %+v", detail)
			}
			if detail.ObservedAt.Before(before) || detail.ObservedAt.After(time.Now()) {
				t.Fatalf("observation time = %v", detail.ObservedAt)
			}
			if tc.negativeTTL && (detail.NegativeTTL == nil || *detail.NegativeTTL != 30) {
				t.Fatalf("negative TTL = %v, want 30", detail.NegativeTTL)
			}
			if !tc.negativeTTL && detail.NegativeTTL != nil {
				t.Fatalf("unexpected negative TTL: %v", *detail.NegativeTTL)
			}
			if tc.wantError && detail.Error == "" {
				t.Fatal("failure has no explanation")
			}
			if tc.name == "answer" {
				if detail.Records[0].TTL != 0 || detail.Records[1].TTL != 120 || detail.Records[0].Name != "answer.example.test." {
					t.Fatalf("record TTL/name lost: %+v", detail.Records)
				}
				encoded, _ := json.Marshal(detail)
				if !strings.Contains(string(encoded), `"ttl":0`) {
					t.Fatalf("zero TTL omitted: %s", encoded)
				}
			}
		})
	}
}

func TestDNSDetailsStreamRetainsEveryOutcomeAndLegacyRecords(t *testing.T) {
	answer := evidenceRR(t, "example.test. 60 IN A 192.0.2.1")
	resolver := startMockDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		switch request.Question[0].Qtype {
		case dns.TypeA:
			reply.Answer = []dns.RR{answer}
		case dns.TypeAAAA:
			reply.Rcode = dns.RcodeServerFailure
		}
		_ = w.WriteMsg(reply)
	}), "udp")
	service := NewDNSService(resolver, "")
	records, details, err := service.LookupDetailed(context.Background(), "example.test", false)
	if err != nil || len(records) != 1 || len(details) != 12 {
		t.Fatalf("records=%v, details=%d, error=%v", records, len(details), err)
	}
	if details["A"].Status != "answer" || details["AAAA"].Status != "error" || details["MX"].Status != "nodata" {
		t.Fatalf("partial failure lost: %+v", details)
	}
	if details["DMARC"].QueryName != "_dmarc.example.test." || details["DMARC"].QueryType != "TXT" {
		t.Fatalf("DMARC query provenance = %+v", details["DMARC"])
	}
	legacy, err := service.Lookup(context.Background(), "example.test", false)
	if err != nil || len(legacy) != 1 || legacy["A"].([]string)[0] != "192.0.2.1" {
		t.Fatalf("legacy lookup changed: %v, %v", legacy, err)
	}
}

func TestDNSDetailsCancellationIncludesUnstartedQueries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	service := NewDNSService("127.0.0.1:1", "")
	var mu sync.Mutex
	details := make(model.DNSDetails)
	err := service.LookupStreamDetailed(ctx, "example.test", false, func(name string, detail model.DNSQueryDetail) {
		mu.Lock()
		defer mu.Unlock()
		details[name] = detail
	})
	if !errors.Is(err, context.Canceled) || len(details) != 12 {
		t.Fatalf("error=%v details=%d, want cancellation and 12 outcomes", err, len(details))
	}
	for name, detail := range details {
		if detail.Status != "error" || detail.Error == "" || detail.QueryName == "" || detail.QueryType == "" || detail.Resolver != "" {
			t.Errorf("%s cancellation detail = %+v", name, detail)
		}
	}
}

func TestDNSDetailsDoHAndFailoverProvenance(t *testing.T) {
	answer := evidenceRR(t, "example.test. 60 IN A 192.0.2.1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, _ := io.ReadAll(r.Body)
		request := new(dns.Msg)
		_ = request.Unpack(wire)
		reply := new(dns.Msg)
		reply.SetReply(request)
		reply.Answer = []dns.RR{answer}
		wire, _ = reply.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	t.Cleanup(server.Close)
	failing := startMockDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	}), "udp")
	service := NewDNSService(failing+","+server.URL, "")
	detail, err := service.LookupTypeDetailed(context.Background(), "example.test", "A", false)
	if err != nil || detail.Resolver != server.URL || detail.Transport != "doh" || detail.Status != "answer" {
		t.Fatalf("winning provenance = %+v, error=%v", detail, err)
	}
}

func TestDNSCacheTTLUsesEveryOutcomeAndObservationTime(t *testing.T) {
	now := time.Now()
	negativeTTL := uint32(30)
	for _, tc := range []struct {
		name   string
		detail model.DNSQueryDetail
		want   time.Duration
	}{
		{"answer", model.DNSQueryDetail{Status: "answer", Records: []model.DNSRecord{{TTL: 60}}}, 40 * time.Second},
		{"multiple records", model.DNSQueryDetail{Status: "answer", Records: []model.DNSRecord{{TTL: 60}, {TTL: 25}}}, 5 * time.Second},
		{"zero TTL", model.DNSQueryDetail{Status: "answer", Records: []model.DNSRecord{{TTL: 0}}}, 0},
		{"negative", model.DNSQueryDetail{Status: "nxdomain", NegativeTTL: &negativeTTL}, 10 * time.Second},
		{"unknown negative TTL", model.DNSQueryDetail{Status: "nodata"}, 0},
		{"failure", model.DNSQueryDetail{Status: "error"}, 0},
		{"expired alias", model.DNSQueryDetail{Status: "answer", Records: []model.DNSRecord{{TTL: 60}}, Aliases: []model.DNSRecord{{TTL: 10}}}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.detail.ObservedAt = now.Add(-20 * time.Second)
			details := model.DNSDetails{"A": tc.detail, "AAAA": {Status: "answer", ObservedAt: now, Records: []model.DNSRecord{{TTL: 300}}}}
			if got := DNSCacheTTL(details, now, 10*time.Minute); got != tc.want {
				t.Fatalf("cache TTL = %v, want %v", got, tc.want)
			}
		})
	}
	if got := DNSCacheTTL(nil, now, 10*time.Minute); got != 0 {
		t.Fatalf("missing evidence cache TTL = %v", got)
	}
}

func TestDNSDetailsTCPFallbackAndReverseNames(t *testing.T) {
	listener, packets, resolver := listenTCPAndUDP(t)
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		if w.RemoteAddr().Network() == "udp" {
			reply.Truncated = true
		} else {
			reply.Answer = []dns.RR{&dns.PTR{
				Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 45},
				Ptr: "host.example.test.",
			}}
		}
		_ = w.WriteMsg(reply)
	})
	for _, server := range []*dns.Server{{Listener: listener, Handler: handler}, {PacketConn: packets, Handler: handler}} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		go func() { _ = server.ActivateAndServe() }()
		<-ready
		t.Cleanup(func() { _ = server.Shutdown() })
	}
	service := NewDNSService(resolver, "")
	for _, address := range []string{"192.0.2.1", "2001:db8::1"} {
		name, _ := dns.ReverseAddr(address)
		detail, err := service.LookupTypeDetailed(context.Background(), address, "PTR", true)
		if err != nil || detail.Transport != "tcp" || detail.QueryName != name || detail.QueryType != "PTR" || len(detail.Records) != 1 {
			t.Fatalf("reverse evidence = %+v, error=%v", detail, err)
		}
		if detail.Records[0].Name != name || detail.Records[0].TTL != 45 || detail.Records[0].Value != "host.example.test" {
			t.Fatalf("reverse record = %+v", detail.Records[0])
		}
	}
}

func TestDNSDetailsDeadlineRetainsFailureProvenance(t *testing.T) {
	resolver := startMockDNSServer(t, dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {}), "udp")
	service := NewDNSService(resolver, "")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	detail, err := service.LookupTypeDetailed(ctx, "example.test", "A", false)
	if !errors.Is(err, context.DeadlineExceeded) || detail.Status != "error" || detail.Error == "" || detail.Rcode != "" || detail.Resolver != resolver || detail.Transport != "udp" {
		t.Fatalf("deadline evidence = %+v, error=%v", detail, err)
	}
}

// A deadline can expire in the network poller before the context timer runs.
// This context deterministically reproduces that scheduling gap: the deadline
// is visible to the socket while Err still reports no cancellation.
type pendingDNSDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (c pendingDNSDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestDNSDetailsDeadlineDoesNotDependOnContextTimer(t *testing.T) {
	resolver := startMockDNSServer(t, dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {}), "udp")
	service := NewDNSService(resolver, "")
	ctx := pendingDNSDeadlineContext{Context: context.Background(), deadline: time.Now().Add(20 * time.Millisecond)}
	detail, err := service.LookupTypeDetailed(ctx, "example.test", "A", false)
	if !errors.Is(err, context.DeadlineExceeded) || detail.Status != "error" {
		t.Fatalf("socket deadline evidence = %+v, error=%v", detail, err)
	}
	if service.failures[resolver] != 0 {
		t.Fatalf("caller deadline penalized resolver: %d failures", service.failures[resolver])
	}
}
