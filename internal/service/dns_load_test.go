//go:build stress

package service

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"whois/internal/utils"

	"github.com/miekg/dns"
)

// TestStressDNSLoad10000 uses real loopback UDP, TCP and HTTP DNS transports, never
// public resolvers. Each of the ten cases runs 1,000 times with 32 workers.
func TestStressDNSLoad10000(t *testing.T) {
	const queries, workers = 10000, 32
	var udpQueries, tcpQueries, dohQueries, failedResolverQueries atomic.Int64
	answer := func(request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		question := request.Question[0]
		if strings.HasPrefix(question.Name, "missing-") {
			response.Rcode = dns.RcodeNameError
			return response
		}
		hdr := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 60}
		switch question.Qtype {
		case dns.TypeA, dns.TypeAAAA:
			if strings.HasPrefix(question.Name, "alias-") {
				response.Answer = append(response.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: question.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
					Target: "canonical.example.test.",
				})
				hdr.Name = "canonical.example.test."
			}
			if question.Qtype == dns.TypeA {
				response.Answer = append(response.Answer, &dns.A{Hdr: hdr, A: net.ParseIP("192.0.2.10")})
			} else {
				response.Answer = append(response.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.ParseIP("2001:db8::10")})
			}
		case dns.TypeCNAME:
			response.Answer = []dns.RR{&dns.CNAME{Hdr: hdr, Target: "canonical.example.test."}}
		case dns.TypeTXT:
			response.Answer = []dns.RR{&dns.TXT{Hdr: hdr, Txt: []string{"v=spf1 ", "-all"}}}
		case dns.TypeMX:
			response.Answer = []dns.RR{&dns.MX{Hdr: hdr, Preference: 10, Mx: "mail.example.test."}}
		case dns.TypePTR:
			response.Answer = []dns.RR{&dns.PTR{Hdr: hdr, Ptr: "host.example.test."}}
		}
		return response
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := answer(request)
		if w.RemoteAddr().Network() == "udp" {
			udpQueries.Add(1)
			if strings.HasPrefix(request.Question[0].Name, "truncated-") {
				response.Answer = nil
				response.Truncated = true
			}
		} else {
			tcpQueries.Add(1)
		}
		_ = w.WriteMsg(response)
	})
	tcpListener, packetConn, resolver := listenTCPAndUDP(t)
	for _, server := range []*dns.Server{
		{PacketConn: packetConn, Handler: handler},
		{Listener: tcpListener, Handler: handler},
	} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		go func() { _ = server.ActivateAndServe() }()
		<-ready
		t.Cleanup(func() { _ = server.Shutdown() })
	}
	failing := startMockDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		failedResolverQueries.Add(1)
		response := new(dns.Msg)
		response.SetRcode(request, dns.RcodeServerFailure)
		_ = w.WriteMsg(response)
	}), "udp")
	doh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dohQueries.Add(1)
		body, err := io.ReadAll(r.Body)
		request := new(dns.Msg)
		if err != nil || request.Unpack(body) != nil {
			http.Error(w, "invalid DNS message", http.StatusBadRequest)
			return
		}
		wire, err := answer(request).Pack()
		if err != nil {
			http.Error(w, "invalid DNS answer", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	t.Cleanup(doh.Close)
	udpService := NewDNSService(resolver, "")
	dohService := NewDNSService(doh.URL, "")
	t.Cleanup(dohService.httpClient.CloseIdleConnections)

	latencies := make([]time.Duration, queries)
	var completed atomic.Int64
	var mismatches atomic.Int64
	var firstFailure string
	var firstFailureOnce sync.Once
	var wg sync.WaitGroup
	start := time.Now()
	for worker := range workers {
		wg.Go(func() {
			for i := worker; i < queries; i += workers {
				service := udpService
				target := fmt.Sprintf("host-%d.example.test", i)
				recordType, want, isIP := "A", "192.0.2.10", false
				switch i % 10 {
				case 0:
					target = "alias-" + target
				case 1:
					target = "alias-" + target
					recordType, want = "AAAA", "2001:db8::10"
				case 2:
					service, recordType, want = dohService, "TXT", "v=spf1 -all"
				case 3:
					service, recordType, want = dohService, "MX", "10 mail.example.test"
				case 4:
					target = fmt.Sprintf("192.0.%d.%d", i/256%256, i%256)
					recordType, want, isIP = "PTR", "host.example.test", true
				case 5:
					target = fmt.Sprintf("2001:db8::%x", i)
					recordType, want, isIP = "PTR", "host.example.test", true
				case 6:
					recordType, want = "CNAME", "canonical.example.test"
				case 7:
					target, want = "missing-"+target, ""
				case 8:
					// A fresh instance keeps every case exercising actual failover,
					// independently of health-based resolver rotation.
					service = NewDNSService(failing+","+resolver, "")
				case 9:
					target = "truncated-" + target
				}
				queryStart := time.Now()
				info := utils.NormalizeTarget(target)
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				got, err := service.LookupType(ctx, info.Host, recordType, isIP)
				cancel()
				latencies[i] = time.Since(queryStart)
				valid := len(got) == 1 && got[0] == want
				if want == "" {
					valid = len(got) == 0
				}
				if !info.Valid || err != nil || !valid {
					mismatches.Add(1)
					firstFailureOnce.Do(func() {
						firstFailure = fmt.Sprintf("query %d: target=%q type=%s result=%v err=%v want=%q valid=%v", i, target, recordType, got, err, want, info.Valid)
					})
				}
				completed.Add(1)
			}
		})
	}
	wg.Wait()
	elapsed := time.Since(start)
	slices.Sort(latencies)
	t.Logf("queries=%d workers=%d mismatches=%d elapsed=%s throughput=%.0f queries/s p50=%s p95=%s p99=%s UDP=%d TCP=%d DoH=%d SERVFAIL=%d",
		completed.Load(), workers, mismatches.Load(), elapsed, float64(queries)/elapsed.Seconds(),
		latencies[queries/2], latencies[queries*95/100], latencies[queries*99/100],
		udpQueries.Load(), tcpQueries.Load(), dohQueries.Load(), failedResolverQueries.Load())
	if mismatches.Load() != 0 {
		t.Errorf("%d unexpected query results; first: %s", mismatches.Load(), firstFailure)
	}
	if udpQueries.Load() != 8000 || tcpQueries.Load() != 1000 || dohQueries.Load() != 2000 || failedResolverQueries.Load() != 1000 {
		t.Error("transport counts do not match the workload; expected UDP=8000 TCP=1000 DoH=2000 SERVFAIL=1000")
	}
}
