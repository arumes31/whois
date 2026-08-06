package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"whois/internal/utils"

	"github.com/miekg/dns"
)

func init() {
	utils.TestInitLogger()
}

func startMockDNSServer(t *testing.T, handler dns.Handler, network string) string {
	if network == "udp" {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen on udp: %v", err)
		}
		server := &dns.Server{PacketConn: pc, Handler: handler}
		go func() { _ = server.ActivateAndServe() }()
		t.Cleanup(func() { _ = server.Shutdown() })
		return pc.LocalAddr().String()
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on tcp: %v", err)
	}
	server := &dns.Server{Listener: l, Handler: handler}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return l.Addr().String()
}

func listenTCPAndUDP(t *testing.T) (net.Listener, net.PacketConn, string) {
	t.Helper()
	var lastErr error
	const (
		firstPort = 10000
		portCount = 20000
	)
	start := int(time.Now().UnixNano() % portCount)
	for offset := range portCount {
		port := firstPort + (start+offset)%portCount
		resolverAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		tcpListener, err := net.Listen("tcp", resolverAddr)
		if err != nil {
			lastErr = err
			continue
		}
		packetConn, err := net.ListenPacket("udp", resolverAddr)
		if err == nil {
			return tcpListener, packetConn, resolverAddr
		}
		lastErr = err
		_ = tcpListener.Close()
	}
	t.Fatalf("listen on a shared TCP/UDP port after retries: %v", lastErr)
	return nil, nil, ""
}

func TestDNSService_Lookup(t *testing.T) {
	// Mock DNS server
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			})
		}
		if r.Question[0].Qtype == dns.TypePTR {
			m.Answer = append(m.Answer, &dns.PTR{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 300},
				Ptr: "google.com.",
			})
		}
		_ = w.WriteMsg(m)
	})

	addr := startMockDNSServer(t, handler, "udp")
	s := NewDNSService(addr, "")

	tests := []struct {
		name     string
		target   string
		isIP     bool
		expected []string
	}{
		{"Mock A", "example.com", false, []string{"A"}},
		{"Mock PTR", "8.8.8.8", true, []string{"PTR"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := s.Lookup(context.Background(), tt.target, tt.isIP)
			if err != nil {
				t.Fatalf("Lookup failed for %s: %v", tt.target, err)
			}
			for _, exp := range tt.expected {
				if _, ok := res[exp]; !ok {
					t.Errorf("Expected %s records for %s", exp, tt.target)
				}
			}
		})
	}

	// Test Invalid Domain
	_, err := s.Lookup(context.Background(), "invalid..domain", false)
	if err != nil {
		t.Logf("Got expected error for invalid domain: %v", err)
	}
}

func TestDNSService_DiscoverSubdomains(t *testing.T) {
	// Mock DNS server
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if strings.HasPrefix(r.Question[0].Name, "www.") {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			})
		}
		_ = w.WriteMsg(m)
	})

	addr := startMockDNSServer(t, handler, "udp")
	s := NewDNSService(addr, "")
	res := s.DiscoverSubdomains(context.Background(), "example.com", []string{"www"})

	if len(res) == 0 {
		t.Error("Expected to find www subdomain")
	}
}

func TestDNSService_LookupStream(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})
	addr := startMockDNSServer(t, handler, "udp")
	s := NewDNSService(addr, "")

	count := 0
	err := s.LookupStream(context.Background(), "google.com", false, func(rtype string, data interface{}) {
		count++
	})
	if err != nil {
		t.Errorf("LookupStream failed: %v", err)
	}

	// Test IP reverse
	count = 0
	_ = s.LookupStream(context.Background(), "8.8.8.8", true, func(rtype string, data interface{}) {
		count++
	})
}

func TestDNSService_LookupStreamDoesNotDiscoverSubdomains(t *testing.T) {
	var queryCount atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		queryCount.Add(1)
		response := new(dns.Msg)
		response.SetReply(request)
		_ = w.WriteMsg(response)
	})
	addr := startMockDNSServer(t, handler, "udp")
	service := NewDNSService(addr, "")
	service.SetMaxAttempts(1)

	if err := service.LookupStream(context.Background(), "example.com", false, func(string, interface{}) {}); err != nil {
		t.Fatalf("LookupStream failed: %v", err)
	}
	const recordQueries = 12 // Eleven standard record types plus DMARC.
	if got := queryCount.Load(); got != recordQueries {
		t.Fatalf("LookupStream made %d DNS queries, want %d without subdomain discovery", got, recordQueries)
	}
}

func TestDNSServiceLookupTypeQueriesOnlyRequestedType(t *testing.T) {
	var queryCount atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		queryCount.Add(1)
		response := new(dns.Msg)
		response.SetReply(request)
		if request.Question[0].Qtype == dns.TypeAAAA {
			response.Answer = append(response.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: net.ParseIP("2001:db8::1"),
			})
		}
		_ = w.WriteMsg(response)
	})
	addr := startMockDNSServer(t, handler, "udp")
	service := NewDNSService(addr, "")
	service.SetMaxAttempts(1)

	records, err := service.LookupType(context.Background(), "example.com", "aaaa", false)
	if err != nil {
		t.Fatalf("LookupType failed: %v", err)
	}
	if len(records) != 1 || records[0] != "2001:db8::1" {
		t.Fatalf("LookupType returned %v", records)
	}
	if got := queryCount.Load(); got != 1 {
		t.Fatalf("LookupType made %d queries, want 1", got)
	}
	if _, err := service.LookupType(context.Background(), "example.com", "BOGUS", false); err == nil {
		t.Fatal("LookupType accepted an unsupported record type")
	}
}

func TestDNSService_LookupStreamReturnsAggregateFailure(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetRcode(request, dns.RcodeServerFailure)
		_ = w.WriteMsg(response)
	})
	addr := startMockDNSServer(t, handler, "udp")
	service := NewDNSService(addr, "")
	service.SetMaxAttempts(1)

	err := service.LookupStream(context.Background(), "example.com", false, func(string, interface{}) {})
	if err == nil {
		t.Fatal("LookupStream returned nil after every resolver query failed")
	}
	if !strings.Contains(err.Error(), "A lookup") || !strings.Contains(err.Error(), "DMARC lookup") {
		t.Fatalf("aggregate error did not preserve individual lookup failures: %v", err)
	}
}

func TestDNSService_LookupStreamPreservesPartialResults(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		if request.Question[0].Qtype == dns.TypeA {
			response.SetReply(request)
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("203.0.113.10"),
			})
		} else {
			response.SetRcode(request, dns.RcodeServerFailure)
		}
		_ = w.WriteMsg(response)
	})
	addr := startMockDNSServer(t, handler, "udp")
	service := NewDNSService(addr, "")
	service.SetMaxAttempts(1)

	gotA := false
	err := service.LookupStream(context.Background(), "example.com", false, func(recordType string, _ interface{}) {
		if recordType == "A" {
			gotA = true
		}
	})
	if err != nil {
		t.Fatalf("LookupStream rejected a partial success: %v", err)
	}
	if !gotA {
		t.Fatal("LookupStream did not emit its successful A result")
	}
}

func TestDNSService_DiscoverSubdomainsStream(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})
	addr := startMockDNSServer(t, handler, "udp")
	s := NewDNSService(addr, "")

	custom := []string{"www"}
	err := s.DiscoverSubdomainsStream(context.Background(), "google.com", custom, func(fqdn string, res map[string][]string) {
		if !strings.HasPrefix(fqdn, "www.") {
			t.Errorf("Expected www prefix, got %s", fqdn)
		}
	})
	if err != nil {
		t.Errorf("DiscoverSubdomainsStream failed: %v", err)
	}
}

func TestDNSService_Query_Errors(t *testing.T) {
	t.Parallel()
	s := NewDNSService("1.2.3.4:53", "") // Non-existent resolver

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := s.query(ctx, "google.com", dns.TypeA, false)
	if err == nil {
		t.Error("Expected error for non-existent resolver")
	}

	_, err = s.query(ctx, "invalid-ip", dns.TypePTR, true)
	if err == nil {
		t.Error("Expected error for invalid IP in reverse query")
	}
}

func TestDNSServiceResolverFailover(t *testing.T) {
	failing := startMockDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetRcode(request, dns.RcodeServerFailure)
		_ = w.WriteMsg(response)
	}), "udp")
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("203.0.113.10"),
		})
		_ = w.WriteMsg(response)
	})
	healthy := startMockDNSServer(t, handler, "udp")
	service := NewDNSService(failing+","+healthy, "")
	service.SetMaxAttempts(2)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := service.query(ctx, "example.com", dns.TypeA, false)
	if err != nil {
		t.Fatalf("query did not fail over: %v", err)
	}
	if len(result) != 1 || result[0] != "203.0.113.10" {
		t.Fatalf("got %v", result)
	}
}

func TestDNSServiceCancellationDoesNotPenalizeResolver(t *testing.T) {
	service := NewDNSService("192.0.2.53:53", "")
	service.SetMaxAttempts(1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := service.query(ctx, "example.com", dns.TypeA, false)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("query error = %v; want context cancellation", err)
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if len(service.failures) != 0 {
		t.Fatalf("caller cancellation recorded resolver failures: %v", service.failures)
	}
	if len(service.unhealthyUntil) != 0 {
		t.Fatalf("caller cancellation degraded resolvers: %v", service.unhealthyUntil)
	}
}

func TestDNSService_Trace_Success(t *testing.T) {
	// Create a mock DNS server to simulate a referral
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)

		if r.Question[0].Name == "example.com." {
			// Simulate a referral to ns1.example.com
			ns := &dns.NS{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
				Ns:  "ns1.example.com.",
			}
			m.Ns = append(m.Ns, ns)

			// Add Glue record
			extra := &dns.A{
				Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
				A:   net.ParseIP("127.0.0.1"),
			}
			m.Extra = append(m.Extra, extra)
		}

		_ = w.WriteMsg(m)
	})

	addr := startMockDNSServer(t, handler, "udp")
	oldRoots := RootServers
	RootServers = []string{addr}
	defer func() { RootServers = oldRoots }()

	s := NewDNSService("", "")
	_, _ = s.Trace(context.Background(), "example.com")
}

func TestDNSService_Trace_ReferralNoGlue(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)

		if r.Question[0].Name == "example.com." {
			// Simulate a referral to ns1.example.com but NO glue
			ns := &dns.NS{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
				Ns:  "ns1.example.com.",
			}
			m.Ns = append(m.Ns, ns)
		}
		_ = w.WriteMsg(m)
	})

	addr := startMockDNSServer(t, handler, "udp")
	oldRoots := RootServers
	RootServers = []string{addr}
	defer func() { RootServers = oldRoots }()

	svc := NewDNSService("", "")
	_, _ = svc.Trace(context.Background(), "example.com")
}

func TestDNSService_Trace_ReferralNoGlue_Detailed(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Name == "example.com." {
			ns := &dns.NS{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
				Ns:  "ns1.example.com.",
			}
			m.Ns = append(m.Ns, ns)
			// NO glue in m.Extra
		}
		_ = w.WriteMsg(m)
	})

	resolver := startMockDNSServer(t, handler, "udp")

	oldRoots := RootServers
	RootServers = []string{resolver}
	defer func() { RootServers = oldRoots }()

	svc := NewDNSService("", "")
	res, _ := svc.Trace(context.Background(), "example.com")
	found := false
	for _, line := range res {
		if strings.Contains(line, "no glue, resolving") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'no glue, resolving' in trace results")
	}
}

func TestDNSService_DoH(t *testing.T) {
	// Mock DoH Server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/dns-message" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		msg := new(dns.Msg)
		if err := msg.Unpack(body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Create response
		reply := new(dns.Msg)
		reply.SetReply(msg)
		reply.Authoritative = true

		if msg.Question[0].Qtype == dns.TypeA {
			reply.Answer = append(reply.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("127.0.0.1"),
			})
		}

		resp, _ := reply.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp)
	}))
	defer ts.Close()

	svc := NewDNSService(ts.URL, "8.8.8.8")
	res, err := svc.query(context.Background(), "test.com", dns.TypeA, false)
	if err != nil {
		t.Fatalf("DoH query failed: %v", err)
	}

	if len(res) == 0 || res[0] != "127.0.0.1" {
		t.Errorf("Expected 127.0.0.1, got %v", res)
	}

	// Test DoH with Hostname and Bootstrap
	t.Run("DoH with Hostname and Bootstrap", func(t *testing.T) {
		tsDoh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/dns-message")
			// Return a simple A response for any query
			reply := new(dns.Msg)
			reply.SetReply(new(dns.Msg)) // Simplified, won't match ID but good for testing transport
			reply.Answer = append(reply.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("1.2.3.4"),
			})
			resp, _ := reply.Pack()
			_, _ = w.Write(resp)
		}))
		defer tsDoh.Close()

		host, port, _ := net.SplitHostPort(strings.TrimPrefix(tsDoh.URL, "http://"))

		// Mock bootstrap DNS server
		handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP(host),
			})
			_ = w.WriteMsg(m)
		})

		bsAddr := startMockDNSServer(t, handler, "udp")

		s := NewDNSService("http://doh.local:"+port, bsAddr)
		// Trigger a query. The transport should call DialContext, resolve doh.local, and connect.
		_, _ = s.query(context.Background(), "example.com", dns.TypeA, false)
	})

	// Test DoH error status
	tsErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer tsErr.Close()
	svcErr := NewDNSService(tsErr.URL, "")
	_, err = svcErr.query(context.Background(), "test.com", dns.TypeA, false)
	if err == nil {
		t.Error("Expected error for DoH 403 status")
	}
}

func TestDNSService_Query_Truncated(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if w.RemoteAddr().Network() == "udp" {
			m.Truncated = true
			_ = w.WriteMsg(m)
			return
		}
		// In TCP, give real answer
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("1.2.3.4"),
		})
		_ = w.WriteMsg(m)
	})

	tcpListener, packetConn, resolverAddr := listenTCPAndUDP(t)

	udpServer := &dns.Server{PacketConn: packetConn, Handler: handler}
	tcpServer := &dns.Server{Listener: tcpListener, Handler: handler}
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	})

	s := NewDNSService(resolverAddr, "")
	res, err := s.query(context.Background(), "example.com", dns.TypeA, false)
	if err != nil {
		t.Fatalf("Truncated query failed: %v", err)
	}
	if len(res) == 0 || res[0] != "1.2.3.4" {
		t.Errorf("Expected 1.2.3.4, got %v", res)
	}
}

func TestNewDNSService_Config(t *testing.T) {
	t.Run("Empty Config", func(t *testing.T) {
		s := NewDNSService("", "")
		if len(s.Resolvers) != 2 {
			t.Errorf("Expected 2 default resolvers, got %d", len(s.Resolvers))
		}
	})

	t.Run("Only Bootstrap", func(t *testing.T) {
		s := NewDNSService("", "1.1.1.1, 9.9.9.9")
		if len(s.Resolvers) != 2 || s.Resolvers[0] != "1.1.1.1" {
			t.Errorf("Expected bootstrap resolvers as fallback, got %v", s.Resolvers)
		}
	})

	t.Run("Full Config", func(t *testing.T) {
		s := NewDNSService("8.8.8.8, 8.8.4.4", "1.1.1.1")
		if len(s.Resolvers) != 2 || s.Resolvers[0] != "8.8.8.8" {
			t.Errorf("Expected configured resolvers, got %v", s.Resolvers)
		}
		if len(s.Bootstrap) != 1 {
			t.Errorf("Expected 1 bootstrap resolver, got %d", len(s.Bootstrap))
		}
	})
}

func TestDNSService_Trace_NoNS(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		// Return empty reply (no answer, no ns)
		_ = w.WriteMsg(m)
	})

	addr := startMockDNSServer(t, handler, "udp")
	oldRoots := RootServers
	RootServers = []string{addr}
	defer func() { RootServers = oldRoots }()

	svc := NewDNSService("", "")
	res, err := svc.Trace(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Trace failed: %v", err)
	}
	found := false
	for _, line := range res {
		if strings.Contains(line, "No NS records found") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'No NS records found' in trace results")
	}
}

func TestDNSService_Trace_TooLong(t *testing.T) {
	// Not easy to test without many referrals, but logic is simple
}

func TestDNSServiceStreamsPropagateCancellation(t *testing.T) {
	service := NewDNSService("192.0.2.53:53", "")
	service.SetMaxAttempts(1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := service.LookupStream(ctx, "example.com", false, func(string, interface{}) {}); !errors.Is(err, context.Canceled) {
		t.Fatalf("LookupStream error = %v; want context cancellation", err)
	}
	if err := service.DiscoverSubdomainsStream(ctx, "example.com", []string{"www"}, func(string, map[string][]string) {}); !errors.Is(err, context.Canceled) {
		t.Fatalf("DiscoverSubdomainsStream error = %v; want context cancellation", err)
	}
}

func TestDNSServiceTraceRejectsNonPublicGlue(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		name := request.Question[0].Name
		response.Ns = append(response.Ns, &dns.NS{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
			Ns:  "ns1.private.example.",
		})
		response.Extra = append(response.Extra, &dns.A{
			Hdr: dns.RR_Header{Name: "ns1.private.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("127.0.0.1"),
		})
		_ = w.WriteMsg(response)
	})
	root := startMockDNSServer(t, handler, "udp")
	originalRoots := RootServers
	RootServers = []string{root}
	t.Cleanup(func() { RootServers = originalRoots })

	results, err := NewDNSService("", "").Trace(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Trace failed: %v", err)
	}
	for _, line := range results {
		if strings.Contains(line, "Rejected non-public glue") {
			return
		}
	}
	t.Fatalf("Trace did not report rejected private glue: %v", results)
}
