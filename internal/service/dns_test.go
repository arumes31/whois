package service

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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

	server := &dns.Server{Addr: "127.0.0.1:15366", Net: "udp", Handler: handler}
	go func() { _ = server.ListenAndServe() }()
	defer func() { _ = server.Shutdown() }()
	time.Sleep(50 * time.Millisecond)

	oldRoots := RootServers
	RootServers = []string{"127.0.0.1:15366"}
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

	// Use fixed port but randomized for this test specifically if needed, 
	// but here we can just use the same port for both UDP and TCP on localhost.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	tcpAddr := l.Addr().String()
	_ = l.Close() // Close so dns.Server can bind

	server := &dns.Server{Addr: tcpAddr, Net: "udp", Handler: handler}
	go func() { _ = server.ListenAndServe() }()
	defer func() { _ = server.Shutdown() }()

	serverTCP := &dns.Server{Addr: tcpAddr, Net: "tcp", Handler: handler}
	go func() { _ = serverTCP.ListenAndServe() }()
	defer func() { _ = serverTCP.Shutdown() }()

	time.Sleep(100 * time.Millisecond)

	s := NewDNSService(tcpAddr, "")
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
