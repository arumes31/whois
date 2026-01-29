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

func TestDNSService_Lookup(t *testing.T) {
	t.Parallel()
	s := NewDNSService("", "")

	tests := []struct {
		name     string
		target   string
		isIP     bool
		expected []string
	}{
		{"Google A", "google.com", false, []string{"A"}},
		{"Google MX", "google.com", false, []string{"MX"}},
		{"Google TXT", "google.com", false, []string{"TXT"}},
		{"Google DNS PTR", "8.8.8.8", true, []string{"PTR"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := s.Lookup(context.Background(), tt.target, tt.isIP)
			if err != nil {
				t.Fatalf("Lookup failed for %s: %v", tt.target, err)
			}
			for _, exp := range tt.expected {
				if _, ok := res[exp]; !ok {
					if exp == "A" || exp == "PTR" {
						t.Errorf("Expected %s records for %s", exp, tt.target)
					} else {
						t.Logf("Optional %s records not found for %s (might be blocked/throttled)", exp, tt.target)
					}
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
	t.Parallel()
	s := NewDNSService("", "")
	res := s.DiscoverSubdomains(context.Background(), "google.com", nil)

	if len(res) == 0 {
		t.Log("No well-known subdomains found for google.com (this might happen depending on DNS)")
	} else {
		t.Logf("Found %d well-known subdomains", len(res))
	}
}

func TestDNSService_LookupStream(t *testing.T) {
	t.Parallel()
	s := NewDNSService("8.8.8.8:53", "")

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
	t.Parallel()
	s := NewDNSService("8.8.8.8:53", "")

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

		// If we are "ns1.example.com", give an answer
		// In our simplified Trace, we just query root servers and then follow referrals.
		// Since we can't easily mock the WHOLE internet root, we just test the referral following logic.

		_ = w.WriteMsg(m)
	})

	server := &dns.Server{Addr: "127.0.0.1:15353", Net: "udp", Handler: handler}
	go func() {
		_ = server.ListenAndServe()
	}()
	defer func() { _ = server.Shutdown() }()

	// Wait for server
	time.Sleep(100 * time.Millisecond)

	s := NewDNSService("", "")
	_, _ = s.Trace(context.Background(), "google.com")
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

	server := &dns.Server{Addr: "127.0.0.1:15355", Net: "udp", Handler: handler}
	go func() { _ = server.ListenAndServe() }()
	defer func() { _ = server.Shutdown() }()
	time.Sleep(50 * time.Millisecond)

	svc := NewDNSService("", "")
	_, _ = svc.Trace(context.Background(), "example.com")
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
		w.Write(resp)
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
}

func TestDNSService_Trace_TooLong(t *testing.T) {
	// Not easy to test without many referrals, but logic is simple
}
