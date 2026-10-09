package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSServiceFiltersAnswerTypes(t *testing.T) {
	resolver := startMockDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		reply.Answer = []dns.RR{
			&dns.CNAME{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "canonical.example.test."},
			&dns.A{Hdr: dns.RR_Header{Name: "canonical.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.10")},
			&dns.AAAA{Hdr: dns.RR_Header{Name: "canonical.example.test.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET}, AAAA: net.ParseIP("2001:db8::10")},
		}
		_ = w.WriteMsg(reply)
	}), "udp")
	service := NewDNSService(resolver, "")
	for _, tc := range []struct{ name, want string }{
		{"A", "192.0.2.10"}, {"AAAA", "2001:db8::10"}, {"CNAME", "canonical.example.test"}, {"MX", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := service.LookupType(t.Context(), "alias.example.test", tc.name, false)
			want := []string{tc.want}
			if tc.want == "" {
				want = nil
			}
			if err != nil || !slices.Equal(got, want) {
				t.Fatalf("LookupType = %v, %v; want %v", got, err, want)
			}
		})
	}
}

func TestDNSServiceInvalidInputDoesNotPenalizeResolver(t *testing.T) {
	service := NewDNSService("127.0.0.1:1", "")
	for _, tc := range []struct {
		name, target, recordType string
		isIP                     bool
	}{
		{"invalid reverse", "invalid-ip", "PTR", true},
		{"invalid domain", "bad..example", "A", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := service.LookupType(t.Context(), tc.target, tc.recordType, tc.isIP); err == nil {
				t.Fatal("invalid input accepted")
			}
			if len(service.failures) != 0 || len(service.unhealthyUntil) != 0 {
				t.Fatalf("invalid input penalized resolver: failures=%v unhealthy=%v", service.failures, service.unhealthyUntil)
			}
		})
	}
}

func TestDNSServiceBootstrapHonorsDeadline(t *testing.T) {
	bootstrap := startMockDNSServer(t, dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {}), "udp")
	service := NewDNSService("http://doh.invalid", bootstrap)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	conn, err := service.httpClient.Transport.(*http.Transport).DialContext(ctx, "tcp", "doh.invalid:443")
	if conn != nil {
		_ = conn.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bootstrap error = %v; want deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("bootstrap ignored 30ms caller deadline: elapsed=%s", elapsed)
	}
	t.Logf("bootstrap deadline completed in %s", time.Since(start))
}

func TestDNSServiceCancellationInterruptsExchange(t *testing.T) {
	received := make(chan struct{})
	resolver := startMockDNSServer(t, dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {
		close(received)
	}), "udp")
	service := NewDNSService(resolver, "")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		_, err := service.LookupType(ctx, "example.test", "A", false)
		finished <- err
	}()
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("resolver did not receive query")
	}
	start := time.Now()
	cancel()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatalf("query error = %v; want canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("canceled query waited for socket timeout: elapsed=%s", elapsed)
	}
	t.Logf("in-flight cancellation completed in %s", time.Since(start))
}

func TestDNSServiceBootstrapFollowsCNAME(t *testing.T) {
	doh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		request := new(dns.Msg)
		if err := request.Unpack(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		reply := new(dns.Msg)
		reply.SetReply(request)
		reply.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.10"),
		}}
		body, _ = reply.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(body)
	}))
	t.Cleanup(doh.Close)
	bootstrap := startMockDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		reply.Answer = []dns.RR{
			&dns.CNAME{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "canonical.invalid."},
			&dns.A{Hdr: dns.RR_Header{Name: "canonical.invalid.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("127.0.0.1")},
		}
		_ = w.WriteMsg(reply)
	}), "udp")
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(doh.URL, "http://"))
	service := NewDNSService("http://doh.invalid:"+port, bootstrap)
	t.Cleanup(service.httpClient.CloseIdleConnections)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	got, err := service.LookupType(ctx, "example.test", "A", false)
	if err != nil || !slices.Equal(got, []string{"192.0.2.10"}) {
		t.Fatalf("bootstrap CNAME query = %v, %v", got, err)
	}
}

func TestDNSServiceRejectsOversizedDoHResponse(t *testing.T) {
	doh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		request := new(dns.Msg)
		_ = request.Unpack(body)
		reply := new(dns.Msg)
		reply.SetReply(request)
		body, _ = reply.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(append(body, make([]byte, 1<<20)...))
	}))
	t.Cleanup(doh.Close)
	service := NewDNSService(doh.URL, "")
	t.Cleanup(service.httpClient.CloseIdleConnections)
	if _, err := service.LookupType(t.Context(), "example.test", "A", false); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized DoH response error = %v; want size limit rejection", err)
	}
}

func TestDNSResolverAddress(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, input, want string }{
		{"IPv4", "192.0.2.53", "192.0.2.53:53"},
		{"IPv4 custom port", "192.0.2.53:5353", "192.0.2.53:5353"},
		{"IPv6", "2001:db8::53", "[2001:db8::53]:53"},
		{"bracketed IPv6", "[2001:db8::53]", "[2001:db8::53]:53"},
		{"IPv6 custom port", "[2001:db8::53]:5353", "[2001:db8::53]:5353"},
		{"hostname", "resolver.example.test", "resolver.example.test:53"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := dnsResolverAddress(tc.input); got != tc.want {
				t.Fatalf("dnsResolverAddress(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}
