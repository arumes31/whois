package handler

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"whois/internal/config"
	"whois/internal/model"
	"whois/internal/service"

	"github.com/labstack/echo/v5"
	"github.com/miekg/dns"
)

func focusedDNSRequest(t *testing.T, h *Handler, target, recordType string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"domain": {target}, "type": {recordType}}
	request := httptest.NewRequest(http.MethodPost, "/dns_lookup", strings.NewReader(form.Encode()))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	recorder := httptest.NewRecorder()
	if err := h.DNSLookup(echo.New().NewContext(request, recorder)); err != nil {
		t.Fatal(err)
	}
	return recorder
}

func TestDNSLookupShowsQueryEvidence(t *testing.T) {
	var queries atomic.Int64
	resolver := startDNSDetailsFixture(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		queries.Add(1)
		reply := new(dns.Msg)
		reply.SetReply(request)
		question := request.Question[0]
		hdr := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 0}
		switch {
		case strings.HasPrefix(question.Name, "missing."):
			reply.Rcode = dns.RcodeNameError
		case strings.HasPrefix(question.Name, "alias."):
			reply.Rcode = dns.RcodeNameError
			reply.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 15}, Target: "missing.example.test."}}
		case strings.HasPrefix(question.Name, "nodata."):
			reply.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.example.test.", Mbox: "admin.example.test.", Minttl: 0}}
		case strings.HasPrefix(question.Name, "failed."):
			reply.Rcode = dns.RcodeServerFailure
		case question.Qtype == dns.TypeTXT:
			reply.Answer = []dns.RR{&dns.TXT{Hdr: hdr, Txt: []string{`<script>alert("dns")</script>`}}}
		case question.Qtype == dns.TypePTR:
			reply.Answer = []dns.RR{&dns.PTR{Hdr: hdr, Ptr: "host.example.test."}}
		default:
			reply.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.ParseIP("192.0.2.1")}}
		}
		_ = w.WriteMsg(reply)
	}))
	h := NewHandler(setupMiniredisStorage(t), &config.Config{})
	h.DNS = service.NewDNSService(resolver, "")
	for _, tc := range []struct {
		name, target, recordType string
		want                     []string
	}{
		{"answer", "answer.example.test", "A", []string{"ANSWER", "answer.example.test.", "NOERROR", "192.0.2.1", "TTL 0 s"}},
		{"missing", "missing.example.test", "A", []string{"NXDOMAIN", "does not exist", "not provided"}},
		{"negative alias", "alias.example.test", "A", []string{"NXDOMAIN", "alias target", "CNAME", "missing.example.test", "TTL 15 s"}},
		{"no data", "nodata.example.test", "AAAA", []string{"NODATA", "No AAAA records found", "Negative-cache TTL", "0 s"}},
		{"failure", "failed.example.test", "A", []string{"LOOKUP FAILED", "SERVFAIL", "all resolvers failed"}},
		{"TXT escaping", "answer.example.test", "TXT", []string{"&lt;script&gt;", "&lt;/script&gt;", "TTL 0 s"}},
		{"IPv4 reverse", "192.0.2.1", "PTR", []string{"1.2.0.192.in-addr.arpa.", "PTR", "host.example.test"}},
		{"IPv6 reverse", "2001:db8::1", "PTR", []string{"ip6.arpa.", "PTR", "host.example.test"}},
		{"IDN actual query", "bücher.de", "A", []string{"xn--bcher-kva.de.", "ANSWER"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := queries.Load()
			response := focusedDNSRequest(t, h, tc.target, tc.recordType)
			body := response.Body.String()
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d, body=%s", response.Code, body)
			}
			for _, want := range append(tc.want, resolver, "UDP", "Observed") {
				if !strings.Contains(body, want) {
					t.Errorf("missing %q in focused evidence: %s", want, body)
				}
			}
			if strings.Contains(body, "<script>") {
				t.Fatalf("unescaped resolver content: %s", body)
			}
			if got := queries.Load() - before; got != 1 {
				t.Fatalf("focused query count = %d, want 1", got)
			}
		})
	}
}

func TestDNSLookupRejectsInvalidTargetsAndTypeCombinations(t *testing.T) {
	var queries atomic.Int64
	resolver := startDNSDetailsFixture(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		queries.Add(1)
		reply := new(dns.Msg)
		reply.SetReply(request)
		_ = w.WriteMsg(reply)
	}))
	h := NewHandler(setupMiniredisStorage(t), &config.Config{})
	h.DNS = service.NewDNSService(resolver, "")
	for _, tc := range []struct{ name, target, recordType, want string }{
		{"invalid name", "<script>.example", "A", "invalid DNS target"},
		{"unsupported type", "example.test", "<script>", "unsupported DNS record type"},
		{"IP with A", "192.0.2.1", "A", "only PTR lookups apply"},
		{"domain with PTR", "example.test", "PTR", "PTR lookups require an IP"},
		{"profile target", "AS13335", "A", "invalid DNS target"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := focusedDNSRequest(t, h, tc.target, tc.recordType)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), tc.want) || strings.Contains(response.Body.String(), "<script>") {
				t.Fatalf("invalid input response = %d %s", response.Code, response.Body.String())
			}
		})
	}
	if queries.Load() != 0 {
		t.Fatalf("invalid input reached DNS resolver %d times", queries.Load())
	}
}

func TestDNSLookupCanceledRequestExplainsFailure(t *testing.T) {
	h := NewHandler(setupMiniredisStorage(t), &config.Config{})
	h.DNS = service.NewDNSService("127.0.0.1:1", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	form := url.Values{"domain": {"example.test"}, "type": {"A"}}
	request := httptest.NewRequest(http.MethodPost, "/dns_lookup", strings.NewReader(form.Encode())).WithContext(ctx)
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	response := httptest.NewRecorder()
	if err := h.DNSLookup(echo.New().NewContext(request, response)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(response.Body.String(), "context canceled") || strings.Contains(response.Body.String(), "No A records found") {
		t.Fatalf("cancellation misrepresented as no data: %s", response.Body.String())
	}
}

func TestDNSLookupRenderEscapesEvidenceAndLabelsDNSSEC(t *testing.T) {
	detail := model.DNSQueryDetail{
		QueryName: "<query>", QueryType: "DNSKEY", Status: "answer", Rcode: "<rcode>",
		Resolver: `<img src=x onerror=alert(1)>`, Error: `<svg onload=alert(1)>`,
		Records: []model.DNSRecord{{Name: "<owner>", Value: "<script>value</script>", TTL: 0}},
		Aliases: []model.DNSRecord{{Name: "<alias>", Value: "<target>", TTL: 1}},
	}
	markup, err := renderDNSLookup(detail)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"<query>", "<rcode>", "<img ", "<svg ", "<owner>", "<script>", "<alias>", "<target>"} {
		if strings.Contains(markup, raw) {
			t.Errorf("unescaped evidence %q in %s", raw, markup)
		}
	}
	for _, want := range []string{"&lt;query&gt;", "&lt;script&gt;", "TTL 0 s", "DNSSEC signatures have not been validated"} {
		if !strings.Contains(markup, want) {
			t.Errorf("missing %q in %s", want, markup)
		}
	}
}
