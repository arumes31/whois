package service

import (
	"slices"
	"testing"

	"github.com/miekg/dns"
)

func TestDNSServicePreservesRootTargets(t *testing.T) {
	resolver := startMockDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		question := request.Question[0]
		header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET}
		switch question.Qtype {
		case dns.TypeMX:
			reply.Answer = []dns.RR{&dns.MX{Hdr: header, Preference: 0, Mx: "."}}
		case dns.TypeSRV:
			reply.Answer = []dns.RR{&dns.SRV{Hdr: header, Target: "."}}
		}
		_ = w.WriteMsg(reply)
	}), "udp")
	service := NewDNSService(resolver, "")
	for _, tc := range []struct{ recordType, want string }{
		{"MX", "0 ."},
		{"SRV", "0 0 0 ."},
	} {
		t.Run(tc.recordType, func(t *testing.T) {
			got, err := service.LookupType(t.Context(), "example.test", tc.recordType, false)
			if err != nil || !slices.Equal(got, []string{tc.want}) {
				t.Fatalf("LookupType = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}
