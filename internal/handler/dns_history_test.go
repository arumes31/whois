package handler

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"whois/internal/config"
	"whois/internal/model"
	"whois/internal/service"

	"github.com/miekg/dns"
)

func TestDNSHistorySkipsPartialFailures(t *testing.T) {
	useLocalTargetEnrichment(t)
	for _, mode := range []string{"batch", "websocket"} {
		t.Run(mode, func(t *testing.T) {
			var failAAAA atomic.Bool
			resolver := startDNSDetailsFixture(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
				reply := new(dns.Msg)
				reply.SetReply(request)
				question := request.Question[0]
				hdr := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET}
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
			}))
			store := setupMiniredisStorage(t)
			h := NewHandler(store, &config.Config{EnableDNS: true})
			h.DNS = service.NewDNSService(resolver, "")
			const target = "history.example.test"
			var run func() model.DNSDetails
			if mode == "batch" {
				run = func() model.DNSDetails {
					return h.queryItem(context.Background(), target, true, false, false, false, false, false).DNSDetails
				}
			} else {
				ws := dialHandlerWebSocket(t, h)
				run = func() model.DNSDetails {
					t.Helper()
					if err := ws.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
						t.Fatal(err)
					}
					if err := ws.WriteJSON(map[string]interface{}{"targets": []string{target}, "config": map[string]bool{"dns": true}}); err != nil {
						t.Fatal(err)
					}
					var details model.DNSDetails
					for {
						var message WSMessage
						if err := ws.ReadJSON(&message); err != nil {
							t.Fatal(err)
						}
						if message.Type == "result" && message.Service == "dns" {
							details = message.DNSDetails
						}
						if message.Type == "all_done" {
							return details
						}
					}
				}
			}
			if details := run(); details["AAAA"].Status != "answer" {
				t.Fatalf("initial complete lookup = %+v", details)
			}
			failAAAA.Store(true)
			if details := run(); details["AAAA"].Status != "error" || details["A"].Status != "answer" {
				t.Fatalf("fixture did not produce partial failure: %+v", details)
			}
			history, diffs, err := store.GetHistoryWithDiffs(context.Background(), target)
			if err != nil || len(history) != 1 || len(diffs) != 0 || !strings.Contains(history[0].Result, "AAAA") {
				t.Fatalf("partial failure became historical removal: history=%+v, diffs=%v, error=%v", history, diffs, err)
			}
			failAAAA.Store(false)
			run()
			history, err = store.GetDNSHistory(context.Background(), target)
			if err != nil || len(history) != 1 {
				t.Fatalf("unchanged complete snapshot bypassed deduplication: history=%+v, error=%v", history, err)
			}
		})
	}
}
