package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"whois/internal/model"

	"github.com/miekg/dns"
)

func (s *DNSService) queryResolverDetailed(ctx context.Context, resolver, queryName string, qtype uint16) (detail model.DNSQueryDetail, err error) {
	detail = model.DNSQueryDetail{QueryName: queryName, QueryType: dns.TypeToString[qtype], Status: "error", Resolver: resolver}
	defer func() {
		detail.ObservedAt = time.Now().UTC()
		if err != nil {
			detail.Error = err.Error()
		}
	}()
	message := new(dns.Msg)
	message.SetQuestion(queryName, qtype)
	message.SetEdns0(4096, false)
	var reply *dns.Msg
	if strings.HasPrefix(resolver, "http://") || strings.HasPrefix(resolver, "https://") {
		detail.Transport = "doh"
		reply, err = s.dohQuery(ctx, resolver, message)
	} else {
		detail.Resolver, detail.Transport = dnsResolverAddress(resolver), "udp"
		client := &dns.Client{Timeout: 5 * time.Second}
		reply, err = exchangeDNSContext(ctx, client, message, detail.Resolver)
		if err == nil && reply != nil && reply.Truncated {
			client.Net, detail.Transport = "tcp", "tcp"
			reply, err = exchangeDNSContext(ctx, client, message, detail.Resolver)
		}
	}
	if err != nil {
		return detail, err
	}
	if reply == nil {
		return detail, fmt.Errorf("no response from resolver")
	}
	detail.Rcode = dns.RcodeToString[reply.Rcode]
	if detail.Rcode == "" {
		detail.Rcode = fmt.Sprintf("RCODE%d", reply.Rcode)
	}
	if reply.Truncated {
		return detail, fmt.Errorf("incomplete DNS response: truncated reply")
	}
	if reply.Rcode != dns.RcodeSuccess && reply.Rcode != dns.RcodeNameError {
		return detail, fmt.Errorf("resolver returned %s", detail.Rcode)
	}
	for _, answer := range reply.Answer {
		header := answer.Header()
		if header.Rrtype != qtype && header.Rrtype != dns.TypeCNAME {
			continue
		}
		value, ok := dnsRecordValue(answer)
		if !ok {
			continue
		}
		record := model.DNSRecord{Name: header.Name, Value: value, TTL: header.Ttl}
		if header.Rrtype == qtype {
			detail.Records = append(detail.Records, record)
		} else {
			detail.Aliases = append(detail.Aliases, record)
		}
	}
	if reply.Rcode == dns.RcodeNameError {
		// NXDOMAIN can accompany a CNAME chain, but cannot prove both that the
		// terminal name is absent and that its requested data exists.
		if qtype != dns.TypeCNAME && len(detail.Records) > 0 {
			detail.Records = nil
			return detail, fmt.Errorf("invalid DNS response: NXDOMAIN includes requested records")
		}
		detail.Status = "nxdomain"
	} else if len(detail.Records) > 0 {
		detail.Status = "answer"
	} else {
		detail.Status = "nodata"
	}
	if detail.Status == "answer" {
		return detail, nil
	}
	hasNS := false
	for _, record := range reply.Ns {
		switch record := record.(type) {
		case *dns.SOA:
			// RFC 2308: negative lifetime is bounded by both SOA values.
			ttl := min(record.Hdr.Ttl, record.Minttl)
			if detail.NegativeTTL == nil || ttl < *detail.NegativeTTL {
				detail.NegativeTTL = &ttl
			}
		case *dns.NS:
			hasNS = true
		}
	}
	if detail.Status == "nodata" && hasNS && detail.NegativeTTL == nil {
		detail.Status = "error"
		return detail, fmt.Errorf("incomplete DNS response: referral without a final answer")
	}
	return detail, nil
}

func dnsRecordValue(record dns.RR) (string, bool) {
	switch record := record.(type) {
	case *dns.A:
		return record.A.String(), true
	case *dns.AAAA:
		return record.AAAA.String(), true
	case *dns.CNAME:
		return strings.TrimSuffix(record.Target, "."), true
	case *dns.NS:
		return strings.TrimSuffix(record.Ns, "."), true
	case *dns.PTR:
		return strings.TrimSuffix(record.Ptr, "."), true
	case *dns.MX:
		return fmt.Sprintf("%d %s", record.Preference, dnsServiceTarget(record.Mx)), true
	case *dns.TXT:
		return strings.Join(record.Txt, ""), true
	case *dns.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d", strings.TrimSuffix(record.Ns, "."),
			strings.TrimSuffix(record.Mbox, "."), record.Serial, record.Refresh, record.Retry, record.Expire, record.Minttl), true
	case *dns.CAA:
		return fmt.Sprintf("%d %s %s", record.Flag, record.Tag, record.Value), true
	case *dns.SRV:
		return fmt.Sprintf("%d %d %d %s", record.Priority, record.Weight, record.Port, dnsServiceTarget(record.Target)), true
	default:
		parts := strings.Split(record.String(), "\t")
		if len(parts) > 4 {
			return strings.Join(parts[4:], " "), true
		}
		return "", false
	}
}
