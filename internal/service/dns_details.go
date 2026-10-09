package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"whois/internal/model"

	"github.com/miekg/dns"
)

var dnsProfileTypes = [...]uint16{
	dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeNS, dns.TypeTXT, dns.TypeMX,
	dns.TypeCAA, dns.TypeSOA, dns.TypeSRV, dns.TypeDS, dns.TypeDNSKEY,
}

// LookupStreamDetailed emits an outcome for every requested query, including
// failures and negative answers. Callbacks may run concurrently.
func (s *DNSService) LookupStreamDetailed(ctx context.Context, target string, isIP bool, callback func(string, model.DNSQueryDetail)) error {
	type queryJob struct {
		name   string
		target string
		qtype  uint16
	}
	var jobs []queryJob
	if isIP {
		jobs = append(jobs, queryJob{"PTR", target, dns.TypePTR})
	} else {
		for _, qtype := range dnsProfileTypes {
			jobs = append(jobs, queryJob{dns.TypeToString[qtype], target, qtype})
		}
		jobs = append(jobs, queryJob{"DMARC", "_dmarc." + target, dns.TypeTXT})
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)
	var mu sync.Mutex
	var queryErrors []error
	successes := 0
	for _, job := range jobs {
		wg.Go(func() {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				// Still emit cancellation evidence for queries not yet started.
			}
			detail, err := s.queryDetailed(ctx, job.target, job.qtype, isIP)
			mu.Lock()
			if err != nil {
				queryErrors = append(queryErrors, fmt.Errorf("%s lookup: %w", job.name, err))
			} else {
				successes++
			}
			mu.Unlock()
			callback(job.name, detail)
		})
	}
	wg.Wait()
	if err := dnsContextErr(ctx); err != nil {
		return err
	}
	if successes == 0 && len(queryErrors) != 0 {
		return fmt.Errorf("dns lookup failed: %w", errors.Join(queryErrors...))
	}
	return nil
}

// LookupTypeDetailed resolves one supported record type without profile fan-out.
func (s *DNSService) LookupTypeDetailed(ctx context.Context, target, recordType string, isIP bool) (model.DNSQueryDetail, error) {
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	queryType, ok := dns.StringToType[recordType]
	switch queryType {
	case dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeNS, dns.TypeTXT, dns.TypeMX,
		dns.TypeCAA, dns.TypeSOA, dns.TypeSRV, dns.TypeDS, dns.TypeDNSKEY, dns.TypePTR:
	default:
		ok = false
	}
	if !ok {
		err := fmt.Errorf("unsupported DNS record type %q", recordType)
		return model.DNSQueryDetail{QueryName: target, QueryType: recordType, Status: "error", ObservedAt: time.Now().UTC(), Error: err.Error()}, err
	}
	if isIP != (queryType == dns.TypePTR) {
		err := fmt.Errorf("PTR lookups require an IP address")
		if isIP {
			err = fmt.Errorf("only PTR lookups apply to IP addresses")
		}
		return model.DNSQueryDetail{QueryName: target, QueryType: recordType, Status: "error", ObservedAt: time.Now().UTC(), Error: err.Error()}, err
	}
	return s.queryDetailed(ctx, target, queryType, isIP)
}

func (s *DNSService) queryDetailed(ctx context.Context, target string, qtype uint16, isReverse bool) (detail model.DNSQueryDetail, err error) {
	detail = model.DNSQueryDetail{QueryName: dns.Fqdn(target), QueryType: dns.TypeToString[qtype], Status: "error"}
	defer func() {
		if err != nil {
			detail.Status, detail.Error = "error", err.Error()
		}
		if detail.ObservedAt.IsZero() {
			detail.ObservedAt = time.Now().UTC()
		}
	}()
	if isReverse && !strings.HasSuffix(target, ".arpa.") {
		detail.QueryName, err = dns.ReverseAddr(target)
		if err != nil {
			return detail, err
		}
	}
	if err := dnsContextErr(ctx); err != nil {
		return detail, err
	}
	if _, valid := dns.IsDomainName(detail.QueryName); !valid {
		return detail, fmt.Errorf("invalid DNS name %q", target)
	}
	candidates := s.resolverCandidates()
	if len(candidates) == 0 {
		return detail, fmt.Errorf("no dns resolvers configured")
	}
	var resolverErrors []string
	for _, resolver := range candidates {
		detail, err = s.queryResolverDetailed(ctx, resolver, detail.QueryName, qtype)
		if err == nil {
			s.recordResolverResult(resolver, nil)
			return detail, nil
		}
		if contextErr := dnsContextErr(ctx); contextErr != nil {
			return detail, contextErr
		}
		s.recordResolverResult(resolver, err)
		resolverErrors = append(resolverErrors, resolver+": "+err.Error())
	}
	return detail, fmt.Errorf("all resolvers failed: %s", strings.Join(resolverErrors, "; "))
}

func dnsDetailValues(detail model.DNSQueryDetail) []string {
	values := make([]string, 0, len(detail.Records))
	for _, record := range detail.Records {
		values = append(values, record.Value)
	}
	return values
}

// DNSRecordResults converts query evidence into the existing record-array shape,
// including SPF extracted from TXT. Negative and failed queries add no records.
func DNSRecordResults(name string, detail model.DNSQueryDetail) map[string]interface{} {
	if detail.Status == "error" || len(detail.Records) == 0 {
		return nil
	}
	values := dnsDetailValues(detail)
	results := map[string]interface{}{name: values}
	if name == "TXT" {
		var spfs []string
		for _, value := range values {
			clean := strings.Trim(value, "'\"")
			if strings.HasPrefix(strings.ToLower(clean), "v=spf1") {
				spfs = append(spfs, clean)
			}
		}
		if len(spfs) > 0 {
			results["SPF"] = spfs
		}
	}
	return results
}

// DNSCacheTTL bounds a complete profile by its shortest remaining evidence TTL.
// A failed query, an unknown negative TTL, or expired/zero TTL disables caching.
func DNSCacheTTL(details model.DNSDetails, now time.Time, maximum time.Duration) time.Duration {
	if len(details) == 0 || maximum <= 0 {
		return 0
	}
	remaining := maximum
	for _, detail := range details {
		if detail.ObservedAt.IsZero() || detail.ObservedAt.After(now) {
			return 0
		}
		var ttls []uint32
		switch detail.Status {
		case "answer":
			if len(detail.Records) == 0 {
				return 0
			}
		case "nxdomain", "nodata":
			if detail.NegativeTTL == nil {
				return 0
			}
			ttls = append(ttls, *detail.NegativeTTL)
		default:
			return 0
		}
		for _, record := range detail.Records {
			ttls = append(ttls, record.TTL)
		}
		for _, alias := range detail.Aliases {
			ttls = append(ttls, alias.TTL)
		}
		for _, ttl := range ttls {
			remaining = min(remaining, detail.ObservedAt.Add(time.Duration(ttl)*time.Second).Sub(now))
			if remaining <= 0 {
				return 0
			}
		}
	}
	return remaining
}

// DNSProfileComplete reports whether every query in a detailed lookup completed
// with an answer or a negative response. Failed queries cannot establish that
// records disappeared, so their partial profile must not become DNS history.
func DNSProfileComplete(details model.DNSDetails, isIP bool) bool {
	complete := func(detail model.DNSQueryDetail) bool {
		switch detail.Status {
		case "answer", "nxdomain", "nodata":
			return true
		default:
			return false
		}
	}
	if isIP {
		return len(details) == 1 && complete(details["PTR"])
	}
	if len(details) != len(dnsProfileTypes)+1 || !complete(details["DMARC"]) {
		return false
	}
	for _, qtype := range dnsProfileTypes {
		if !complete(details[dns.TypeToString[qtype]]) {
			return false
		}
	}
	return true
}
