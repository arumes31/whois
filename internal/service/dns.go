package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type DNSService struct {
	Resolvers      []string
	Bootstrap      []string
	httpClient     *http.Client
	currentIndex   int
	mu             sync.Mutex
	maxAttempts    int
	failures       map[string]int
	unhealthyUntil map[string]time.Time
}

func NewDNSService(resolvers string, bootstrap string) *DNSService {
	var resList []string
	if resolvers != "" {
		for _, s := range strings.Split(resolvers, ",") {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				resList = append(resList, trimmed)
			}
		}
	}

	var bootList []string
	if bootstrap != "" {
		for _, s := range strings.Split(bootstrap, ",") {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				bootList = append(bootList, trimmed)
			}
		}
	}

	// If no resolvers are configured, fallback to bootstrap
	if len(resList) == 0 {
		resList = bootList
	}

	// If still empty (both empty), provide a ultimate fallback
	if len(resList) == 0 {
		resList = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}

	// Setup custom transport to use bootstrap DNS for DoH hostname resolution
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// HTTP client used for DoH uses bootstrap servers to resolve hostnames
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, _ := net.SplitHostPort(addr)
			if net.ParseIP(host) == nil && len(bootList) > 0 {
				// Resolve using bootstrap
				m := new(dns.Msg)
				m.SetQuestion(dns.Fqdn(host), dns.TypeA)
				c := new(dns.Client)

				var resolvedIP string
				for _, b := range bootList {
					srv := b
					if !strings.Contains(srv, ":") && !strings.HasPrefix(srv, "https://") {
						srv += ":53"
					}
					// Only use standard DNS bootstrap servers for resolving DoH hostnames
					if !strings.HasPrefix(srv, "https://") {
						in, _, err := c.Exchange(m, srv)
						if err == nil && len(in.Answer) > 0 {
							if a, ok := in.Answer[0].(*dns.A); ok {
								resolvedIP = a.A.String()
								break
							}
						}
					}
				}
				if resolvedIP != "" {
					addr = net.JoinHostPort(resolvedIP, port)
				}
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}

	return &DNSService{
		Resolvers:      resList,
		Bootstrap:      bootList,
		httpClient:     &http.Client{Transport: transport, Timeout: 10 * time.Second},
		maxAttempts:    3,
		failures:       make(map[string]int),
		unhealthyUntil: make(map[string]time.Time),
	}
}

func (s *DNSService) SetMaxAttempts(attempts int) {
	if attempts < 1 {
		attempts = 1
	}
	s.mu.Lock()
	s.maxAttempts = attempts
	s.mu.Unlock()
}

func (s *DNSService) resolverCandidates() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.Resolvers) == 0 {
		return nil
	}
	limit := s.maxAttempts
	if limit > len(s.Resolvers) {
		limit = len(s.Resolvers)
	}
	now := time.Now()
	candidates := make([]string, 0, limit)
	degraded := make([]string, 0, limit)
	for offset := range len(s.Resolvers) {
		resolver := s.Resolvers[(s.currentIndex+offset)%len(s.Resolvers)]
		if until := s.unhealthyUntil[resolver]; until.After(now) {
			degraded = append(degraded, resolver)
		} else {
			candidates = append(candidates, resolver)
		}
	}
	candidates = append(candidates, degraded...)
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	s.currentIndex = (s.currentIndex + 1) % len(s.Resolvers)
	return candidates
}

func (s *DNSService) recordResolverResult(resolver string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		delete(s.failures, resolver)
		delete(s.unhealthyUntil, resolver)
		return
	}
	s.failures[resolver]++
	if s.failures[resolver] >= 2 {
		s.unhealthyUntil[resolver] = time.Now().Add(30 * time.Second)
	}
}

func (s *DNSService) LookupStream(ctx context.Context, target string, isIP bool, callback func(string, interface{})) error {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5) // Limit to 5 concurrent queries per target
	var resultMu sync.Mutex
	var queryErrors []error
	successfulQueries := 0
	recordResult := func(name string, err error) {
		resultMu.Lock()
		defer resultMu.Unlock()
		if err != nil {
			queryErrors = append(queryErrors, fmt.Errorf("%s lookup: %w", name, err))
			return
		}
		successfulQueries++
	}

	if isIP {
		// Reverse Lookup
		wg.Add(1)
		go func() {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			r, err := s.query(ctx, target, dns.TypePTR, true)
			recordResult("PTR", err)
			if err == nil && len(r) > 0 {
				callback("PTR", r)
			}
		}()
	} else {
		types := []uint16{
			dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeNS, dns.TypeTXT, dns.TypeMX,
			dns.TypeCAA, dns.TypeSOA, dns.TypeSRV, dns.TypeDS, dns.TypeDNSKEY,
		}
		typeNames := map[uint16]string{
			dns.TypeA: "A", dns.TypeAAAA: "AAAA", dns.TypeCNAME: "CNAME",
			dns.TypeNS: "NS", dns.TypeTXT: "TXT", dns.TypeMX: "MX",
			dns.TypeCAA: "CAA", dns.TypeSOA: "SOA", dns.TypeSRV: "SRV",
			dns.TypeDS: "DS", dns.TypeDNSKEY: "DNSKEY",
		}

		for _, t := range types {
			wg.Add(1)
			go func(t uint16, name string) {
				defer wg.Done()

				select {
				case <-ctx.Done():
					return
				case sem <- struct{}{}:
					defer func() { <-sem }()
				}

				r, err := s.query(ctx, target, t, false)
				recordResult(name, err)
				if err == nil && len(r) > 0 {
					callback(name, r)

					// Special case for SPF extraction from TXT
					if t == dns.TypeTXT {
						var spfs []string
						for _, txt := range r {
							clean := strings.Trim(txt, "'\"")
							if strings.HasPrefix(strings.ToLower(clean), "v=spf1") {
								spfs = append(spfs, clean)
							}
						}
						if len(spfs) > 0 {
							callback("SPF", spfs)
						}
					}
				}
			}(t, typeNames[t])
		}

		// DMARC Lookup
		wg.Add(1)
		go func() {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			r, err := s.query(ctx, "_dmarc."+target, dns.TypeTXT, false)
			recordResult("DMARC", err)
			if err == nil && len(r) > 0 {
				callback("DMARC", r)
			}
		}()
	}

	wg.Wait()
	resultMu.Lock()
	defer resultMu.Unlock()
	if successfulQueries == 0 && len(queryErrors) > 0 {
		return fmt.Errorf("dns lookup failed: %w", errors.Join(queryErrors...))
	}
	return nil
}

// LookupType resolves exactly one supported DNS record type. It is used by the
// focused lookup tool so a single A query does not fan out into a full profile.
func (s *DNSService) LookupType(ctx context.Context, target, recordType string, isIP bool) ([]string, error) {
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	types := map[string]uint16{
		"A": dns.TypeA, "AAAA": dns.TypeAAAA, "CNAME": dns.TypeCNAME,
		"NS": dns.TypeNS, "TXT": dns.TypeTXT, "MX": dns.TypeMX,
		"CAA": dns.TypeCAA, "SOA": dns.TypeSOA, "SRV": dns.TypeSRV,
		"DS": dns.TypeDS, "DNSKEY": dns.TypeDNSKEY, "PTR": dns.TypePTR,
	}
	queryType, ok := types[recordType]
	if !ok {
		return nil, fmt.Errorf("unsupported DNS record type %q", recordType)
	}
	if isIP != (queryType == dns.TypePTR) {
		if isIP {
			return nil, fmt.Errorf("only PTR lookups apply to IP addresses")
		}
		return nil, fmt.Errorf("PTR lookups require an IP address")
	}
	return s.query(ctx, target, queryType, isIP)
}

// DiscoverSubdomains performs a brute-force search for common subdomains
func (s *DNSService) DiscoverSubdomains(ctx context.Context, domain string, customSubs []string) map[string]interface{} {
	results := make(map[string]interface{})
	var mu sync.Mutex
	_ = s.DiscoverSubdomainsStream(ctx, domain, customSubs, func(fqdn string, res map[string][]string) {
		mu.Lock()
		results[fqdn] = res
		mu.Unlock()
	})
	return results
}

func (s *DNSService) DiscoverSubdomainsStream(ctx context.Context, domain string, customSubs []string, callback func(string, map[string][]string)) error {
	subs := []string{
		"www", "mail", "ftp", "webmail", "admin", "cpanel", "login", "secure",
		"smtp", "pop", "imap", "autodiscover", "autoconfig", "mta-sts",
		"vpn", "remote", "gateway", "portal", "cloud", "api", "dev", "test",
		"staging", "beta", "demo", "status", "monitor", "metrics", "health",
		"shop", "store", "blog", "forum", "wiki", "docs", "support", "help",
		"cdn", "static", "assets", "media", "images", "files", "download",
		"mysql", "sql", "db", "git", "gitlab", "jenkins", "docker", "proxy",
		"ns1", "ns2", "ns3", "whm", "web", "server", "app", "dashboard",
		"ssh", "sip", "vnc", "rdp", "postgres", "redis", "mongodb", "elastic",
		"kibana", "grafana", "prometheus", "traefik", "nginx", "apache",
		"k8s", "kubernetes", "aws", "azure", "gcp", "mail1", "mail2",
	}

	if len(customSubs) > 0 {
		subs = customSubs
	}

	var wg sync.WaitGroup
	// Limit concurrency for subdomain discovery
	sem := make(chan struct{}, 20)

	for _, sub := range subs {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			fqdn := sub + "." + domain
			res := s.Resolve(ctx, fqdn)

			if len(res) > 0 {
				callback(fqdn, res)
			}
		}(sub)
	}
	wg.Wait()
	return nil
}

// Resolve resolves A, AAAA, and CNAME records for a given FQDN
func (s *DNSService) Resolve(ctx context.Context, fqdn string) map[string][]string {
	res := make(map[string][]string)
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME} {
		r, err := s.query(ctx, fqdn, t, false)
		if err == nil && len(r) > 0 {
			typeName := "A"
			if t == dns.TypeAAAA {
				typeName = "AAAA"
			}
			if t == dns.TypeCNAME {
				typeName = "CNAME"
			}
			res[typeName] = r
		}
	}
	return res
}

var RootServers = []string{
	"198.41.0.4:53", "199.9.14.201:53", "192.33.4.12:53", "199.7.91.13:53",
	"192.203.230.10:53", "192.5.5.241:53", "192.112.36.4:53", "198.97.190.53:53",
	"192.36.148.17:53", "192.58.128.30:53", "193.0.14.129:53", "199.7.83.42:53",
	"202.12.27.33:53",
}

func (s *DNSService) Trace(ctx context.Context, target string) ([]string, error) {
	var results []string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(target), dns.TypeA)
	m.RecursionDesired = false

	// Start from a random root server
	nextServer := RootServers[0]

	for {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		results = append(results, fmt.Sprintf("Querying %s for %s", nextServer, target))
		c := new(dns.Client)
		c.Timeout = 2 * time.Second

		// dns.Client.Exchange doesn't take context directly, but we can use ExchangeContext if available
		// or just wrap it. miekg/dns supports ExchangeContext.
		in, _, err := c.ExchangeContext(ctx, m, nextServer)
		if err != nil {
			return results, fmt.Errorf("exchange error at %s: %v", nextServer, err)
		}

		if len(in.Answer) > 0 {
			for _, ans := range in.Answer {
				results = append(results, fmt.Sprintf("Answer: %s", ans.String()))
			}
			break
		}

		if len(in.Ns) == 0 {
			results = append(results, "No NS records found in authority section")
			break
		}

		// Find next server in NS records
		found := false
		for _, ns := range in.Ns {
			if n, ok := ns.(*dns.NS); ok {
				// We need the IP of this NS. In a real trace we'd check Glue records (in.Extra)
				// For simplicity, we'll try to resolve the NS or use Glue if available.
				nsName := n.Ns
				nsIP := ""
				for _, extra := range in.Extra {
					if a, ok := extra.(*dns.A); ok && a.Header().Name == nsName {
						nsIP = a.A.String()
						break
					}
				}

				if nsIP != "" {
					nextServer = nsIP + ":53"
					found = true
					results = append(results, fmt.Sprintf("Following referral to %s (%s)", nsName, nsIP))
					break
				} else {
					// Fallback: Resolve the NS name (simplified)
					results = append(results, fmt.Sprintf("Referral to %s (no glue, resolving...)", nsName))
				}
			}
		}

		if !found {
			results = append(results, "Could not follow referral (no glue records)")
			break
		}

		if len(results) > 20 { // Safety break
			results = append(results, "Trace too long, aborting")
			break
		}
	}

	return results, nil
}

func (s *DNSService) query(ctx context.Context, target string, qtype uint16, isReverse bool) ([]string, error) {
	candidates := s.resolverCandidates()
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no dns resolvers configured")
	}
	var errors []string
	for _, resolver := range candidates {
		result, err := s.queryResolver(ctx, resolver, target, qtype, isReverse)
		s.recordResolverResult(resolver, err)
		if err == nil {
			return result, nil
		}
		errors = append(errors, resolver+": "+err.Error())
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("all resolvers failed: %s", strings.Join(errors, "; "))
}

func (s *DNSService) queryResolver(ctx context.Context, resolver, target string, qtype uint16, isReverse bool) ([]string, error) {

	m := new(dns.Msg)
	queryName := target
	if isReverse && !strings.HasSuffix(target, ".arpa.") {
		var err error
		queryName, err = dns.ReverseAddr(target)
		if err != nil {
			return nil, err
		}
	} else if !isReverse {
		queryName = dns.Fqdn(target)
	}

	m.SetQuestion(queryName, qtype)
	m.SetEdns0(4096, false)

	var in *dns.Msg
	var err error

	if strings.HasPrefix(resolver, "http://") || strings.HasPrefix(resolver, "https://") {
		// DoH Query
		in, err = s.dohQuery(ctx, resolver, m)
	} else {
		// Standard DNS
		srv := resolver
		if !strings.Contains(srv, ":") {
			srv += ":53"
		}
		c := new(dns.Client)
		c.Timeout = 5 * time.Second
		in, _, err = c.ExchangeContext(ctx, m, srv)
		if err == nil && in != nil && in.Truncated {
			c.Net = "tcp"
			in, _, err = c.ExchangeContext(ctx, m, srv)
		}
	}

	if err != nil {
		return nil, err
	}
	if in == nil {
		return nil, fmt.Errorf("no response from resolver")
	}
	if in.Rcode != dns.RcodeSuccess && in.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("resolver returned %s", dns.RcodeToString[in.Rcode])
	}

	var results []string
	for _, ans := range in.Answer {
		switch t := ans.(type) {
		case *dns.A:
			results = append(results, t.A.String())
		case *dns.AAAA:
			results = append(results, t.AAAA.String())
		case *dns.CNAME:
			results = append(results, strings.TrimSuffix(t.Target, "."))
		case *dns.NS:
			results = append(results, strings.TrimSuffix(t.Ns, "."))
		case *dns.PTR:
			results = append(results, strings.TrimSuffix(t.Ptr, "."))
		case *dns.MX:
			results = append(results, fmt.Sprintf("%d %s", t.Preference, strings.TrimSuffix(t.Mx, ".")))
		case *dns.TXT:
			results = append(results, strings.Join(t.Txt, ""))
		case *dns.SOA:
			results = append(results, fmt.Sprintf("%s %s %d %d %d %d %d",
				strings.TrimSuffix(t.Ns, "."),
				strings.TrimSuffix(t.Mbox, "."),
				t.Serial, t.Refresh, t.Retry, t.Expire, t.Minttl))
		case *dns.CAA:
			results = append(results, fmt.Sprintf("%d %s %s", t.Flag, t.Tag, t.Value))
		case *dns.SRV:
			results = append(results, fmt.Sprintf("%d %d %d %s", t.Priority, t.Weight, t.Port, strings.TrimSuffix(t.Target, ".")))
		default:
			str := ans.String()
			parts := strings.Split(str, "\t")
			if len(parts) > 4 {
				results = append(results, strings.Join(parts[4:], " "))
			}
		}
	}
	return results, nil
}

func (s *DNSService) dohQuery(ctx context.Context, url string, m *dns.Msg) (*dns.Msg, error) {
	data, err := m.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh status error: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		return nil, err
	}

	return reply, nil
}
