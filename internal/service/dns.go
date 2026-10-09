package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"whois/internal/model"
	"whois/internal/utils"

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
					// Only use standard DNS bootstrap servers for resolving DoH hostnames
					if !strings.HasPrefix(b, "http://") && !strings.HasPrefix(b, "https://") {
						in, err := exchangeDNSContext(ctx, c, m, dnsResolverAddress(b))
						if err == nil && in != nil && in.Rcode == dns.RcodeSuccess {
							for _, answer := range in.Answer {
								if a, ok := answer.(*dns.A); ok {
									resolvedIP = a.A.String()
									break
								}
							}
						}
					}
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					if resolvedIP != "" {
						break
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
	return s.LookupStreamDetailed(ctx, target, isIP, func(name string, detail model.DNSQueryDetail) {
		for recordType, records := range DNSRecordResults(name, detail) {
			callback(recordType, records)
		}
	})
}

// LookupType resolves exactly one supported DNS record type. It is used by the
// focused lookup tool so a single A query does not fan out into a full profile.
func (s *DNSService) LookupType(ctx context.Context, target, recordType string, isIP bool) ([]string, error) {
	detail, err := s.LookupTypeDetailed(ctx, target, recordType, isIP)
	return dnsDetailValues(detail), err
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
	if err := ctx.Err(); err != nil {
		return err
	}
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

		in, err := exchangeDNSContext(ctx, c, m, nextServer)
		if err != nil {
			return results, fmt.Errorf("exchange error at %s: %w", nextServer, err)
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
					if !utils.IsPublicIP(net.ParseIP(nsIP)) {
						results = append(results, fmt.Sprintf("Rejected non-public glue for %s (%s)", nsName, nsIP))
						continue
					}
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
	detail, err := s.queryDetailed(ctx, target, qtype, isReverse)
	return dnsDetailValues(detail), err
}

// A root target explicitly means no service for MX (RFC 7505) and SRV
// (RFC 2782). Preserve it instead of rendering an empty hostname.
func dnsServiceTarget(name string) string {
	if name == "." {
		return name
	}
	return strings.TrimSuffix(name, ".")
}

func dnsResolverAddress(resolver string) string {
	if _, _, err := net.SplitHostPort(resolver); err == nil {
		return resolver
	}
	host := strings.Trim(resolver, "[]")
	if net.ParseIP(host) != nil || !strings.Contains(host, ":") {
		return net.JoinHostPort(host, "53")
	}
	return resolver
}

// ExchangeContext in miekg/dns applies deadlines, but does not interrupt an
// active socket read when a context without a deadline is canceled.
func exchangeDNSContext(ctx context.Context, client *dns.Client, message *dns.Msg, resolver string) (*dns.Msg, error) {
	conn, err := client.DialContext(ctx, resolver)
	if err != nil {
		if contextErr := dnsContextErr(ctx); contextErr != nil {
			return nil, contextErr
		}
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	reply, _, err := client.ExchangeWithConnContext(ctx, message, conn)
	if contextErr := dnsContextErr(ctx); contextErr != nil {
		return nil, contextErr
	}
	return reply, err
}

func dnsContextErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Socket deadlines may fire before the context timer is scheduled. Treat
	// an elapsed caller deadline consistently and do not penalize the resolver.
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
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

	// RFC 8484 limits application/dns-message payloads to 65,535 bytes.
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(dns.MaxMsgSize)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > dns.MaxMsgSize {
		return nil, fmt.Errorf("doh response too large (maximum %d bytes)", dns.MaxMsgSize)
	}

	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		return nil, err
	}

	return reply, nil
}
