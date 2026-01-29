package service

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type DNSService struct {
	Resolver string
}

func NewDNSService(resolver string) *DNSService {
	if resolver == "" {
		resolver = "8.8.8.8:53"
	}
	return &DNSService{
		Resolver: resolver,
	}
}

func (s *DNSService) Lookup(ctx context.Context, target string, isIP bool) (map[string]interface{}, error) {
	results := make(map[string]interface{})
	var mu sync.Mutex
	err := s.LookupStream(ctx, target, isIP, func(rtype string, data interface{}) {
		mu.Lock()
		results[rtype] = data
		mu.Unlock()
	})
	return results, err
}

func (s *DNSService) LookupStream(ctx context.Context, target string, isIP bool, callback func(string, interface{})) error {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5) // Limit to 5 concurrent queries per target

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
			if err == nil && len(r) > 0 {
				callback("PTR", r)
			} else {
				callback("PTR", []string{})
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
			if err == nil && len(r) > 0 {
				callback("DMARC", r)
			}
		}()

		// Well-known subdomains (run concurrently with other lookups)
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := s.DiscoverSubdomains(ctx, target, nil)
			if len(res) > 0 {
				callback("Subdomains", res)
			}
		}()
	}

	wg.Wait()
	return nil
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

func (s *DNSService) Trace(ctx context.Context, target string) ([]string, error) {
	var results []string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(target), dns.TypeA)
	m.RecursionDesired = false

	rootServers := []string{
		"198.41.0.4:53", "199.9.14.201:53", "192.33.4.12:53", "199.7.91.13:53",
		"192.203.230.10:53", "192.5.5.241:53", "192.112.36.4:53", "198.97.190.53:53",
		"192.36.148.17:53", "192.58.128.30:53", "193.0.14.129:53", "199.7.83.42:53",
		"202.12.27.33:53",
	}

	// Start from a random root server
	nextServer := rootServers[0]

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
	m.SetEdns0(4096, false) // Request larger UDP buffer

	c := new(dns.Client)
	c.Timeout = 5 * time.Second
	
	in, _, err := c.ExchangeContext(ctx, m, s.Resolver)
	if err != nil {
		return nil, err
	}

	// Fallback to TCP if truncated
	if in.Truncated {
		c.Net = "tcp"
		in, _, err = c.ExchangeContext(ctx, m, s.Resolver)
		if err != nil {
			return nil, err
		}
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
			// Fallback for other types
			str := ans.String()
			parts := strings.Split(str, "\t")
			if len(parts) > 4 {
				results = append(results, strings.Join(parts[4:], " "))
			}
		}
	}
	return results, nil
}
