package service

import (
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

func (s *DNSService) Lookup(target string, isIP bool) (map[string]interface{}, error) {
	results := make(map[string]interface{})
	var mu sync.Mutex
	var wg sync.WaitGroup

	if isIP {
		// Reverse Lookup
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := s.query(target, dns.TypePTR, true)
			mu.Lock()
			if err == nil && len(r) > 0 {
				results["PTR"] = r
			} else {
				results["PTR"] = []string{}
			}
			mu.Unlock()
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
				r, err := s.query(target, t, false)
				mu.Lock()
				if err == nil && len(r) > 0 {
					results[name] = r
				}
				mu.Unlock()
			}(t, typeNames[t])
		}

		// DMARC Lookup
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := s.query("_dmarc."+target, dns.TypeTXT, false)
			if err == nil && len(r) > 0 {
				mu.Lock()
				results["DMARC"] = r
				mu.Unlock()
			}
		}()

		// Well-known subdomains (run concurrently with other lookups)
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := s.DiscoverSubdomains(target, nil)
			mu.Lock()
			results["Subdomains"] = res
			mu.Unlock()
		}()
	}

	wg.Wait()

	// Post-process TXT for SPF
	mu.Lock()
	defer mu.Unlock()
	if txts, ok := results["TXT"]; ok {
		if txtList, ok := txts.([]string); ok {
			var spfs []string
			for _, txt := range txtList {
				clean := strings.Trim(txt, "'\"")
				if strings.HasPrefix(strings.ToLower(clean), "v=spf1") {
					spfs = append(spfs, clean)
				}
			}
			if len(spfs) > 0 {
				results["SPF"] = spfs
				// Validation logic could go here, for now skipping complex validation
			}
		}
	}

	return results, nil
}

// DiscoverSubdomains performs a brute-force search for common subdomains
func (s *DNSService) DiscoverSubdomains(domain string, customSubs []string) map[string]interface{} {
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

	results := make(map[string]interface{})
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrency for subdomain discovery
	sem := make(chan struct{}, 20)

	for _, sub := range subs {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fqdn := sub + "." + domain
			res := make(map[string][]string)

			for _, t := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME} {
				r, err := s.query(fqdn, t, false)
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

			if len(res) > 0 {
				mu.Lock()
				results[fqdn] = res
				mu.Unlock()
			}
		}(sub)
	}
	wg.Wait()
	return results
}

func (s *DNSService) Trace(target string) ([]string, error) {
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
		results = append(results, fmt.Sprintf("Querying %s for %s", nextServer, target))
		c := new(dns.Client)
		c.Timeout = 2 * time.Second
		in, _, err := c.Exchange(m, nextServer)
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

func (s *DNSService) query(target string, qtype uint16, isReverse bool) ([]string, error) {
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
	c := new(dns.Client)
	c.Timeout = 5 * time.Second
	in, _, err := c.Exchange(m, s.Resolver)
	if err != nil {
		return nil, err
	}

	var results []string
	for _, ans := range in.Answer {
		// Clean up output to match Python's style roughly
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
			results = append(results, strings.Join(t.Txt, "")) // TXT strings are often split
		default:
			results = append(results, strings.TrimSuffix(ans.Header().Name, "."))
		}
	}
	return results, nil
}
