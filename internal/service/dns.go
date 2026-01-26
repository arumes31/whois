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

func NewDNSService() *DNSService {
	return &DNSService{
		Resolver: "8.8.8.8:53",
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
		}
		typeNames := map[uint16]string{
			dns.TypeA: "A", dns.TypeAAAA: "AAAA", dns.TypeCNAME: "CNAME",
			dns.TypeNS: "NS", dns.TypeTXT: "TXT", dns.TypeMX: "MX",
		}

		for _, t := range types {
			wg.Add(1)
			go func(t uint16, name string) {
				defer wg.Done()
				r, err := s.query(target, t, false)
				mu.Lock()
				if err == nil && len(r) > 0 {
					results[typeNames[t]] = r
				}
				mu.Unlock()
			}(t, typeNames[t])
		}
	}

	wg.Wait()

	// Post-process TXT for SPF
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
