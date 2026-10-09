package model

import "time"

// DNSRecord retains the owner and remaining TTL reported by the resolver.
type DNSRecord struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// DNSQueryDetail describes one actual DNS query, including negative responses.
// DNSSEC record presence is evidence only; no local validation is performed.
type DNSQueryDetail struct {
	QueryName   string      `json:"query_name"`
	QueryType   string      `json:"query_type"`
	Status      string      `json:"status"`
	Rcode       string      `json:"rcode,omitempty"`
	Resolver    string      `json:"resolver,omitempty"`
	Transport   string      `json:"transport,omitempty"`
	ObservedAt  time.Time   `json:"observed_at"`
	Records     []DNSRecord `json:"records,omitempty"`
	Aliases     []DNSRecord `json:"aliases,omitempty"`
	NegativeTTL *uint32     `json:"negative_ttl,omitempty"`
	Error       string      `json:"error,omitempty"`
}

// DNSDetails uses display keys such as A, PTR and DMARC. QueryType records the
// wire type, so DMARC is explicitly a TXT query at the _dmarc name.
type DNSDetails map[string]DNSQueryDetail
