package model

import "time"

// ASNInfo distinguishes qualifying origin observations from ASN activity. In
// particular, Announced=false does not exclude an active transit-only network.
type ASNInfo struct {
	Number         uint32       `json:"number"`
	Holder         string       `json:"holder,omitempty"`
	Announced      *bool        `json:"announced,omitempty"`
	MinPeersSeeing int          `json:"min_peers_seeing"`
	OverviewStart  *time.Time   `json:"overview_start,omitempty"`
	OverviewEnd    *time.Time   `json:"overview_end,omitempty"`
	Prefixes       *ASNPrefixes `json:"prefixes,omitempty"`
}

// ASNPrefixes retains the provider's actual observation window, which may end
// before the requested current time. Items are not a claim of current routes.
type ASNPrefixes struct {
	Status      string     `json:"status"`
	Items       []string   `json:"items"`
	PeriodStart *time.Time `json:"period_start,omitempty"`
	PeriodEnd   *time.Time `json:"period_end,omitempty"`
	SourceURL   string     `json:"source_url"`
	FetchedAt   *time.Time `json:"fetched_at,omitempty"`
	Error       string     `json:"error,omitempty"`
}
