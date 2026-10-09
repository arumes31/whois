package model

import "time"

// RoutingInfo reports a provider's observed announcement, not address allocation
// or geolocation. FetchedAt is retrieval time, not the age of the RIS snapshot.
type RoutingInfo struct {
	Query                string     `json:"query"`
	IP                   string     `json:"ip,omitempty"`
	Status               string     `json:"status"`
	Prefix               string     `json:"prefix,omitempty"`
	OriginASNs           []uint32   `json:"origin_asns,omitempty"`
	Source               string     `json:"source"`
	SourceURL            string     `json:"source_url,omitempty"`
	FetchedAt            *time.Time `json:"fetched_at,omitempty"`
	SnapshotCadenceHours int        `json:"snapshot_cadence_hours"`
	Reason               string     `json:"reason,omitempty"`
	Error                string     `json:"error,omitempty"`
}
