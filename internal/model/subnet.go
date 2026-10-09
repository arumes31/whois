package model

// SubnetInfo is a local CIDR calculation. Counts use decimal strings so that
// IPv6 ranges retain their exact value in JSON and JavaScript clients.
type SubnetInfo struct {
	Version      int      `json:"version"`
	CIDR         string   `json:"cidr"`
	PrefixLength int      `json:"prefix_length"`
	InputAddress string   `json:"input_address"`
	Network      string   `json:"network"`
	LastAddress  string   `json:"last_address"`
	AddressCount string   `json:"address_count"`
	Netmask      string   `json:"netmask,omitempty"`
	WildcardMask string   `json:"wildcard_mask,omitempty"`
	Broadcast    string   `json:"broadcast,omitempty"`
	FirstUsable  string   `json:"first_usable,omitempty"`
	LastUsable   string   `json:"last_usable,omitempty"`
	UsableCount  string   `json:"usable_count,omitempty"`
	Notes        []string `json:"notes"`
}
