package service

type ScanResult struct {
	Open     map[int]string `json:"open"` // Port -> Banner
	Closed   []int          `json:"closed"`
	Filtered []int          `json:"filtered,omitempty"`
	Error    []string       `json:"error,omitempty"`
	Elapsed  float64        `json:"elapsed"`
}
