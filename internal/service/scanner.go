package service

type ScanResult struct {
	Open    map[int]string `json:"open"` // Port -> Banner
	Closed  []int          `json:"closed"`
	Error   []string       `json:"error,omitempty"`
	Elapsed float64        `json:"elapsed"`
}
