package model

type DNSResult map[string]interface{}

type QueryResult struct {
	Whois *string     `json:"whois"`
	DNS   DNSResult   `json:"dns"`
	CT    interface{} `json:"ct"`
}

type HistoryEntry struct {
	Timestamp string `json:"timestamp"`
	Result    string `json:"result"`
}
