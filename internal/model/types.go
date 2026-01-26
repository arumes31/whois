package model

type DNSResult map[string]interface{}

type QueryResult struct {
	Whois interface{} `json:"whois"`
	DNS   DNSResult   `json:"dns"`
	CT    interface{} `json:"ct"`
	SSL   interface{} `json:"ssl,omitempty"`
	HTTP  interface{} `json:"http,omitempty"`
	Geo   interface{} `json:"geo,omitempty"`
}

type HistoryEntry struct {
	Timestamp string `json:"timestamp"`
	Result    string `json:"result"`
}