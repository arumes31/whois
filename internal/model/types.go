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

type SSLInfo struct {
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	Expiry      string `json:"expiry"`
	DaysLeft    int    `json:"days_left"`
	Protocol    string `json:"protocol"`
	CipherSuite string `json:"cipher_suite"`
	Verified    bool   `json:"verified"`
	Error       string `json:"error,omitempty"`
}

type HTTPInfo struct {
	Status       string            `json:"status"`
	Protocol     string            `json:"protocol"`
	Headers      map[string]string `json:"headers"`
	Security     map[string]string `json:"security"`
	ResponseTime int64             `json:"response_time_ms"`
	IP           string            `json:"ip"`
	Verified     bool              `json:"verified"`
	Error        string            `json:"error,omitempty"`
}

type HistoryEntry struct {
	Timestamp string `json:"timestamp"`
	Result    string `json:"result"`
}
