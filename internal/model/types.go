package model

type DNSResult map[string]interface{}

type QueryResult struct {
	Target interface{} `json:"target,omitempty"`
	Whois  interface{} `json:"whois"`
	DNS    DNSResult   `json:"dns"`
	CT     interface{} `json:"ct"`
	SSL    interface{} `json:"ssl,omitempty"`
	HTTP   interface{} `json:"http,omitempty"`
	Geo    interface{} `json:"geo,omitempty"`
}

type TargetKind string

const (
	TargetKindUnknown TargetKind = "unknown"
	TargetKindDomain  TargetKind = "domain"
	TargetKindIPv4    TargetKind = "ipv4"
	TargetKindIPv6    TargetKind = "ipv6"
	TargetKindCIDR    TargetKind = "cidr"
	TargetKindASN     TargetKind = "asn"
)

type IPMetadata struct {
	Address         string   `json:"address"`
	Version         int      `json:"version"`
	ReverseDNS      []string `json:"reverse_dns,omitempty"`
	IsPrivate       bool     `json:"is_private"`
	IsLoopback      bool     `json:"is_loopback"`
	IsLinkLocal     bool     `json:"is_link_local"`
	IsMulticast     bool     `json:"is_multicast"`
	IsUnspecified   bool     `json:"is_unspecified"`
	IsDocumentation bool     `json:"is_documentation"`
	IsCGNAT         bool     `json:"is_cgnat"`
	IsReserved      bool     `json:"is_reserved"`
	IsBogon         bool     `json:"is_bogon"`
	Scope           string   `json:"scope"`
}

type TargetInfo struct {
	Input        string       `json:"input"`
	Normalized   string       `json:"normalized"`
	Host         string       `json:"host,omitempty"`
	Port         string       `json:"port,omitempty"`
	Scheme       string       `json:"scheme,omitempty"`
	Kind         TargetKind   `json:"kind"`
	Prefix       string       `json:"prefix,omitempty"`
	ASN          uint32       `json:"asn,omitempty"`
	Valid        bool         `json:"valid"`
	Networkable  bool         `json:"networkable"`
	ResolutionMS int64        `json:"resolution_ms"`
	IPs          []IPMetadata `json:"ips,omitempty"`
	Warnings     []string     `json:"warnings,omitempty"`
	Error        string       `json:"error,omitempty"`
}

type CertificateInfo struct {
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	SerialNumber       string   `json:"serial_number"`
	NotBefore          string   `json:"not_before"`
	NotAfter           string   `json:"not_after"`
	DNSNames           []string `json:"dns_names,omitempty"`
	FingerprintSHA256  string   `json:"fingerprint_sha256"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	IsCA               bool     `json:"is_ca"`
}

type SSLInfo struct {
	Issuer            string            `json:"issuer"`
	Subject           string            `json:"subject"`
	Expiry            string            `json:"expiry"`
	DaysLeft          int               `json:"days_left"`
	Protocol          string            `json:"protocol"`
	CipherSuite       string            `json:"cipher_suite"`
	Verified          bool              `json:"verified"`
	HostnameValid     bool              `json:"hostname_valid"`
	SelfSigned        bool              `json:"self_signed"`
	Expired           bool              `json:"expired"`
	ExpiringSoon      bool              `json:"expiring_soon"`
	SANs              []string          `json:"sans,omitempty"`
	Chain             []CertificateInfo `json:"chain,omitempty"`
	FingerprintSHA256 string            `json:"fingerprint_sha256,omitempty"`
	SupportedVersions []string          `json:"supported_versions,omitempty"`
	ALPN              string            `json:"alpn,omitempty"`
	OCSPStapled       bool              `json:"ocsp_stapled"`
	OCSPStatus        string            `json:"ocsp_status,omitempty"`
	SCTCount          int               `json:"sct_count"`
	Score             int               `json:"score"`
	Grade             string            `json:"grade,omitempty"`
	Issues            []string          `json:"issues,omitempty"`
	PEM               string            `json:"pem,omitempty"`
	VerificationError string            `json:"verification_error,omitempty"`
	Error             string            `json:"error,omitempty"`
}

type HTTPRedirect struct {
	Status   int    `json:"status"`
	URL      string `json:"url"`
	Location string `json:"location,omitempty"`
}

type HTTPTiming struct {
	DNS     int64 `json:"dns_ms"`
	Connect int64 `json:"connect_ms"`
	TLS     int64 `json:"tls_ms"`
	TTFB    int64 `json:"ttfb_ms"`
	Total   int64 `json:"total_ms"`
}

type SecurityCheck struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Value    string `json:"value,omitempty"`
	Guidance string `json:"guidance,omitempty"`
}

type CookieInfo struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"http_only"`
	SameSite string `json:"same_site"`
}

type HTTPInfo struct {
	Status           string            `json:"status"`
	Protocol         string            `json:"protocol"`
	Headers          map[string]string `json:"headers"`
	Security         map[string]string `json:"security"`
	ResponseTime     int64             `json:"response_time_ms"`
	IP               string            `json:"ip"`
	Verified         bool              `json:"verified"`
	FinalURL         string            `json:"final_url,omitempty"`
	Redirects        []HTTPRedirect    `json:"redirects,omitempty"`
	Timing           HTTPTiming        `json:"timing"`
	SecurityChecks   []SecurityCheck   `json:"security_checks,omitempty"`
	Cookies          []CookieInfo      `json:"cookies,omitempty"`
	Compression      string            `json:"compression,omitempty"`
	ContentType      string            `json:"content_type,omitempty"`
	ContentLength    int64             `json:"content_length"`
	Server           string            `json:"server,omitempty"`
	PoweredBy        string            `json:"powered_by,omitempty"`
	CORS             string            `json:"cors,omitempty"`
	AllowedMethods   []string          `json:"allowed_methods,omitempty"`
	RobotsTXT        string            `json:"robots_txt,omitempty"`
	SecurityTXT      string            `json:"security_txt,omitempty"`
	DirectoryListing bool              `json:"directory_listing"`
	Score            int               `json:"score"`
	Grade            string            `json:"grade,omitempty"`
	Issues           []string          `json:"issues,omitempty"`
	Error            string            `json:"error,omitempty"`
}

type HistoryEntry struct {
	Timestamp string `json:"timestamp"`
	Result    string `json:"result"`
}
