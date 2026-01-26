package service

import (
	"crypto/tls"
	"net"
	"time"
)

type SSLInfo struct {
	Issuer      string    `json:"issuer"`
	Subject     string    `json:"subject"`
	Expiry      time.Time `json:"expiry"`
	DaysLeft    int       `json:"days_left"`
	Protocol    string    `json:"protocol"`
	CipherSuite string    `json:"cipher_suite"`
	Error       string    `json:"error,omitempty"`
}

func GetSSLInfo(host string) *SSLInfo {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host+":443", conf)
	if err != nil {
		return &SSLInfo{Error: err.Error()}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return &SSLInfo{Error: "no certificates found"}
	}

	cert := state.PeerCertificates[0]
	
	protocol := "Unknown"
	switch state.Version {
	case tls.VersionTLS10: protocol = "TLS 1.0"
	case tls.VersionTLS11: protocol = "TLS 1.1"
	case tls.VersionTLS12: protocol = "TLS 1.2"
	case tls.VersionTLS13: protocol = "TLS 1.3"
	}

	return &SSLInfo{
		Issuer:      cert.Issuer.CommonName,
		Subject:     cert.Subject.CommonName,
		Expiry:      cert.NotAfter,
		DaysLeft:    int(time.Until(cert.NotAfter).Hours() / 24),
		Protocol:    protocol,
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}
}
