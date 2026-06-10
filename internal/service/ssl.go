package service

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"
	"whois/internal/model"
)

func GetSSLInfo(ctx context.Context, host string) *model.SSLInfo {
	addr := host
	if !strings.Contains(host, ":") {
		addr = host + ":443"
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}

	// First try with verification
	conf := &tls.Config{InsecureSkipVerify: false}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	var tlsConn *tls.Conn
	var handshakeErr error
	verified := true

	if err == nil {
		tlsConn = tls.Client(conn, conf)
		handshakeErr = tlsConn.HandshakeContext(ctx)
		if handshakeErr != nil {
			_ = conn.Close()
			// Fallback to insecure if verification fails
			verified = false
			conf.InsecureSkipVerify = true
			conn, err = dialer.DialContext(ctx, "tcp", addr)
			if err == nil {
				tlsConn = tls.Client(conn, conf)
				handshakeErr = tlsConn.HandshakeContext(ctx)
			}
		}
	}

	if err != nil {
		return &model.SSLInfo{Error: err.Error()}
	}
	if handshakeErr != nil {
		_ = conn.Close()
		return &model.SSLInfo{Error: handshakeErr.Error()}
	}

	defer func() {
		_ = tlsConn.Close()
	}()

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return &model.SSLInfo{Error: "no certificates found"}
	}

	cert := state.PeerCertificates[0]

	protocol := "Unknown"
	switch state.Version {
	case tls.VersionTLS10:
		protocol = "TLS 1.0"
	case tls.VersionTLS11:
		protocol = "TLS 1.1"
	case tls.VersionTLS12:
		protocol = "TLS 1.2"
	case tls.VersionTLS13:
		protocol = "TLS 1.3"
	}

	return &model.SSLInfo{
		Issuer:      cert.Issuer.CommonName,
		Subject:     cert.Subject.CommonName,
		Expiry:      cert.NotAfter.Format(time.RFC3339),
		DaysLeft:    int(time.Until(cert.NotAfter).Hours() / 24),
		Protocol:    protocol,
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		Verified:    verified,
	}
}
