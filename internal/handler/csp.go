package handler

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"whois/internal/config"
)

// WebSocketConnectSource returns the exact CSP host source used by the
// same-origin browser WebSocket client. It shares origin/proxy resolution with
// the handshake check and serializes only a validated host and numeric port.
func WebSocketConnectSource(r *http.Request, cfg *config.Config) (string, bool) {
	origin, err := expectedWebSocketOrigin(r, cfg)
	if err != nil || !safeCSPHost(origin.host) {
		return "", false
	}
	port, err := strconv.ParseUint(origin.port, 10, 16)
	if err != nil || port == 0 {
		return "", false
	}

	scheme := "ws"
	if origin.scheme == "https" {
		scheme = "wss"
	}
	return scheme + "://" + net.JoinHostPort(origin.host, origin.port), true
}

func safeCSPHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}
