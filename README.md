# WHOIS | Network Diagnostics & Discovery

[![Build and Publish Docker Image](https://github.com/arumes31/whois/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/arumes31/whois/actions/workflows/docker-publish.yml)
[![Daily Security Scan](https://github.com/arumes31/whois/actions/workflows/security-scan.yml/badge.svg)](https://github.com/arumes31/whois/actions/workflows/security-scan.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/arumes31/whois)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker Image Size](https://img.shields.io/docker/image-size/arumes31/whois-go?label=docker%20image)](https://ghcr.io/arumes31/whois)

A high-performance, professional-grade network diagnostic platform designed for deep reconnaissance and system monitoring. Featuring a modern Copper/Brass Steampunk aesthetic with a glassmorphism layout, it provides real-time, multi-vector analysis for IT professionals and security researchers.

## Core Capabilities

- **Multi-Vector LOOKUP:** Comprehensive analysis including WHOIS data, advanced DNS resolution (A, AAAA, MX, NS, TXT, SPF, DMARC), and GeoIP geolocation.
- **High-Speed Subdomain Discovery:** Uses multi-source Certificate Transparency (CT) logs (Certspotter primary, crt.sh fallback) with real-time incremental streaming to the UI.
- **Security Port Scanner:** Specialized tool for open port detection and service banner grabbing. Requires authentication for operational security.
- **Live WebSocket Streaming:** All diagnostic results and discovery events are pushed to the GUI individually as they complete, ensuring zero-latency feedback.
- **Automated Monitoring:** Periodic DNS health checks with change detection and unified diff history.
- **Industrial Logging:** Powered by Uber-Zap structured logging for full auditability of every service request and database operation.
- **100% Self-Contained:** All assets (CSS, JS, Fonts) are hosted locally. Zero external CDNs required, making it ideal for isolated or air-gapped networks.

## Technical Architecture

### Backend (Go / Echo)
- **Concurrent Engine:** Leverages Go's goroutines for parallel diagnostic execution with strict `context.Context` lifecycle management.
- **WebSocket Protocol:** Custom multi-stage completion signaling (`done`/`all_done`) for precise progress tracking and resource cleanup.
- **Service Layer:** Modular architecture with independent handlers for DNS, WHOIS, SSL, HTTP, and GeoIP.

### Frontend (HTMX / Bootstrap 5)
- **Reactive Components:** Uses HTMX for seamless partial page updates and WebSockets for live data feeds.
- **Theming:** Custom "Copper/Brass Steampunk" palette using modern CSS variables and glassmorphism effects.
- **Interactivity:** Universal "Click-to-Copy" on all diagnostic records with immediate visual feedback.

### Storage & Persistence (Redis)
- **Scalable Stats:** Optimized statistics gathering using `SCAN` iterators instead of `KEYS` to maintain performance as history grows.
- **Data Safety:** Utilizes Docker persistent volumes (`whois_data`) for MMDB and OUI databases to survive container restarts.

## Installation & Setup

### Docker Compose (Recommended)
```bash
docker compose up -d
```
Access the dashboard at `http://localhost:14400`.

### Environment Configuration
| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Key for session encryption (Required) | - |
| `CONFIG_USER` | Admin username | admin |
| `CONFIG_PASS` | Admin passcode | - |
| `REDIS_HOST` | Redis server hostname | redis |
| `REDIS_PORT` | Redis server port | 6379 |
| `PORT` | Web server port | 5000 |
| `DNS_SERVERS` | List of resolvers (supports DoH) | Cloudflare, Google, Quad9 DoH |
| `BOOTSTRAP_DNS` | DNS used to resolve DoH providers | 1.1.1.1, 9.9.9.9 |
| `TRUSTED_IPS` | IP whitelist for `/metrics` (CIDR supported) | - |
| `TRUST_PROXY` | Use proxy headers for client IP | true |
| `USE_CLOUDFLARE` | Use CF-Connecting-IP header | false |
| `MAXMIND_ACCOUNT_ID` | MaxMind Account ID for GeoIP | - |
| `MAXMIND_LICENSE_KEY` | MaxMind License Key for GeoIP | - |
| `ENABLE_GEO` | Enable GeoIP/ASN diagnostics | true |
| `ENABLE_SSL` | Enable SSL/TLS diagnostics | true |
| `ENABLE_WHOIS` | Enable WHOIS diagnostics | true |
| `ENABLE_DNS` | Enable advanced DNS diagnostics | true |
| `ENABLE_CT` | Enable CT log discovery | true |
| `ENABLE_HTTP` | Enable HTTP inspection | true |

## Deployment

### Docker Hub / GHCR (Recommended)
You can pull the official image directly:
```bash
docker pull ghcr.io/arumes31/whois:latest
```

### Docker Compose
```bash
docker compose up -d
```
Access the dashboard at `http://localhost:14400`.

## Development & Maintenance

### Testing
The project maintains a high-parallelism test suite:
```bash
# Run all tests with coverage
go test -v -cover ./...
```

### Formatting & Linting
Standard Go toolchain rules apply:
```bash
# Run linter
golangci-lint run
```

## Security Disclosure
This tool is intended for authorized network diagnostics and research. Users are responsible for complying with local regulations and terms of service for target networks.