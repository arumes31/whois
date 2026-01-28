# WHOIS | Network Diagnostics & Discovery

[![Build and Publish Docker Image](https://github.com/arumes31/whois/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/arumes31/whois/actions/workflows/docker-publish.yml)
[![Daily Security Scan](https://github.com/arumes31/whois/actions/workflows/security-scan.yml/badge.svg)](https://github.com/arumes31/whois/actions/workflows/security-scan.yml)

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
| `CONFIG_PASS` | Admin password | - |
| `REDIS_HOST` | Redis server hostname | redis |
| `TRUSTED_IPS` | IP whitelist for `/metrics` | - |
| `MAXMIND_LICENSE_KEY` | Optional key for automated GeoIP updates | - |

## Local Data Strategy
To eliminate external API dependencies for GeoIP and MAC lookups, place these files in the `data/` volume:
1. `oui.txt`: IEEE OUI database.
2. `GeoLite2-City.mmdb`: MaxMind City database.

The system will automatically transition to local-first mode upon detection.

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