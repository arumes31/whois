# WHOIS | Network Diagnostics & Discovery

[![Go-CI](https://github.com/arumes31/whois/actions/workflows/go-ci.yml/badge.svg)](https://github.com/arumes31/whois/actions/workflows/go-ci.yml)
[![Build and Publish Docker Image](https://github.com/arumes31/whois/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/arumes31/whois/actions/workflows/docker-publish.yml)
[![Daily Security Scan](https://github.com/arumes31/whois/actions/workflows/security-scan.yml/badge.svg)](https://github.com/arumes31/whois/actions/workflows/security-scan.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/arumes31/whois/test)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
...
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