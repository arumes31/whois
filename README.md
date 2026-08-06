# WHOIS | Network Diagnostics & Discovery

[![Go-CI](https://github.com/arumes31/whois/actions/workflows/go-ci.yml/badge.svg)](https://github.com/arumes31/whois/actions/workflows/go-ci.yml)
[![Build and Publish Docker Image](https://github.com/arumes31/whois/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/arumes31/whois/actions/workflows/docker-publish.yml)
[![Daily Security Scan](https://github.com/arumes31/whois/actions/workflows/security-scan.yml/badge.svg)](https://github.com/arumes31/whois/actions/workflows/security-scan.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/arumes31/whois/test)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Issues](https://img.shields.io/github/issues/arumes31/whois)](https://github.com/arumes31/whois/issues)
[![Last Commit](https://img.shields.io/github/last-commit/arumes31/whois/test)](https://github.com/arumes31/whois/commits/test)

A network diagnostic dashboard for WHOIS, DNS, HTTP/TLS inspection, GeoIP, port scanning, and monitored DNS history. It combines a Go service with a locally hosted web interface and Redis-backed state.

## 🚀 Core Capabilities

- 🔍 **Multi-Vector LOOKUP:** Comprehensive analysis including WHOIS data, advanced DNS resolution (A, AAAA, MX, NS, TXT, SPF, DMARC), and local GeoIP location data when installed.
- 🌐 **Subdomain Discovery:** Uses multi-source Certificate Transparency (CT) logs (Certspotter primary, crt.sh fallback) with real-time incremental streaming.
- 🛡️ **Security Port Scanner:** Specialized tool for open port detection and service banner grabbing with localized security controls.
- 🧭 **Provider-Free Target Intelligence:** Normalizes pasted URLs, detects domains/IPv4/IPv6/CIDRs/ASNs, classifies private, reserved, documentation, CGNAT, and bogon ranges, and performs reverse DNS locally.
- 🔐 **TLS & HTTP Posture:** Directly inspects certificate chains, SANs, fingerprints, supported TLS versions, OCSP stapling, redirects, request timings, cookies, CORS, security headers, and well-known policy files.
- 📡 **Live WebSocket Streaming:** Diagnostic results and discovery events are pushed individually as they complete, ensuring zero-latency feedback.
- 📈 **Automated Monitoring:** Periodic DNS health checks with change detection and unified diff history.
- 📦 **Locally Hosted UI Assets:** CSS, JavaScript, and fonts are served by the application without browser-side CDNs. Network diagnostics still contact the target and configured DNS, WHOIS/RDAP, CT, GeoIP, and database sources.

## 🏗️ Technical Architecture

```mermaid
graph TD
    User((User)) -->|WebSocket / Fetch| FE[Frontend: ES Modules / Phosphor UI]
    subgraph "Go Diagnostic Engine (Echo Framework)"
        FE -->|Requests| Handler[Echo API Handlers]
        Handler -->|Concurrent Execution| Svc[Service Layer]
        Svc -->|DoH / UDP| DNS[DNS Service]
        Svc -->|RDAP / P43| WHOIS[WHOIS Service]
        Svc -->|HTTPS| CT[CT Log Service]
        Svc -->|TCP| Scan[Scanner Service]
        Svc -->|GeoIP| Geo[GeoIP Service]
    end
    Svc -->|Store History| Cache[Redis Storage]
    Scheduler[Cron Scheduler] -->|Periodic Tasks| Svc
```

### Technical Highlights
*   **Echo Framework:** Leverages a high-performance, minimalist Go web framework for optimized routing and middleware management.
*   **Dependency-free frontend:** The console runs on vanilla ES modules — no Bootstrap, no HTMX, no client-side framework. A custom phosphor-terminal design system (locally hosted JetBrains Mono + Inter) replaces the old vendor bundle.
*   **Concurrency:** Built on Go's goroutine model with strict `context.Context` lifecycle management for safe, parallel diagnostic execution.
*   **DNS over HTTPS (DoH):** Implements secure, encrypted DNS queries with automatic load balancing across providers (Cloudflare, Google, Quad9).

## 🛠️ Tech Stack

| Layer | Technologies |
|---|---|
| **Backend** | Go 1.26.4+, Echo v4, Zap Logging |
| **Frontend** | Vanilla ES modules, custom phosphor design system, Chart.js (vendored) |
| **Storage** | Redis with bounded DNS history and set-backed dashboard counters |
| **Networking** | DoH (DNS-over-HTTPS), RDAP, ICMP, TCP |
| **DevOps** | Docker, GitHub Actions, golangci-lint |

## 📦 Installation & Setup

### Docker Compose (Recommended)

Create the local configuration first. Compose intentionally refuses to start with missing administrator credentials or a missing session-signing key.

```bash
cp .env.example .env
openssl rand -hex 32  # use this output for SECRET_KEY
openssl rand -hex 24  # use this output for CONFIG_PASS
# Edit .env and set CONFIG_USER, CONFIG_PASS, and SECRET_KEY.

docker compose config
docker compose up -d --build
```

Access the dashboard at `http://localhost:14400`.

Compose binds port 14400 to `127.0.0.1` by default and runs both services with read-only root filesystems, bounded process counts, and writable named volumes only for application data. Set `WHOIS_BIND_ADDRESS` only when remote access is intentional.

Local Compose uses plain HTTP, so `.env.example` sets `SESSION_COOKIE_SECURE=false`. When the browser reaches the application through an HTTPS reverse proxy, set `SESSION_COOKIE_SECURE=true`; otherwise the browser will not send the administrator session cookie. Plain HTTP administration should remain limited to a trusted loopback workstation.

### Run the Published GHCR Image

The local and GHCR definitions both inherit their hardened runtime contract from `docker-compose.common.yml`. The GHCR leaf never inherits the local `build` rule, so the rendered published-image configuration is image-only while retaining identical Redis, security, feature, and concurrency settings.

```bash
cp .env.example .env
# Set CONFIG_USER, CONFIG_PASS, and SECRET_KEY in .env as shown above.
docker compose -f docker-compose.ghcr.yml config
docker compose -f docker-compose.ghcr.yml pull
docker compose -f docker-compose.ghcr.yml up -d --no-build
```

Published `latest`, release, and commit-SHA tags are assembled only after the full reusable Go CI gate and both architecture builds pass. Each architecture is pushed without a staging tag, verified and scanned by immutable digest, then the final manifest is checked for the exact `linux/amd64` and `linux/arm64` digests. The verifier also requires an SPDX SBOM and SLSA provenance attestation that explicitly references each platform digest.

### Health and Operations

`GET /livez` reports process liveness and is used by Docker. `GET /readyz` is dependency-aware: it returns HTTP 200 when Redis is connected and HTTP 503 when Redis is unavailable. `GET /health` remains a backward-compatible readiness alias.

```bash
curl --fail http://localhost:14400/livez
curl --fail http://localhost:14400/readyz
docker compose ps
docker compose logs -f web redis
```

The `whois_data` and `redis_data` named volumes contain downloaded lookup data and application history. Back them up before upgrades that remove or recreate volumes. `docker compose down` preserves them; `docker compose down --volumes` deletes them.

Redis is bounded to 192 MiB with `allkeys-lru` eviction by default, below the 256 MiB container limit. Override `REDIS_MAXMEMORY` or `REDIS_MAXMEMORY_POLICY` only after accounting for Redis overhead and the container memory limit.

### Reverse Proxy Configuration (Nginx)
If you are running behind Nginx, you **must** ensure WebSocket headers are forwarded correctly:
```nginx
location / {
    proxy_pass http://localhost:14400;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
}
```

Leave `TRUST_PROXY=false` when port 14400 is reachable directly. Enable it only when clients cannot bypass the reverse proxy, and set `TRUSTED_PROXIES` to that proxy's exact IP/CIDR ranges. Forwarded client-IP headers affect access controls such as `/metrics`. Set `ALLOWED_DOMAIN` to the public hostname and keep `WS_SKIP_ORIGIN_CHECK=false`.

### Environment Configuration

#### 🛡️ Core & Security
| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | **Required** signing key for administrator sessions; generate at least 32 random bytes | None |
| `SEO_ENABLED` | Enable SEO optimizations and dynamic metadata | `false` |
| `SEO_DOMAIN` | Canonical domain for SEO indexing | - |
| `ALLOWED_DOMAIN` | Base domain allowed for WebSocket connections | - |
| `WS_SKIP_ORIGIN_CHECK` | Completely disable WebSocket origin validation | `false` |
| `MAX_WS_CONNECTIONS` | Process-wide WebSocket connection ceiling | `128` |
| `MAX_WS_CONNECTIONS_PER_IP` | Per-client WebSocket connection ceiling; must not exceed the global ceiling | `8` |
| `CONFIG_USER` | Administrator username; must be changed in production | `admin` outside Compose |
| `CONFIG_PASS` | Administrator passcode; minimum 12 characters in production | `admin` outside Compose |
| `ENVIRONMENT` | Runtime environment; Compose defaults to restrictive `production` behavior | `production` in Compose |
| `SESSION_COOKIE_SECURE` | Send administrator cookies only over HTTPS; local HTTP Compose explicitly sets this false | `true` in production outside Compose |
| `ALLOW_DEV_CORS` | Force-allow wildcard CORS even in non-development environment | `false` |
| `CORS_ORIGINS` | Comma-separated cross-origin clients; same-origin use needs no entry | Empty |
| `TRUSTED_IPS` | CSV of IPs allowed to access `/metrics` | `127.0.0.1,::1,...` |
| `TRUSTED_PROXIES` | CSV of proxy IP/CIDR ranges allowed to supply client-IP headers | `127.0.0.1/32,::1/128` |
| `TRUST_PROXY` | Trust `X-Forwarded-For` headers; enable only behind a trusted proxy | `false` |
| `USE_CLOUDFLARE` | Use `CF-Connecting-IP` for client identification | `false` |
| `ALLOW_PRIVATE_IPS` | Permit diagnostics against RFC1918/ULA private ranges | `false` |
| `ALLOW_LOOPBACK_IPS` | Separately permit loopback targets (development only) | `false` |
| `ALLOW_LINK_LOCAL_IPS` | Separately permit link-local targets, including metadata ranges | `false` |

#### 📡 DNS & Networking
| Variable | Description | Default |
|----------|-------------|---------|
| `DNS_SERVERS` | CSV of DoH resolvers used for multi-vector lookups | `Cloudflare, Google, Quad9` |
| `BOOTSTRAP_DNS` | DNS used to resolve the hostnames of DoH providers | `1.1.1.1, 9.9.9.9` |
| `DNS_MAX_ATTEMPTS` | Resolver attempts before returning an error; unhealthy resolvers receive a short cooldown | `3` |
| `DNS_HISTORY_MAX_TARGETS` | Maximum target histories retained in Redis | `1000` |
| `DNS_HISTORY_TTL_HOURS` | Retention window for per-target DNS history | `720` |
| `MAX_TARGET_CONCURRENCY` | Maximum target diagnostic chains running at once | `4` |
| `MAX_SERVICE_CONCURRENCY` | Maximum individual diagnostic services running at once | `12` |
| `PORT_SCAN_CONCURRENCY` | TCP scan worker count | `32` |
| `PORT_SCAN_MAX_PORTS` | Maximum ports accepted in one scan | `1024` |
| `PORT` | Local port the web server listens on | `5000` |
| `WHOIS_BIND_ADDRESS` | Host address used by Compose's published HTTP port | `127.0.0.1` |
| `WHOIS_PORT` | Host port published by Compose | `14400` |
| `REDIS_HOST` | Hostname of the Redis server | `localhost` |
| `REDIS_PORT` | Port of the Redis server | `6379` |
| `REDIS_MAXMEMORY` | Redis data-memory ceiling beneath the container limit | `192mb` |
| `REDIS_MAXMEMORY_POLICY` | Eviction policy after the Redis memory ceiling is reached | `allkeys-lru` |

#### 🔍 Diagnostic Features
| Variable | Description | Default |
|----------|-------------|---------|
| `ENABLE_GEO` | Enable local GeoIP city/location lookups when a database is installed | `true` |
| `AUTO_UPDATE_DATABASES` | Download and periodically refresh GeoIP/OUI databases; keep disabled for offline startup | `false` |
| `ENABLE_DNS` | Enable authoritative DNS record retrieval | `true` |
| `ENABLE_WHOIS` | Enable WHOIS and RDAP data retrieval | `true` |
| `ENABLE_SSL` | Enable SSL/TLS certificate analysis | `true` |
| `ENABLE_HTTP` | Enable HTTP security header inspection | `true` |
| `ENABLE_CT` | Enable Certificate Transparency log discovery | `true` |

Target classification, TLS/HTTP inspection, DNS failover, and port scanning are performed directly by the application and do not require a paid intelligence provider. GeoIP, CT, WHOIS/RDAP, and configured public DNS resolvers remain optional external data sources.

Startup is network-silent by default. For automatic GeoIP/OUI downloads set `AUTO_UPDATE_DATABASES=true`; otherwise pre-populate the persistent lookup-data volume. For a more isolated deployment, also disable unneeded external-source feature flags and point DNS settings at internal resolvers. The application is not fully offline merely because its browser assets are local.

#### 🌍 External API Keys
| Variable | Description | Default |
|----------|-------------|---------|
| `MAXMIND_ACCOUNT_ID` | MaxMind Account ID for GeoIP database updates | - |
| `MAXMIND_LICENSE_KEY` | MaxMind License Key for GeoIP database updates | - |

## 🔄 Development Lifecycle

### Automated Workflow
GitHub Actions uses commit-SHA-pinned actions for linting, `go vet`, race-enabled tests, deterministic stress tests, fuzz smoke tests, reachable dependency vulnerability scanning, and Docker build checks. Registry-writing jobs reuse that complete gate. Container publication pushes untagged per-architecture digests, scans those exact immutable images, and publishes registry tags only after assembling and verifying their platform digests and attestations. Run-unique digest artifacts coordinate the jobs, so branch and release runs cannot share mutable staging references. The Dockerfile owns the reproducible asset build and embeds a checksum manifest that is verified during the image build and again before publication.

The manual **Delete Old Packages** workflow defaults to a dry run. When explicitly enabled, it prunes only untagged manifests older than 30 days and discovers all children referenced by retained multi-architecture tags before deletion; inspection failures stop deletion for that package.

The Node runtime, container base images, QEMU helper image, Buildx binary, and BuildKit image are pinned exactly in release automation. Runtime `apk add` dependencies intentionally follow compatible patch revisions from the Alpine 3.24 repositories: exact APK pins are not retained indefinitely by Alpine mirrors and would make otherwise reproducible rebuilds fail. CI bypasses the cached runtime stage so those packages are refreshed for every registry-writing build. This limited patch drift is deliberate; every resulting immutable architecture digest is checksum-verified and blocked on the Critical/High vulnerability scan before it can receive a deployment tag.

```bash
# Run the same core checks used by CI
go test -race -count=1 ./...
go test -race -tags=stress -count=1 -run '^TestStress' ./internal/service
govulncheck ./...
npm ci --ignore-scripts
npm test

# Run linter
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4 run

# Validate and build the container
docker compose config
docker build --check .
docker build -t whois:local .
docker run --rm --entrypoint /bin/sh whois:local -c 'cd /app && sha256sum -c assets.sha256'
```

## ⚖️ Compliance & Security
This tool is intended for authorized network diagnostics and research. Users are responsible for complying with local regulations. The platform includes a mandatory **Security & Legal Disclosure** system to ensure users acknowledge terms of use before proceeding.

---
*Built with ❤️ using Go and a hand-rolled phosphor terminal UI.*
