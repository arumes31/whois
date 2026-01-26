# WHOIS & DNS

[![Build and Publish Docker Image](https://github.com/arumes31/whois/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/arumes31/whois/actions/workflows/docker-publish.yml)
[![Daily Security Scan](https://github.com/arumes31/whois/actions/workflows/security-scan.yml/badge.svg)](https://github.com/arumes31/whois/actions/workflows/security-scan.yml)

A comprehensive network diagnostic and monitoring tool for performing WHOIS lookups, DNS analysis, and security scanning.

## Features

- **Bulk Query:** Perform WHOIS, DNS (A, AAAA, MX, NS, TXT, SPF, DMARC), and Certificate Transparency (CT) lookups for multiple domains/IPs at once.
- **Single DNS Lookup:** Fast, targeted DNS queries for specific record types via HTMX.
- **MAC Lookup:** Identify hardware vendors from MAC addresses using the MacVendors API (with local caching).
- **Port Scanner:** Security tool to scan common ports on targets (Login required).
- **Monitoring & History:** Track DNS changes over time with unified diffs and 24h scheduled checks.
- **100% Self-Contained:** All CSS and JS assets (Bootstrap, FontAwesome, PrismJS, HTMX, Tippy, Chart.js) are bundled locally for offline/private network support.
- **Nordic Cyber Theme:** Professional, high-contrast aesthetic optimized for readability.

## Redis Integration

Redis is the core of the application's state management:
- **Caching:** Stores lookup results to minimize external API calls.
- **Rate Limiting:** Protects endpoints from abuse.
- **DNS History:** Maintains versioned history of DNS records.
- **Job Scheduling:** Manages the background monitoring queue.

## Configuration

Set these environment variables to customize the installation:
- `SECRET_KEY`: Session security (Required for production).
- `CONFIG_USER` / `CONFIG_PASS`: Credentials for the `/config` tools.
- `REDIS_HOST`: Hostname of your Redis instance (Default: `redis`).
- `TRUSTED_IPS`: Comma-separated list of IPs or CIDRs allowed to access `/metrics`.
- `TRUST_PROXY`: Set to `true` to use `X-Forwarded-For` for client IP (Default: `true`).
- `USE_CLOUDFLARE`: Set to `true` to use `CF-Connecting-IP` header.
- `ENABLE_GEO`, `ENABLE_SSL`, `ENABLE_WHOIS`, `ENABLE_DNS`, `ENABLE_CT`, `ENABLE_HTTP`: Toggle individual diagnostic features (Default: `true`).

## Deployment

### Method 1: Docker Compose (Recommended)
You can use the local build or the pre-built image from GitHub Container Registry (GHCR).

#### Using Local Build
```bash
docker compose up -d
```

#### Docker Compose (GHCR)
Download the compose file:
```bash
curl -O https://raw.githubusercontent.com/arumes31/whois/main/docker-compose.ghcr.yml
```

Run the application:
```bash
docker compose -f docker-compose.ghcr.yml up -d
```
Access the application at `http://localhost:14400`.

### Method 2: Manual Docker Build
1. **Create a network:**
   ```bash
   docker network create whois-net
   ```
2. **Start Redis:**
   ```bash
   docker run -d --name whois-redis --network whois-net redis
   ```
3. **Build and run the app:**
   ```bash
   docker build -t whois-app .
   docker run -d --name whois-web --network whois-net -p 5000:5000 -e REDIS_HOST=whois-redis whois-app
   ```
Access the application at `http://localhost:5000`.

## Tech Stack
- **Backend:** Go / Echo
- **Frontend:** HTMX / Bootstrap 5 / PrismJS
- **Storage:** Redis
- **Data Sources:** github.com/likexian/whois, github.com/miekg/dns, crt.sh, MacVendors API
