# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Multi-vector diagnostic engine (Geo, WHOIS, DNS, CT, Portscan, Ping, Trace).
- Real-time WebSocket streaming UI with Steampunk Copper aesthetic.
- DNS over HTTPS (DoH) support with load balancing and fallback.
- Mandatory Security & Legal Disclosure system.
- Dockerized deployment with automated GeoIP database management.

### Fixed
- Permission issues in Docker containers using `su-exec`.
- DNS TXT record truncation by forcing TCP fallback.
- Standardized UI tooltips across all diagnostic modules.
- Clipboard empty issue via robust fallback copy mechanism.

### Changed
- Refactored frontend to use 100% locally hosted assets (no CDNs).
- Optimized Redis storage using SCAN iterators for high-performance history.
