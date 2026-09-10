# Security Policy

## Supported versions

Security fixes are applied to the latest commit on the `main` branch and to the
latest published container image.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature for this
repository. Do not disclose suspected vulnerabilities in a public issue.

Include the affected version or commit, reproduction steps, potential impact,
and any suggested mitigation. Secrets used while testing must be revoked and
must not be included in the report.

You can expect an initial acknowledgement within seven days. A coordinated
disclosure date will be agreed after the report has been validated and a fix is
available.

## Dependency scan interpretation

CI checks reachable Go vulnerabilities and scans the built AMD64 and ARM64
images for fixable vulnerabilities at every severity. Keep scanner findings
visible; do not dismiss an alert just to make a build pass.

The September 2026 dependency refresh addresses the reported Go standard
library, Echo, SSH, and OpenSSL vulnerabilities. Go's module-level advisory
[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) still applies to the
unmaintained `golang.org/x/crypto/openpgp` package and has no fixed version.
This application imports `golang.org/x/crypto/ocsp`, not OpenPGP; `govulncheck`
reports no affected imported packages or reachable symbols. No ignore rule is
used for this advisory. Reassess it whenever crypto imports change.

Code-scanning results for `main` and the published `latest` image update only
after fixes are merged, a new image is successfully published, and the relevant
CodeQL and image scans run. A clean pull-request build does not repair or replace
an already published image.
