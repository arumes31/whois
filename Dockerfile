FROM node:26.12.0-alpine3.24@sha256:6f08a523443ddedf52941874c203475b0ad503e859ad70cb26ab8be9a517dbd5 AS assets
WORKDIR /assets
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY scripts ./scripts
COPY static ./static
COPY templates ./templates
RUN npm run build:assets && npm run assets:check

FROM golang:1.27.3-alpine3.24@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/whois-app ./cmd/server

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS runtime
LABEL org.opencontainers.image.authors="https://github.com/arumes31" \
      org.opencontainers.image.source="https://github.com/arumes31/whois"
WORKDIR /app

# Alpine repositories retain the supported branch, not every historical APK
# patch. Package names deliberately follow v3.24 security patches; see README.
RUN addgroup -S -g 101 whoisgroup \
    && adduser -S -D -H -u 100 -G whoisgroup whoisuser \
    && apk upgrade --no-cache \
    && apk add --no-cache tzdata ca-certificates traceroute iputils

COPY --from=builder --chown=100:101 /out/whois-app ./whois-app
COPY --from=assets --chown=100:101 /assets/templates ./templates
COPY --from=assets --chown=100:101 /assets/static ./static
COPY --from=assets --chown=100:101 /assets/assets.sha256 ./assets.sha256
COPY --chown=100:101 data ./data
COPY --chown=100:101 --chmod=0555 entrypoint.sh ./entrypoint.sh

# Fail the build if the final runtime copy differs from the deterministic asset stage.
RUN sha256sum -c ./assets.sha256

USER 100:101

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:5000/livez || exit 1

EXPOSE 5000
ENTRYPOINT ["./entrypoint.sh"]
