FROM node:26.8.2-alpine3.24@sha256:ef24c5053d50fdc3e4e56eb4e7ddb7861874ab0fdc797046ba897581deb8e868 AS assets
WORKDIR /assets
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY scripts ./scripts
COPY static ./static
COPY templates ./templates
RUN npm run build:assets && npm run assets:check

FROM golang:1.27.1-alpine3.24@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/whois-app ./cmd/server

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS runtime
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
