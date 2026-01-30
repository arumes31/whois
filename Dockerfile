# Build Stage
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o whois-app cmd/server/main.go

# Runtime Stage
FROM alpine:latest
LABEL author="arumes31" maintainer="https://github.com/arumes31"
WORKDIR /app

# Create non-root user
RUN addgroup -S whoisgroup && adduser -S whoisuser -G whoisgroup

RUN apk add --no-cache tzdata ca-certificates traceroute iputils su-exec
COPY --from=builder /app/whois-app .
COPY templates ./templates
COPY static ./static
COPY data ./data
COPY entrypoint.sh ./entrypoint.sh

# Ensure user can read templates, static, and data, and entrypoint is executable
RUN chown -R whoisuser:whoisgroup /app && chmod +x ./entrypoint.sh

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:5000/health || exit 1

EXPOSE 5000
ENTRYPOINT ["./entrypoint.sh"]