# Build Stage
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o whois-app cmd/server/main.go

# Runtime Stage
FROM alpine:latest
WORKDIR /app

# Create non-root user
RUN addgroup -S whoisgroup && adduser -S whoisuser -G whoisgroup

RUN apk add --no-cache tzdata ca-certificates
COPY --from=builder /app/whois-app .
COPY templates ./templates
COPY static ./static

# Ensure user can read templates and static
RUN chown -R whoisuser:whoisgroup /app

USER whoisuser

EXPOSE 5000
CMD ["./whois-app"]