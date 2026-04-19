# ── Build Stage ───────────────────────────────────────────────
FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o session-server .

# ── Final Stage ───────────────────────────────────────────────
FROM scratch

# Copy binary and default config
COPY --from=builder /app/session-server /session-server
COPY --from=builder /app/config.conf /config.conf

# Certs directory (TLS auto-generate needs it writable)
# Use a volume or pre-bake your real certs
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 6379

ENTRYPOINT ["/session-server", "/config.conf"]
