# Go Session Server

A **lightweight, Redis-protocol-compatible** session cache written in pure Go.  
Zero external dependencies. Drop-in replacement for Redis when used with Spring Boot session management.

---

## Architecture

```
Spring Boot (Lettuce/Jedis)
        │
        │  RESP Protocol  (optionally over TLS)
        ▼
┌──────────────────────────────────────────────┐
│            Go Session Server                 │
│                                              │
│  ┌─────────────┐   ┌──────────────────────┐  │
│  │ IP Allowlist│──►│  AUTH (password)     │  │
│  │ (CIDR+exact)│   └──────────┬───────────┘  │
│  └─────────────┘              │              │
│                    ┌──────────▼───────────┐  │
│                    │  Command Dispatcher  │  │
│                    │  SET/GET/DEL/TTL/…   │  │
│                    └──────────┬───────────┘  │
│                    ┌──────────▼───────────┐  │
│                    │  Sharded Store       │  │
│                    │  256 × sync.RWMutex  │  │
│                    └──────────┬───────────┘  │
│                    ┌──────────▼───────────┐  │
│                    │  TTL Sweeper         │  │
│                    │  (background goroutine)  │
│                    └──────────────────────┘  │
└──────────────────────────────────────────────┘
```

---

## Security Layers

| Layer | Mechanism |
|---|---|
| **Network** | IP Allowlist — exact IP or CIDR range |
| **Protocol** | Redis `AUTH` password on every connection |
| **Transport** | Optional TLS 1.2+ with strong cipher suites |
| **Loopback** | `127.0.0.1` / `::1` always permitted (local health checks) |
| **TTL cap** | `SESSION_MAX_TTL` clamps any runaway session lifetime |

---

## Quick Start

```bash
# Build
go build -ldflags="-s -w" -o session-server ./cmd/server

# Run (uses config.conf in current directory)
./session-server

# Or specify config path
./session-server /etc/session-server/config.conf
```

### Docker

```bash
docker build -t go-session-server .
docker run -p 6379:6379 \
  -e AUTH_PASSWORD=mysecret \
  -e AUTH_ALLOWED_IPS="10.0.0.0/24,192.168.1.5" \
  go-session-server
```

---

## Configuration (`config.conf`)

All settings can also be set as **environment variables** (same key name).

### IP Allowlist

```ini
# Single IP
AUTH_ALLOWED_IPS=192.168.1.50

# CIDR subnet
AUTH_ALLOWED_IPS=10.0.0.0/24

# Mixed (comma-separated)
AUTH_ALLOWED_IPS=10.0.0.0/24, 192.168.5.20

# Empty = allow ALL IPs (dev only)
AUTH_ALLOWED_IPS=
```

Rules:
- Only listed entries can connect; loopback has **no** implicit exception — add `127.0.0.1` / `::1` explicitly if localhost should access the server
- Invalid entries are skipped with a warning at startup
- Connection is dropped before AUTH if the IP is not allowed

### Session TTL

```ini
SESSION_DEFAULT_TTL=30m    # fallback when Spring sends SET without EX
SESSION_MAX_TTL=24h        # hard cap — clamps any larger EX value
SESSION_SWEEP_INTERVAL=1m  # how often expired keys are purged
```

### TLS

```ini
TLS_ENABLED=true
TLS_CERT_FILE=certs/server.crt
TLS_KEY_FILE=certs/server.key
# Missing cert files → self-signed cert is auto-generated on startup
```

---

## Spring Boot Setup

### `pom.xml`

```xml
<dependency>
    <groupId>org.springframework.session</groupId>
    <artifactId>spring-session-data-redis</artifactId>
</dependency>
<dependency>
    <groupId>io.lettuce</groupId>
    <artifactId>lettuce-core</artifactId>
</dependency>
```

### `application.properties`

```properties
# Point at your Go session server — no other code changes needed
spring.data.redis.host=192.168.1.10
spring.data.redis.port=6379
spring.data.redis.password=change-me-strong-password

# TLS (if enabled on server)
# spring.data.redis.ssl.enabled=true

# Session config
spring.session.store-type=redis
spring.session.redis.namespace=spring:session
spring.session.redis.flush-mode=on_save

# ★ THIS sets the TTL sent to the Go server via EX <seconds>
spring.session.timeout=30m
```

### How TTL flows end-to-end

```
application.properties          Go Session Server
─────────────────────           ─────────────────────────────────
spring.session.timeout=30m  →  SET key value EX 1800
                                   ↓
                               stores key with TTL = 1800s
                               (capped to SESSION_MAX_TTL if exceeded)

spring.session.timeout=0    →  SET key value  (no EX)
                                   ↓
                               stores key with SESSION_DEFAULT_TTL
```

---

## Monitoring

```bash
redis-cli -h 192.168.1.10 -p 6379 -a yourpassword INFO
```

Output includes:
- `connected_clients`
- `total_keys`
- `keyspace_hits` / `keyspace_misses`
- `default_ttl_seconds` / `max_ttl_seconds`
- `ip_allowlist` — shows configured rules
- `tls_enabled` / `auth_required`

---

## Performance

| Metric | Result |
|---|---|
| Binary size | **4 MB** |
| Idle RAM | **~5 MB** |
| 10k sessions (1KB each) | **~15 MB** |
| SET throughput | **~4.2M ops/sec** |
| GET throughput | **~7.4M ops/sec** |
| GET allocations | **0 allocs/op** |

---

## Supported RESP Commands

`AUTH` `PING` `QUIT` `RESET`  
`SET` (EX / PX / NX / XX / KEEPTTL) `GET` `DEL` `EXISTS`  
`SETNX` `SETEX` `GETSET` `GETDEL`  
`EXPIRE` `EXPIREAT` `PEXPIRE` `TTL` `PTTL`  
`FLUSHALL` `FLUSHDB` `DBSIZE` `INFO`  
`CONFIG GET/SET/RESETSTAT` `SELECT` `COMMAND` `CLIENT`
