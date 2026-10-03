# RequestGuard

**RequestGuard is a lightweight Go HTTP reverse proxy for IP reputation filtering, country-based policies, rate limiting, and temporary IP bans.**

It sits in front of a local application and forwards allowed requests to `127.0.0.1`. It is designed for small self-hosted services, home servers, and deployments that need a simple **IP filtering and request protection layer** without a large security stack.

## Features

- **IP reputation checking** with [AbuseIPDB](https://www.abuseipdb.com/)
- **Country-based request policies**
- **Temporary IP bans**
- **Per-IP rate limiting**
- **IP reputation caching**
- **IP and MAC whitelist support**
- **SQLite persistent storage**
- **HTTP reverse proxy** to local applications
- **Same-port forwarding** with `LISTEN_PORTS=all` or selected ports/ranges
- CLI commands for bans, reputation, checks, and cleanup
- **CGO-free static binary** builds
- Linux ARM64 support, including **Termux**

## How it works

```text
Internet
   │
   ▼
┌─────────────────────────┐
│       RequestGuard      │
│                         │
│ IP reputation           │
│ Country policy          │
│ Rate limiting           │
│ Ban / whitelist         │
│ Request filtering       │
└────────────┬────────────┘
             │ allowed requests
             ▼
       127.0.0.1
       Local application
```

For a previously unseen public IP, RequestGuard can query AbuseIPDB for country and abuse-confidence information. The result is evaluated against the configured country, reputation, ban, and rate-limit policies.

If the request passes the checks, RequestGuard forwards it to the configured local application.

## Policy example

The default configuration provides three policy groups:

| Policy | Countries | Reputation threshold | Rate limit |
| --- | --- | ---: | ---: |
| Trust | KR, JP | 90 | 60 req/s |
| Mixed | US | 75 | 30 req/s |
| Low | CN and others | 25 | 10 req/s |

These values are configurable through environment variables.

> **Note:** The default policy is an example, not a universal security recommendation. Adjust it for your deployment and expected traffic.

## Requirements

- Go **1.22+** for building
- An AbuseIPDB API key
- A local application listening on `127.0.0.1`

Go does not need to be installed on the target device if you build the binary elsewhere.

## Build

Clone the repository:

```sh
git clone https://github.com/NanahoshiLusuna/RequestGuard_Go.git
cd RequestGuard_Go
```

Build a native binary:

```sh
CGO_ENABLED=0 go build -o requestguard ./cmd/requestguard
```

### Linux ARM64 / Termux

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o requestguard ./cmd/requestguard
```

Copy the resulting binary and `requestguard.env` to the target device.

## Configuration

Create the configuration file:

```sh
cp requestguard.env.example requestguard.env
```

Set your AbuseIPDB API key:

```env
ABUSEIPDB_API_KEY=your_api_key
```

Example configuration:

```env
LISTEN_HOST=0.0.0.0
LISTEN_PORTS=all

UPSTREAM_HOST=127.0.0.1
UPSTREAM_PORT=3000

ABUSE_SCORE_THRESHOLD=75

TRUST_COUNTRIES=KR,JP
TRUST_SCORE_THRESHOLD=90
TRUST_RATE_LIMIT_PER_SEC=60

MIXED_COUNTRIES=US

LOW_SCORE_THRESHOLD=25
LOW_RATE_LIMIT_PER_SEC=10

BAN_DAYS=30
MAX_BAN_DAYS=365

RATE_LIMIT_PER_SEC=30
WHITELIST=
```

See `requestguard.env.example` for the complete configuration reference.

### Important

The application behind RequestGuard should normally listen on:

```text
127.0.0.1
```

Do not expose the upstream application directly if RequestGuard is intended to be the public entry point.

## Run

Start RequestGuard:

```sh
./requestguard
```

With no subcommand, RequestGuard starts the proxy server.

## CLI

Show active bans:

```sh
./requestguard bans
```

Show cached IP reputation:

```sh
./requestguard reputation
```

Remove expired records:

```sh
./requestguard purge
```

Check an IP with AbuseIPDB:

```sh
./requestguard check 8.8.8.8
```

Show help:

```sh
./requestguard --help
```

## Port forwarding

RequestGuard supports a fixed upstream port as well as same-port forwarding.

### Fixed upstream

With:

```env
LISTEN_PORT=8080
UPSTREAM_HOST=127.0.0.1
UPSTREAM_PORT=3000
```

requests received on port 8080 are forwarded to `127.0.0.1:3000`.

### Same-port forwarding

Set:

```env
LISTEN_PORTS=all
```

to listen on available external ports and forward each request to the same port on `127.0.0.1`.

For example:

```text
Public :3000
    │
    ▼
RequestGuard
    │
    ▼
127.0.0.1:3000
```

Specific ports and ranges are also supported, for example:

```env
LISTEN_PORTS=80,443,3000-3010
```

Busy ports are skipped.

## AbuseIPDB

RequestGuard uses AbuseIPDB to obtain reputation information for previously unseen public IP addresses.

The API key can be obtained from the AbuseIPDB account API page.

If the reputation lookup fails, RequestGuard falls back to stored ban, rate-limit, and request-format checks rather than treating the lookup failure itself as an automatic allow.

## Data storage

RequestGuard stores persistent state in SQLite.

Stored information includes:

- Temporary IP bans
- Cached IP reputation results
- Expiration information

Expired records can be removed with:

```sh
./requestguard purge
```

The default database path is:

```text
data/requestguard.db
```

## Security model

RequestGuard is intended to be one layer between the public network and a local application:

```text
Public network
      │
      ▼
 RequestGuard
      │
      │ allowed requests
      ▼
127.0.0.1 application
```

RequestGuard is **not a replacement for a firewall, TLS termination, authentication, or a full WAF**.

Use additional controls when your deployment requires stronger protection.

## Project structure

```text
RequestGuard_Go/
├── cmd/
│   └── requestguard/
│       └── main.go
├── internal/
│   └── rg/
├── go.mod
├── go.sum
├── requestguard.env.example
└── README.md
```

## License

See the repository for the current license information.
