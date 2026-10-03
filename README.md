# RequestGuard

**RequestGuard is a lightweight Go reverse proxy that filters incoming requests using IP reputation, country-based policies, rate limiting, and temporary IP bans.**

It runs in front of a local application and forwards allowed requests to `127.0.0.1`.

RequestGuard is designed for small self-hosted services, home servers, and applications that need a simple **IP filtering and request protection layer** without running a large security stack.

## Features

* **IP reputation checking** with [AbuseIPDB](https://www.abuseipdb.com/)
* **Country-based request policies**
* **IP blocking and temporary bans**
* **Per-IP rate limiting**
* **IP reputation caching**
* **Whitelist support**
* **SQLite-based persistent storage**
* **Reverse proxy** to local applications
* **All-port forwarding** with `LISTEN_PORTS=all`
* CLI commands for inspecting bans and reputation data
* **Single static binary** with `CGO_ENABLED=0`
* Linux ARM64 support, including **Termux**

## How it works

```text
Internet
   │
   ▼
┌──────────────────────┐
│     RequestGuard     │
│                      │
│ IP reputation        │
│ Country policy       │
│ Rate limiting        │
│ Ban / whitelist      │
└──────────┬───────────┘
           │
           ▼
     127.0.0.1
     Local application
```

Incoming requests are checked before they reach the local application.

For a new public IP, RequestGuard can query AbuseIPDB to obtain its country and abuse confidence score.

The result is then evaluated against the configured country, reputation, ban, and rate-limit policies.

If a request passes the checks, it is forwarded to the configured local application.

## Policy example

The default configuration separates IPs into three policy groups:

| Policy | Countries     | Reputation threshold | Rate limit |
| ------ | ------------- | -------------------: | ---------: |
| Trust  | KR, JP        |                   90 |   60 req/s |
| Mixed  | US            |                   75 |   30 req/s |
| Low    | CN and others |                   25 |   10 req/s |

These values are configurable through environment variables.

**The default policy is only an example. Adjust it for your own deployment.**

## Requirements

* Go **1.22+** for building
* An AbuseIPDB API key
* A local application listening on `127.0.0.1`

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

The resulting `requestguard` binary can be copied to the target machine.

### Linux ARM64 / Termux

Build an ARM64 Linux binary:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o requestguard ./cmd/requestguard
```

Copy the binary to the device together with `requestguard.env`.

## Configuration

Create the configuration file:

```sh
cp requestguard.env.example requestguard.env
```

Set your AbuseIPDB API key:

```env
ABUSEIPDB_API_KEY=your_api_key
```

The main configuration options include:

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

### Important

The application behind RequestGuard should listen on:

```text
127.0.0.1
```

Do not expose the upstream application directly if RequestGuard is intended to be the public entry point.

## Run

Start RequestGuard:

```sh
./requestguard
```

By default, the program starts the proxy server.

## CLI commands

### Show active bans

```sh
./requestguard bans
```

### Show cached IP reputation

```sh
./requestguard reputation
```

### Remove expired records

```sh
./requestguard purge
```

### Check an IP with AbuseIPDB

```sh
./requestguard check 8.8.8.8
```

### Show help

```sh
./requestguard --help
```

## Port forwarding

Set:

```env
LISTEN_PORTS=all
```

to inspect all available ports and forward a request to the same port on `127.0.0.1`.

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

This allows multiple local services to remain bound to loopback while RequestGuard acts as the public filtering layer.

## Public URL

If the application needs to know its public URL, configure:

```env
PUBLIC_BASE_URL=https://example.com
```

The application can continue listening on:

```text
127.0.0.1
```

while `PUBLIC_BASE_URL` represents the externally visible address.

## AbuseIPDB

RequestGuard uses AbuseIPDB to obtain reputation information for previously unseen public IP addresses.

The API key can be obtained from:

https://www.abuseipdb.com/account/api

If the reputation lookup fails, RequestGuard falls back to its stored ban, rate-limit, and request-format checks.

## Data storage

RequestGuard stores persistent state using SQLite.

This includes information such as:

* Temporary IP bans
* Cached IP reputation results
* Expiration information

Expired records can be removed with:

```sh
./requestguard purge
```

## Security model

RequestGuard is intended to sit between the public network and a local application:

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

This means the upstream application does not need to be directly exposed to the network.

However, RequestGuard is **not a replacement for a firewall, TLS termination, authentication, or a full WAF**.

Use it as one layer of a larger deployment when stronger protection is required.

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
