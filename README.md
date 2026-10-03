# RequestGuard Go

**Go HTTP reverse proxy for IP reputation, country-based filtering, rate limiting, temporary IP bans, and AbuseIPDB integration.**

RequestGuard Go is the Go implementation of the RequestGuard project. The Python implementation is available in [RequestGuard](https://github.com/NanahoshiLusuna/RequestGuard).

**언어 / Language / 言語:** [한국어](#한국어) · [English](#english) · [日本語](#日本語)

---

# 한국어

RequestGuard Go는 로컬 애플리케이션 앞에 배치하여 외부 HTTP 요청을 검사하고, 정책을 통과한 요청만 로컬 애플리케이션으로 전달하는 **경량 Go 리버스 프록시**입니다.

IP 평판, 국가별 정책, 요청 속도, 임시 IP 차단, IP/MAC 화이트리스트 등을 조합하여 간단한 요청 보호 계층을 제공합니다.

Python 구현은 [RequestGuard](https://github.com/NanahoshiLusuna/RequestGuard)에서 확인할 수 있습니다.

## 주요 기능

- **AbuseIPDB 연동**을 통한 IP 평판 조회
- **국가별 정책** 및 평판 기준
- **IP별 속도 제한**
- **임시 IP 차단** 및 만료 관리
- **IP 평판 캐시**
- **IP 및 MAC 화이트리스트**
- **SQLite 영속 저장소**
- 로컬 애플리케이션을 위한 **HTTP 리버스 프록시**
- `LISTEN_PORTS=all` 또는 포트/범위를 이용한 **동일 포트 전달**
- 차단, 평판, 조회, 정리 기능을 제공하는 **CLI**
- **CGO 없이 빌드 가능한 정적 바이너리**
- Linux ARM64 및 **Termux** 지원

## 작동 방식

```text
인터넷
  │
  ▼
┌─────────────────────────┐
│      RequestGuard Go    │
│                         │
│ IP 평판                 │
│ 국가 정책               │
│ 속도 제한               │
│ 차단 / 화이트리스트     │
│ HTTP 요청 검사          │
└────────────┬────────────┘
             │ 허용된 요청
             ▼
       127.0.0.1
       로컬 애플리케이션
```

처음 보는 공개 IP는 설정에 따라 AbuseIPDB에서 국가와 abuse-confidence 정보를 조회할 수 있습니다. 조회 결과는 국가, 평판 점수, 차단 정책 및 속도 제한 기준에 따라 평가됩니다.

검사를 통과한 요청은 설정된 로컬 애플리케이션으로 전달됩니다.

## 기본 정책 예시

| 정책 | 국가 | 평판 기준 | 속도 제한 |
| --- | --- | ---: | ---: |
| Trust | KR, JP | 90 | 60 req/s |
| Mixed | US | 75 | 30 req/s |
| Low | CN 및 기타 | 25 | 10 req/s |

이 값은 환경 변수로 변경할 수 있습니다.

> 위 값은 예시 기본값이며 모든 환경에 동일하게 적용되는 보안 정책이 아닙니다. 실제 서비스의 트래픽과 운영 환경에 맞게 조정하세요.

## 요구 사항

- 빌드 시 **Go 1.22+**
- **AbuseIPDB API 키**
- 일반적으로 `127.0.0.1`에서 대기하는 로컬 애플리케이션

대상 장치에서 Go를 직접 설치할 필요는 없습니다. 다른 환경에서 바이너리를 빌드하여 복사할 수 있습니다.

## 빌드

저장소를 복제합니다.

```sh
git clone https://github.com/NanahoshiLusuna/RequestGuard_Go.git
cd RequestGuard_Go
```

일반 빌드:

```sh
CGO_ENABLED=0 go build -o requestguard ./cmd/requestguard
```

Linux ARM64 / Termux:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o requestguard ./cmd/requestguard
```

생성된 바이너리와 `requestguard.env`를 대상 장치로 복사합니다.

## 설정

설정 파일을 만듭니다.

```sh
cp requestguard.env.example requestguard.env
```

AbuseIPDB API 키를 입력합니다.

```env
ABUSEIPDB_API_KEY=your_api_key
```

예시:

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

전체 설정 항목은 `requestguard.env.example`에서 확인할 수 있습니다.

### 중요

RequestGuard 뒤의 애플리케이션은 일반적으로 다음처럼 루프백에서만 받는 것이 좋습니다.

```text
127.0.0.1
```

RequestGuard를 외부 진입점으로 사용할 경우 업스트림 애플리케이션을 인터넷에 직접 노출하지 마세요.

## 실행

```sh
./requestguard
```

하위 명령 없이 실행하면 프록시 서버가 시작됩니다.

## CLI

현재 차단 목록:

```sh
./requestguard bans
```

평판 캐시:

```sh
./requestguard reputation
```

만료 기록 삭제:

```sh
./requestguard purge
```

IP 평판 조회:

```sh
./requestguard check 8.8.8.8
```

도움말:

```sh
./requestguard --help
```

## 포트 전달

고정된 업스트림 포트와 동일 포트 전달을 모두 지원합니다.

### 고정 업스트림 포트

```env
LISTEN_PORT=8080
UPSTREAM_HOST=127.0.0.1
UPSTREAM_PORT=3000
```

위 설정에서는 외부 `8080` 요청을 `127.0.0.1:3000`으로 전달합니다.

### 동일 포트 전달

```env
LISTEN_PORTS=all
```

외부에서 사용 가능한 포트를 검사하고 클라이언트가 접속한 포트 번호 그대로 `127.0.0.1`의 같은 포트로 전달합니다.

예:

```text
공개 :3000
   │
   ▼
RequestGuard Go
   │
   ▼
127.0.0.1:3000
```

특정 포트와 범위도 사용할 수 있습니다.

```env
LISTEN_PORTS=80,443,3000-3010
```

이미 사용 중인 포트는 건너뜁니다.

## AbuseIPDB

처음 확인하는 공개 IP에 대해 AbuseIPDB에서 평판 정보를 조회할 수 있습니다.

API 키는 AbuseIPDB 계정의 API 페이지에서 발급합니다.

평판 조회가 실패하더라도 그 실패 자체를 자동 허용으로 취급하지 않고, 저장된 차단 기록, 속도 제한 및 요청 형식 검사를 계속 적용합니다.

## 데이터 저장

상태 정보는 SQLite에 저장됩니다.

저장될 수 있는 정보:

- 임시 IP 차단
- IP 평판 캐시
- 만료 정보

만료된 기록:

```sh
./requestguard purge
```

기본 DB 경로:

```text
data/requestguard.db
```

## 보안 모델

RequestGuard Go는 공개 네트워크와 로컬 애플리케이션 사이의 한 계층으로 사용하는 것을 목표로 합니다.

```text
공개 네트워크
      │
      ▼
RequestGuard Go
      │ 허용된 요청
      ▼
127.0.0.1 애플리케이션
```

RequestGuard Go는 **방화벽, TLS 종료, 인증 시스템 또는 완전한 WAF를 대체하지 않습니다.**

필요한 배포 환경에서는 추가적인 보안 계층을 함께 사용하세요.

## 프로젝트 구조

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

---

# English

RequestGuard Go is a lightweight **Go HTTP reverse proxy** that sits in front of a local application, inspects incoming requests, and forwards only requests that pass the configured policies.

It combines IP reputation, country-based policies, rate limiting, temporary IP bans, and IP/MAC whitelisting into a small request-protection layer.

The Python implementation is available in [RequestGuard](https://github.com/NanahoshiLusuna/RequestGuard).

## Features

- **AbuseIPDB integration** for IP reputation checks
- **Country-based policies** and reputation thresholds
- **Per-IP rate limiting**
- **Temporary IP bans** with expiration
- **IP reputation caching**
- **IP and MAC whitelist** support
- **SQLite persistent storage**
- **HTTP reverse proxy** for local applications
- **Same-port forwarding** with `LISTEN_PORTS=all` or selected ports/ranges
- CLI commands for bans, reputation, checks, and cleanup
- **CGO-free static builds**
- Linux ARM64 and **Termux** support

## How it works

```text
Internet
   │
   ▼
┌─────────────────────────┐
│      RequestGuard Go    │
│                         │
│ IP reputation           │
│ Country policy          │
│ Rate limiting           │
│ Ban / whitelist         │
│ HTTP request inspection │
└────────────┬────────────┘
             │ allowed requests
             ▼
       127.0.0.1
       Local application
```

For a previously unseen public IP, RequestGuard Go can query AbuseIPDB for country and abuse-confidence information. The result is evaluated against the configured country, reputation, ban, and rate-limit policies.

Requests that pass the checks are forwarded to the configured local application.

## Default policy example

| Policy | Countries | Reputation threshold | Rate limit |
| --- | --- | ---: | ---: |
| Trust | KR, JP | 90 | 60 req/s |
| Mixed | US | 75 | 30 req/s |
| Low | CN and others | 25 | 10 req/s |

These values can be changed through environment variables.

> These values are example defaults, not a universal security policy. Adjust them for your deployment and expected traffic.

## Requirements

- **Go 1.22+** for building
- An **AbuseIPDB API key**
- A local application, normally listening on `127.0.0.1`

Go does not have to be installed on the target device if you build the binary elsewhere.

## Build

Clone the repository:

```sh
git clone https://github.com/NanahoshiLusuna/RequestGuard_Go.git
cd RequestGuard_Go
```

Native build:

```sh
CGO_ENABLED=0 go build -o requestguard ./cmd/requestguard
```

Linux ARM64 / Termux:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o requestguard ./cmd/requestguard
```

Copy the resulting binary and `requestguard.env` to the target device.

## Configuration

Create the configuration file:

```sh
cp requestguard.env.example requestguard.env
```

Set the AbuseIPDB API key:

```env
ABUSEIPDB_API_KEY=your_api_key
```

Example:

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

The application behind RequestGuard Go should normally listen on loopback:

```text
127.0.0.1
```

Do not expose the upstream application directly if RequestGuard Go is intended to be the public entry point.

## Run

```sh
./requestguard
```

With no subcommand, RequestGuard Go starts the proxy server.

## CLI

Show active bans:

```sh
./requestguard bans
```

Show cached reputation:

```sh
./requestguard reputation
```

Remove expired records:

```sh
./requestguard purge
```

Check an IP through AbuseIPDB:

```sh
./requestguard check 8.8.8.8
```

Show help:

```sh
./requestguard --help
```

## Port forwarding

RequestGuard Go supports both a fixed upstream port and same-port forwarding.

### Fixed upstream port

```env
LISTEN_PORT=8080
UPSTREAM_HOST=127.0.0.1
UPSTREAM_PORT=3000
```

With this configuration, requests received on public port `8080` are forwarded to `127.0.0.1:3000`.

### Same-port forwarding

```env
LISTEN_PORTS=all
```

RequestGuard Go listens on available external ports and forwards each request to the same port on `127.0.0.1`.

Example:

```text
Public :3000
    │
    ▼
RequestGuard Go
    │
    ▼
127.0.0.1:3000
```

Specific ports and ranges are also supported:

```env
LISTEN_PORTS=80,443,3000-3010
```

Busy ports are skipped.

## AbuseIPDB

RequestGuard Go can query AbuseIPDB for reputation information for previously unseen public IP addresses.

The API key is obtained from the AbuseIPDB account API page.

If the reputation lookup fails, RequestGuard Go does not treat the failure itself as an automatic allow. Stored bans, rate limits, and request-format checks continue to apply.

## Data storage

Persistent state is stored in SQLite.

Stored information can include:

- Temporary IP bans
- IP reputation cache
- Expiration information

Remove expired records with:

```sh
./requestguard purge
```

Default database path:

```text
data/requestguard.db
```

## Security model

RequestGuard Go is intended to be one layer between the public network and a local application.

```text
Public network
      │
      ▼
RequestGuard Go
      │ allowed requests
      ▼
127.0.0.1 application
```

RequestGuard Go is **not a replacement for a firewall, TLS termination, authentication, or a full WAF**.

Use additional security controls when your deployment requires stronger protection.

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

---

# 日本語

RequestGuard Go は、ローカルアプリケーションの前段に配置し、受信したHTTPリクエストを検査して、設定されたポリシーを通過したリクエストだけをローカルアプリケーションへ転送する **軽量なGo製HTTPリバースプロキシ**です。

IPレピュテーション、国別ポリシー、レート制限、一時的なIPブロック、IP/MACホワイトリストを組み合わせ、シンプルなリクエスト保護レイヤーを提供します。

Python実装は [RequestGuard](https://github.com/NanahoshiLusuna/RequestGuard) で確認できます。

## 主な機能

- **AbuseIPDB連携**によるIPレピュテーション確認
- **国別ポリシー**とレピュテーション基準
- **IP単位のレート制限**
- 有効期限付きの**一時IPブロック**
- **IPレピュテーションキャッシュ**
- **IPおよびMACホワイトリスト**
- **SQLite永続ストレージ**
- ローカルアプリケーション向け**HTTPリバースプロキシ**
- `LISTEN_PORTS=all` またはポート・範囲を指定する**同一ポート転送**
- ブロック、レピュテーション、確認、クリーンアップ用CLI
- **CGOなしでビルドできる静的バイナリ**
- Linux ARM64 および **Termux** 対応

## 動作方式

```text
インターネット
    │
    ▼
┌─────────────────────────┐
│     RequestGuard Go     │
│                         │
│ IPレピュテーション      │
│ 国別ポリシー            │
│ レート制限              │
│ ブロック / ホワイトリスト │
│ HTTPリクエスト検査      │
└────────────┬────────────┘
             │ 許可されたリクエスト
             ▼
        127.0.0.1
        ローカルアプリ
```

初めて確認する公開IPについて、設定に応じてAbuseIPDBから国情報とabuse-confidence情報を取得できます。結果は、設定された国別ポリシー、レピュテーション、ブロック、レート制限の基準に従って評価されます。

検査を通過したリクエストは、設定されたローカルアプリケーションへ転送されます。

## デフォルトポリシーの例

| ポリシー | 国 | レピュテーション基準 | レート制限 |
| --- | --- | ---: | ---: |
| Trust | KR, JP | 90 | 60 req/s |
| Mixed | US | 75 | 30 req/s |
| Low | CN およびその他 | 25 | 10 req/s |

これらの値は環境変数で変更できます。

> これらは設定例としてのデフォルト値であり、すべての環境に適した普遍的なセキュリティポリシーではありません。実際のトラフィックと運用環境に合わせて調整してください。

## 必要環境

- ビルドに **Go 1.22+**
- **AbuseIPDB APIキー**
- 通常は `127.0.0.1` で待ち受けるローカルアプリケーション

対象端末にGoをインストールする必要はありません。別の環境でビルドしたバイナリをコピーして使用できます。

## ビルド

リポジトリをクローンします。

```sh
git clone https://github.com/NanahoshiLusuna/RequestGuard_Go.git
cd RequestGuard_Go
```

通常のビルド:

```sh
CGO_ENABLED=0 go build -o requestguard ./cmd/requestguard
```

Linux ARM64 / Termux:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o requestguard ./cmd/requestguard
```

生成されたバイナリと `requestguard.env` を対象端末へコピーします。

## 設定

設定ファイルを作成します。

```sh
cp requestguard.env.example requestguard.env
```

AbuseIPDB APIキーを設定します。

```env
ABUSEIPDB_API_KEY=your_api_key
```

例:

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

完全な設定項目は `requestguard.env.example` を参照してください。

### 重要

RequestGuard Go の背後にあるアプリケーションは、通常ループバックのみで待ち受けるようにします。

```text
127.0.0.1
```

RequestGuard Go を公開入口として使用する場合、アップストリームアプリケーションをインターネットへ直接公開しないでください。

## 実行

```sh
./requestguard
```

サブコマンドなしで起動すると、プロキシサーバーを開始します。

## CLI

現在のブロック一覧:

```sh
./requestguard bans
```

レピュテーションキャッシュ:

```sh
./requestguard reputation
```

期限切れ記録の削除:

```sh
./requestguard purge
```

AbuseIPDBによるIP確認:

```sh
./requestguard check 8.8.8.8
```

ヘルプ:

```sh
./requestguard --help
```

## ポート転送

固定アップストリームポートと同一ポート転送の両方をサポートします。

### 固定アップストリームポート

```env
LISTEN_PORT=8080
UPSTREAM_HOST=127.0.0.1
UPSTREAM_PORT=3000
```

この設定では、公開 `8080` 番ポートへのリクエストを `127.0.0.1:3000` に転送します。

### 同一ポート転送

```env
LISTEN_PORTS=all
```

使用可能な外部ポートで待ち受け、クライアントが接続したポート番号と同じ番号の `127.0.0.1` へ転送します。

例:

```text
公開 :3000
   │
   ▼
RequestGuard Go
   │
   ▼
127.0.0.1:3000
```

特定のポートや範囲も指定できます。

```env
LISTEN_PORTS=80,443,3000-3010
```

使用中のポートはスキップされます。

## AbuseIPDB

初めて確認する公開IPについて、AbuseIPDBからレピュテーション情報を取得できます。

APIキーはAbuseIPDBアカウントのAPIページから発行します。

レピュテーション検索が失敗しても、その失敗自体を自動許可として扱いません。保存済みのブロック、レート制限、リクエスト形式検査は継続して適用されます。

## データ保存

永続状態はSQLiteに保存されます。

保存される情報には以下が含まれます。

- 一時IPブロック
- IPレピュテーションキャッシュ
- 有効期限情報

期限切れ記録の削除:

```sh
./requestguard purge
```

デフォルトのデータベースパス:

```text
data/requestguard.db
```

## セキュリティモデル

RequestGuard Go は、公開ネットワークとローカルアプリケーションの間に配置する1つの保護レイヤーとして設計されています。

```text
公開ネットワーク
      │
      ▼
RequestGuard Go
      │ 許可されたリクエスト
      ▼
127.0.0.1 アプリケーション
```

RequestGuard Go は、**ファイアウォール、TLS終端、認証システム、完全なWAFの代替ではありません。**

より強い保護が必要な環境では、追加のセキュリティ対策を併用してください。

## プロジェクト構成

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

---

## License / 라이선스 / ライセンス

No license file is currently included in this repository.
