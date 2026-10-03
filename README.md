# RequestGuard (Go)

Python 구현과 같은 검문 프록시다. 설치 없이 실행 파일 하나만 복사해서 켠다.

바깥 주소의 포트를 검사하고, 통과한 요청을 `127.0.0.1`의 같은 포트로 넘긴다. 앱은 `127.0.0.1`에만 바인드한다.

## 빌드

Go 1.22 이상이 있는 기기에서 빌드한다. 폰에는 Go를 설치하지 않는다.

```sh
cd RequestGuardGo
CGO_ENABLED=0 go build -o requestguard ./cmd/requestguard
```

Termux(arm64)용:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o requestguard ./cmd/requestguard
```

만든 파일을 폰에 복사하고, 같은 디렉터리에 `requestguard.env`를 둔다.

```sh
cp requestguard.env.example requestguard.env
# ABUSEIPDB_API_KEY만 채운다.
./requestguard
```

## 동작

처음 보는 공개 IP는 AbuseIPDB로 국가와 점수를 본다. 조회가 실패하면 저장된 차단, 속도, 형식으로만 판단한다.

| 순위 | 국가 | 점수 | 초당 연결 |
|---|---|---|---|
| 신뢰 | 한국, 일본 | 90 | 60 |
| 애매 | 미국 | 75 | 30 |
| 엄격 | 중국과 그 외 | 25 | 10 |

같은 망의 MAC이 보이면 IP와 함께 센다. 라우터 너머의 MAC은 보이지 않는다.

```sh
./requestguard bans
./requestguard reputation
./requestguard purge
./requestguard check 8.8.8.8
```

앱이 바깥에 보이는 주소와 다른 공개 URL을 써야 하면, 앱의 수신 주소는 `127.0.0.1`로 두고 `PUBLIC_BASE_URL`만 공개 주소로 둔다.
