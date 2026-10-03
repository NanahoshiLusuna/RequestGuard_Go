package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"requestguard/internal/rg"
)

const helpText = `RequestGuard — 앱 앞에 두는 요청 검문

  requestguard              프록시를 실행합니다
  requestguard bans         남은 차단을 봅니다
  requestguard reputation   블랙리스트 조회 캐시를 봅니다
  requestguard purge        만료된 기록을 지웁니다
  requestguard check <ip>   AbuseIPDB 점수만 조회합니다

처음 보는 공개 IP의 첫 요청은 AbuseIPDB로 국가와 점수를 확인합니다.
한국·일본은 신뢰, 미국은 애매, 중국과 그 외는 엄격합니다.
국가를 모르거나 조회가 실패하면 저장된 차단, 속도, 형식으로 판단합니다.
LISTEN_PORTS=all 이면 바깥 주소의 모든 포트를 검사하고, 같은 번호의 127.0.0.1으로 넘깁니다.
앱은 127.0.0.1에서만 받으세요.
설정 파일은 실행 디렉터리의 requestguard.env 입니다.
API 키는 https://www.abuseipdb.com/account/api 에서 발급합니다.
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		fmt.Print(helpText)
		return 0
	}
	log.SetFlags(log.LstdFlags)
	rg.LoadEnvFiles()
	cfg, err := rg.ConfigFromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2
	}
	store, err := rg.OpenStore(cfg.DBPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}
	defer store.Close()
	command := "serve"
	if len(args) > 0 {
		command = args[0]
	}
	switch command {
	case "bans":
		printBans(store)
		return 0
	case "reputation":
		printReputation(store, cfg)
		return 0
	case "purge":
		n, err := store.Purge(time.Now())
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		fmt.Printf("removed %d\n", n)
		return 0
	case "check":
		if len(args) != 2 {
			fmt.Fprint(os.Stderr, helpText)
			return 2
		}
		return check(cfg, args[1])
	case "serve":
		if n, err := store.Purge(time.Now()); err == nil && n > 0 {
			log.Printf("purged %d", n)
		}
		abuse := rg.NewAbuse(cfg.APIKey, cfg.AbuseMaxAgeDays, cfg.AbuseTimeoutSec)
		gate := rg.NewGate(cfg, store, abuse)
		go func() {
			for {
				time.Sleep(time.Hour)
				if n, err := store.Purge(time.Now()); err == nil && n > 0 {
					log.Printf("purged %d", n)
				}
			}
		}()
		if err := rg.Serve(cfg, gate); err != nil {
			log.Printf("serve: %v", err)
			return 1
		}
		return 0
	default:
		fmt.Fprint(os.Stderr, helpText)
		return 2
	}
}

func printBans(store *rg.Store) {
	rows, err := store.ListBans(time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	if len(rows) == 0 {
		fmt.Println("no bans")
		return
	}
	for _, ban := range rows {
		when := time.Unix(ban.ExpiresAt, 0).UTC().Format("2006-01-02T15:04:05Z")
		fmt.Printf("%s\t%s\t%s\t%s\n", ban.IP, ban.Reason, when, ban.Detail)
	}
}

func printReputation(store *rg.Store, cfg rg.Config) {
	rows, err := store.ListReputation(time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	if len(rows) == 0 {
		fmt.Println("no reputation cache")
		return
	}
	for _, row := range rows {
		when := time.Unix(row.ExpiresAt, 0).UTC().Format("2006-01-02T15:04:05Z")
		rank := rg.RankFor(row.Country, cfg)
		if rank == "" {
			rank = "-"
		}
		country := row.Country
		if country == "" {
			country = "-"
		}
		fmt.Printf("%s\tscore=%d\tcountry=%s\trank=%s\texpires=%s\t%s\n", row.IP, row.Score, country, rank, when, row.Detail)
	}
}

func check(cfg rg.Config, raw string) int {
	ip, err := rg.NormalizeIP(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid ip")
		return 2
	}
	result := rg.NewAbuse(cfg.APIKey, cfg.AbuseMaxAgeDays, cfg.AbuseTimeoutSec).Check(ip)
	if !result.OK {
		fmt.Fprintf(os.Stderr, "check failed: %s\n", result.Error)
		return 1
	}
	rank := rg.RankFor(result.Country, cfg)
	threshold := rg.ScoreThreshold(rank, cfg)
	blocked := result.Score >= threshold
	country := result.Country
	if country == "" {
		country = "-"
	}
	shown := rank
	if shown == "" {
		shown = "-"
	}
	fmt.Printf("%s score=%d country=%s rank=%s threshold=%d block=%t\n", ip, result.Score, country, shown, threshold, blocked)
	return 0
}
