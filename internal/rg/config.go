package rg

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	APIKey               string
	ListenHost           string
	ListenPort           int
	UpstreamHost         string
	UpstreamPort         int
	ListenAll            bool
	ListenPorts          []int
	SamePort             bool
	AbuseScoreThreshold  int
	AbuseMaxAgeDays      int
	BanDays              int
	MaxBanDays           int
	RateLimitPerSec      int
	TrustCountries       map[string]struct{}
	MixedCountries       map[string]struct{}
	TrustScoreThreshold  int
	TrustRateLimitPerSec int
	LowScoreThreshold    int
	LowRateLimitPerSec   int
	Whitelist            map[string]struct{}
	DBPath               string
	RequestTimeoutSec    float64
	AbuseTimeoutSec      float64
	MaxConnections       int
	MaxHeaderBytes       int
	MaxHeaderLine        int
	MaxHeaders           int
	MaxTargetBytes       int
	MaxBodyBytes         int
	AbsurdBodyBytes      int
	MaxDotDot            int
}

func DefaultConfig(apiKey string) Config {
	return Config{
		APIKey:               apiKey,
		ListenHost:           "0.0.0.0",
		ListenPort:           8080,
		UpstreamHost:         "127.0.0.1",
		UpstreamPort:         3000,
		AbuseScoreThreshold:  75,
		AbuseMaxAgeDays:      30,
		BanDays:              30,
		MaxBanDays:           365,
		RateLimitPerSec:      30,
		TrustCountries:       setOf("JP", "KR"),
		MixedCountries:       setOf("US"),
		TrustScoreThreshold:  90,
		TrustRateLimitPerSec: 60,
		LowScoreThreshold:    25,
		LowRateLimitPerSec:   10,
		Whitelist:            map[string]struct{}{},
		DBPath:               "data/requestguard.db",
		RequestTimeoutSec:    15,
		AbuseTimeoutSec:      5,
		MaxConnections:       64,
		MaxHeaderBytes:       32 * 1024,
		MaxHeaderLine:        8 * 1024,
		MaxHeaders:           100,
		MaxTargetBytes:       8 * 1024,
		MaxBodyBytes:         1024 * 1024,
		AbsurdBodyBytes:      32 * 1024 * 1024,
	}
}

func LoadEnvFiles() {
	loadEnvFile("requestguard.env")
	if exe, err := os.Executable(); err == nil {
		loadEnvFile(dirJoin(exeDir(exe), "requestguard.env"))
	}
}

func ConfigFromEnv() (Config, error) {
	apiKey := strings.TrimSpace(os.Getenv("ABUSEIPDB_API_KEY"))
	if apiKey == "" {
		return Config{}, fmt.Errorf("ABUSEIPDB_API_KEY가 없습니다. https://www.abuseipdb.com/account/api 에서 발급한 키를 requestguard.env에 넣으세요. 가입 확인 링크는 API 키가 아닙니다.")
	}
	if strings.HasPrefix(apiKey, "http://") || strings.HasPrefix(apiKey, "https://") {
		return Config{}, fmt.Errorf("ABUSEIPDB_API_KEY에는 가입 확인 링크가 아니라 계정 API 페이지에서 발급한 키를 넣으세요.")
	}
	banDays, err := envInt("BAN_DAYS", 30, 1, 3650)
	if err != nil {
		return Config{}, err
	}
	maxBan, err := envInt("MAX_BAN_DAYS", 365, banDays, 3650)
	if err != nil {
		return Config{}, err
	}
	trust, err := countries("TRUST_COUNTRIES", "KR,JP")
	if err != nil {
		return Config{}, err
	}
	mixed, err := countries("MIXED_COUNTRIES", "US")
	if err != nil {
		return Config{}, err
	}
	var overlap []string
	for code := range trust {
		if _, ok := mixed[code]; ok {
			overlap = append(overlap, code)
		}
	}
	if len(overlap) > 0 {
		return Config{}, fmt.Errorf("TRUST_COUNTRIES와 MIXED_COUNTRIES에 같은 국가가 있습니다: %s", strings.Join(overlap, ", "))
	}
	listenHost := strings.TrimSpace(os.Getenv("LISTEN_HOST"))
	if listenHost == "" {
		listenHost = "0.0.0.0"
	}
	listenPort, err := envInt("LISTEN_PORT", 8080, 1, 65535)
	if err != nil {
		return Config{}, err
	}
	upstreamHost := strings.TrimSpace(os.Getenv("UPSTREAM_HOST"))
	if upstreamHost == "" {
		upstreamHost = "127.0.0.1"
	}
	upstreamPort, err := envInt("UPSTREAM_PORT", 3000, 1, 65535)
	if err != nil {
		return Config{}, err
	}
	listenAll, ports, samePort, err := listenPorts()
	if err != nil {
		return Config{}, err
	}
	if samePort && loopbackName(listenHost) {
		return Config{}, fmt.Errorf("같은 포트로 넘기려면 수신 주소를 127.0.0.1로 두면 안 됩니다. 앱만 127.0.0.1에서 받으세요.")
	}
	if !samePort && forwardsToSelf(listenHost, listenPort, upstreamHost, upstreamPort) {
		return Config{}, fmt.Errorf("프록시가 자기 자신으로 요청을 넘깁니다. 앱은 다른 포트에서만 받고, 이 프록시 포트만 바깥에 여세요.")
	}
	score, err := envInt("ABUSE_SCORE_THRESHOLD", 75, 0, 100)
	if err != nil {
		return Config{}, err
	}
	rate, err := envInt("RATE_LIMIT_PER_SEC", 30, 1, 100000)
	if err != nil {
		return Config{}, err
	}
	trustScore, err := envInt("TRUST_SCORE_THRESHOLD", 90, 0, 100)
	if err != nil {
		return Config{}, err
	}
	trustRate, err := envInt("TRUST_RATE_LIMIT_PER_SEC", 60, 1, 100000)
	if err != nil {
		return Config{}, err
	}
	lowScore, err := envInt("LOW_SCORE_THRESHOLD", 25, 0, 100)
	if err != nil {
		return Config{}, err
	}
	lowRate, err := envInt("LOW_RATE_LIMIT_PER_SEC", 10, 1, 100000)
	if err != nil {
		return Config{}, err
	}
	maxConn, err := envInt("MAX_CONNECTIONS", 64, 1, 10000)
	if err != nil {
		return Config{}, err
	}
	whitelist, err := parseWhitelist(os.Getenv("WHITELIST"))
	if err != nil {
		return Config{}, err
	}
	dbPath := strings.TrimSpace(os.Getenv("DB_PATH"))
	if dbPath == "" {
		dbPath = "data/requestguard.db"
	}
	age := banDays
	if age > 30 {
		age = 30
	}
	cfg := DefaultConfig(apiKey)
	cfg.ListenHost = listenHost
	cfg.ListenPort = listenPort
	cfg.UpstreamHost = upstreamHost
	cfg.UpstreamPort = upstreamPort
	cfg.ListenAll = listenAll
	cfg.ListenPorts = ports
	cfg.SamePort = samePort
	cfg.AbuseScoreThreshold = score
	cfg.AbuseMaxAgeDays = age
	cfg.BanDays = banDays
	cfg.MaxBanDays = maxBan
	cfg.RateLimitPerSec = rate
	cfg.TrustCountries = trust
	cfg.MixedCountries = mixed
	cfg.TrustScoreThreshold = trustScore
	cfg.TrustRateLimitPerSec = trustRate
	cfg.LowScoreThreshold = lowScore
	cfg.LowRateLimitPerSec = lowRate
	cfg.Whitelist = whitelist
	cfg.DBPath = dbPath
	cfg.RequestTimeoutSec = envFloat("REQUEST_TIMEOUT", 15)
	cfg.AbuseTimeoutSec = envFloat("ABUSE_TIMEOUT", 5)
	cfg.MaxConnections = maxConn
	return cfg, nil
}

func RankFor(country string, cfg Config) string {
	if country == "" {
		return ""
	}
	if _, ok := cfg.TrustCountries[country]; ok {
		return "trust"
	}
	if _, ok := cfg.MixedCountries[country]; ok {
		return "mixed"
	}
	return "low"
}

func ScoreThreshold(rank string, cfg Config) int {
	switch rank {
	case "trust":
		return cfg.TrustScoreThreshold
	case "low":
		return cfg.LowScoreThreshold
	default:
		return cfg.AbuseScoreThreshold
	}
}

func RateCap(rank string, cfg Config) int {
	switch rank {
	case "trust":
		return cfg.TrustRateLimitPerSec
	case "low":
		return cfg.LowRateLimitPerSec
	default:
		return cfg.RateLimitPerSec
	}
}

func envInt(name string, def, low, high int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	value := def
	if raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return 0, fmt.Errorf("%s은 정수여야 합니다.", name)
		}
		value = n
	}
	if value < low || value > high {
		return 0, fmt.Errorf("%s은 %d에서 %d 사이여야 합니다.", name, low, high)
	}
	return value, nil
}

func envFloat(name string, def float64) float64 {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def
	}
	n, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return def
	}
	return n
}

func countries(name, def string) (map[string]struct{}, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		raw = def
	}
	out := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		item := strings.ToUpper(strings.TrimSpace(part))
		if item == "" {
			continue
		}
		if len(item) != 2 || !isAlpha(item) {
			return nil, fmt.Errorf("%s에 잘못된 국가 코드가 있습니다: %s", name, item)
		}
		out[item] = struct{}{}
	}
	return out, nil
}

func listenPorts() (bool, []int, bool, error) {
	raw := strings.TrimSpace(os.Getenv("LISTEN_PORTS"))
	if raw == "" {
		return false, nil, false, nil
	}
	if strings.EqualFold(raw, "all") {
		return true, nil, true, nil
	}
	ports, err := ParsePorts(raw)
	if err != nil {
		return false, nil, false, err
	}
	return false, ports, true, nil
}

func ParsePorts(raw string) ([]int, error) {
	var found []int
	seen := map[int]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		var values []int
		if strings.Contains(item, "-") {
			left, right, _ := strings.Cut(item, "-")
			start, err := portNum(left)
			if err != nil {
				return nil, err
			}
			end, err := portNum(right)
			if err != nil {
				return nil, err
			}
			if end < start {
				return nil, fmt.Errorf("포트 범위가 뒤집혀 있습니다: %s", item)
			}
			for p := start; p <= end; p++ {
				values = append(values, p)
			}
		} else {
			p, err := portNum(item)
			if err != nil {
				return nil, err
			}
			values = []int{p}
		}
		for _, p := range values {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			found = append(found, p)
		}
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("LISTEN_PORTS에 포트가 없습니다.")
	}
	return found, nil
}

func portNum(raw string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("포트는 정수여야 합니다: %s", raw)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("포트는 1에서 65535 사이여야 합니다: %d", n)
	}
	return n, nil
}

func parseWhitelist(raw string) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		if mac := NormalizeMAC(item); mac != "" {
			out[MacKey(mac)] = struct{}{}
			continue
		}
		ip, err := NormalizeIP(item)
		if err != nil {
			return nil, fmt.Errorf("WHITELIST에 잘못된 IP 또는 MAC이 있습니다: %s", item)
		}
		out[ip] = struct{}{}
	}
	return out, nil
}

func forwardsToSelf(listenHost string, listenPort int, upstreamHost string, upstreamPort int) bool {
	if listenPort != upstreamPort {
		return false
	}
	name := strings.ToLower(strings.Trim(strings.TrimSpace(upstreamHost), "[]"))
	if name == "localhost" {
		return true
	}
	up := net.ParseIP(name)
	if up == nil {
		return false
	}
	if up.IsLoopback() || up.IsUnspecified() {
		return true
	}
	listen := net.ParseIP(strings.Trim(strings.TrimSpace(listenHost), "[]"))
	if listen == nil {
		return false
	}
	return listen.Equal(up)
}

func loopbackName(host string) bool {
	name := strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	if name == "localhost" {
		return true
	}
	ip := net.ParseIP(name)
	return ip != nil && ip.IsLoopback()
}

func loadEnvFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		key, value, _ := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		if key != "" && os.Getenv(key) == "" {
			_ = os.Setenv(key, value)
		}
	}
}

func setOf(items ...string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, item := range items {
		out[item] = struct{}{}
	}
	return out
}

func isAlpha(s string) bool {
	for _, r := range s {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

func exeDir(path string) string {
	i := strings.LastIndex(path, "/")
	if i < 0 {
		return "."
	}
	return path[:i]
}

func dirJoin(a, b string) string {
	if a == "" || a == "." {
		return b
	}
	return a + "/" + b
}
