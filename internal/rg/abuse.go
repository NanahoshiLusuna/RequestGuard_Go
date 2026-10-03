package rg

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const checkURL = "https://api.abuseipdb.com/api/v2/check"

type CheckResult struct {
	OK      bool
	Score   int
	Error   string
	Country string
}

type AbuseIPDB struct {
	key        string
	maxAgeDays int
	timeout    time.Duration
	mu         sync.Mutex
	cooldown   time.Time
	client     *http.Client
}

func NewAbuse(key string, maxAgeDays int, timeoutSec float64) *AbuseIPDB {
	if maxAgeDays < 1 {
		maxAgeDays = 1
	}
	if maxAgeDays > 30 {
		maxAgeDays = 30
	}
	transport := &http.Transport{Proxy: nil}
	return &AbuseIPDB{
		key:        key,
		maxAgeDays: maxAgeDays,
		timeout:    time.Duration(timeoutSec * float64(time.Second)),
		client: &http.Client{
			Timeout:   time.Duration(timeoutSec * float64(time.Second)),
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (a *AbuseIPDB) Check(ip string) CheckResult {
	normalized, err := NormalizeIP(ip)
	if err != nil {
		return CheckResult{Error: "bad_ip"}
	}
	if !IsPublic(normalized) {
		return CheckResult{Error: "private"}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if time.Now().Before(a.cooldown) {
		return CheckResult{Error: "cooldown"}
	}
	return a.checkLocked(normalized)
}

func (a *AbuseIPDB) checkLocked(ip string) CheckResult {
	q := url.Values{}
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", fmt.Sprintf("%d", a.maxAgeDays))
	req, err := http.NewRequest(http.MethodGet, checkURL+"?"+q.Encode(), nil)
	if err != nil {
		return a.fail(0, err.Error())
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Key", a.key)
	req.Header.Set("User-Agent", "RequestGuard")
	resp, err := a.client.Do(req)
	if err != nil {
		log.Printf("abuseipdb %T", err)
		return a.fail(0, fmt.Sprintf("%T", err))
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		log.Printf("abuseipdb http_%d", resp.StatusCode)
		return a.fail(resp.StatusCode, fmt.Sprintf("http_%d", resp.StatusCode))
	}
	if resp.StatusCode >= 400 {
		log.Printf("abuseipdb http_%d", resp.StatusCode)
		return a.fail(resp.StatusCode, fmt.Sprintf("http_%d", resp.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return a.fail(0, "read")
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return a.fail(0, "bad_payload")
	}
	data, _ := payload["data"].(map[string]any)
	score, ok := data["abuseConfidenceScore"].(float64)
	if !ok || score != float64(int(score)) {
		return CheckResult{Error: "bad_payload"}
	}
	country := "XX"
	if raw, ok := data["countryCode"].(string); ok {
		if code := NormalizeCountry(raw); code != "" {
			country = code
		}
	}
	return CheckResult{OK: true, Score: int(score), Country: country}
}

func (a *AbuseIPDB) fail(status int, errText string) CheckResult {
	delay := 5 * time.Second
	if status == 401 || status == 403 || status == 429 {
		delay = 300 * time.Second
	}
	a.cooldown = time.Now().Add(delay)
	return CheckResult{Error: errText}
}
