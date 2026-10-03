package rg

import (
	"database/sql"
	"log"
	"sync"
	"time"
)

type Decision struct {
	Action    string
	Status    int
	Reason    string
	Detail    string
	ExpiresAt *int64
}

type Checker interface {
	Check(ip string) CheckResult
}

type RateLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
	seen int
}

func NewLimiter() *RateLimiter {
	return &RateLimiter{hits: map[string][]time.Time{}}
}

func (l *RateLimiter) Observe(key string, now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-time.Second)
	hits := l.hits[key]
	i := 0
	for i < len(hits) && !hits[i].After(cutoff) {
		i++
	}
	hits = append(hits[i:], now)
	l.hits[key] = hits
	l.seen++
	if l.seen%1024 == 0 || len(l.hits) > 10000 {
		l.sweep(now)
	}
	return len(hits)
}

func (l *RateLimiter) sweep(now time.Time) {
	cutoff := now.Add(-time.Second)
	for key, hits := range l.hits {
		if len(hits) == 0 || !hits[len(hits)-1].After(cutoff) {
			delete(l.hits, key)
		}
	}
}

func RateBanDays(rps, threshold, baseDays, maxDays int) int {
	if rps < threshold {
		return 0
	}
	scaled := (baseDays*rps + threshold - 1) / threshold
	if scaled < baseDays {
		scaled = baseDays
	}
	if scaled > maxDays {
		return maxDays
	}
	return scaled
}

type Gate struct {
	Config  Config
	Store   *Store
	Abuse   Checker
	Limiter *RateLimiter
	Now     func() time.Time
	Links   func(ip string) (string, error)

	guard    sync.Mutex
	inflight map[string]*sync.Mutex
}

func NewGate(cfg Config, store *Store, abuse Checker) *Gate {
	return &Gate{
		Config:   cfg,
		Store:    store,
		Abuse:    abuse,
		Limiter:  NewLimiter(),
		Now:      time.Now,
		Links:    func(ip string) (string, error) { return LinkAddress(ip), nil },
		inflight: map[string]*sync.Mutex{},
	}
}

func (g *Gate) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *Gate) NoteAttempt(rawIP string) *Decision {
	ip, keys, err := g.identifiers(rawIP)
	if err != nil {
		return &Decision{Action: "reject", Status: 400, Reason: "bad_request", Detail: "bad_ip"}
	}
	if g.exempt(keys) {
		return nil
	}
	now := g.now()
	g.inherit(keys, now)
	country, rank, _, rateCap := g.policy(ip, now)
	worst := 0
	for _, key := range keys {
		if n := g.Limiter.Observe(key, now); n > worst {
			worst = n
		}
	}
	if worst >= rateCap {
		days := RateBanDays(worst, rateCap, g.Config.BanDays, g.Config.MaxBanDays)
		detail := "rps=" + itoa(worst)
		if rank != "" {
			detail += " country=" + country + " rank=" + rank
		}
		intensity := sql.NullFloat64{Float64: float64(worst), Valid: true}
		for _, key := range keys {
			g.ban(key, "rate", days, now, detail, intensity, nil)
		}
	}
	return g.active(keys, now)
}

func (g *Gate) Decide(rawIP string, parsed *ParsedRequest, reqErr *RequestError) Decision {
	ip, keys, err := g.identifiers(rawIP)
	if err != nil {
		return Decision{Action: "reject", Status: 400, Reason: "bad_request", Detail: "bad_ip"}
	}
	if g.exempt(keys) {
		if reqErr != nil {
			return Decision{Action: "reject", Status: reqErr.Status, Reason: "bad_request", Detail: reqErr.Code}
		}
		return Decision{Action: "allow", Status: 200, Reason: "ok"}
	}
	now := g.now()
	if g.active(keys, now) == nil && g.ensureReputation(ip, now) == "" {
		rep, _ := g.Store.GetReputation(ip, now)
		country, rank, scoreLimit, _ := g.policy(ip, now)
		if rep != nil && rep.Score >= scoreLimit {
			detail := "score=" + itoa(rep.Score)
			if rank != "" {
				detail += " country=" + country + " rank=" + rank
			}
			for _, key := range keys {
				g.ban(key, "blacklist", g.Config.BanDays, now, detail, sql.NullFloat64{}, nil)
			}
		}
	}
	if reqErr != nil {
		g.applyFormat(keys, reqErr, now)
	}
	if active := g.active(keys, now); active != nil {
		return *active
	}
	if reqErr != nil {
		return Decision{Action: "reject", Status: reqErr.Status, Reason: "bad_request", Detail: reqErr.Code}
	}
	return Decision{Action: "allow", Status: 200, Reason: "ok"}
}

func (g *Gate) NoteFormat(rawIP string, reqErr *RequestError) Decision {
	_, keys, err := g.identifiers(rawIP)
	if err != nil {
		return Decision{Action: "reject", Status: 400, Reason: "bad_request", Detail: "bad_ip"}
	}
	if g.exempt(keys) {
		return Decision{Action: "reject", Status: reqErr.Status, Reason: "bad_request", Detail: reqErr.Code}
	}
	now := g.now()
	g.applyFormat(keys, reqErr, now)
	if active := g.active(keys, now); active != nil {
		return *active
	}
	return Decision{Action: "reject", Status: reqErr.Status, Reason: "bad_request", Detail: reqErr.Code}
}

func (g *Gate) Evaluate(rawIP string, parsed *ParsedRequest, reqErr *RequestError) Decision {
	early := g.NoteAttempt(rawIP)
	if early != nil {
		if reqErr != nil {
			_, keys, err := g.identifiers(rawIP)
			if err != nil {
				return *early
			}
			now := g.now()
			g.applyFormat(keys, reqErr, now)
			if active := g.active(keys, now); active != nil {
				return *active
			}
		}
		return *early
	}
	return g.Decide(rawIP, parsed, reqErr)
}

func (g *Gate) identifiers(rawIP string) (string, []string, error) {
	ip, err := NormalizeIP(rawIP)
	if err != nil {
		return "", nil, err
	}
	keys := []string{ip}
	if g.Links != nil {
		found, err := g.Links(ip)
		if err != nil {
			log.Printf("mac lookup failed ip=%s", ip)
		} else if mac := NormalizeMAC(found); mac != "" {
			keys = append(keys, MacKey(mac))
		}
	}
	return ip, keys, nil
}

func (g *Gate) exempt(keys []string) bool {
	for _, key := range keys {
		if _, ok := g.Config.Whitelist[key]; ok {
			return true
		}
	}
	return false
}

func (g *Gate) policy(ip string, now time.Time) (string, string, int, int) {
	rep, _ := g.Store.GetReputation(ip, now)
	country := ""
	if rep != nil && rep.Detail != "private" {
		country = rep.Country
	}
	rank := RankFor(country, g.Config)
	return country, rank, ScoreThreshold(rank, g.Config), RateCap(rank, g.Config)
}

func (g *Gate) active(keys []string, now time.Time) *Decision {
	var chosen *Ban
	for _, key := range keys {
		ban, err := g.Store.GetBan(key, now)
		if err != nil || ban == nil {
			continue
		}
		if chosen == nil || ban.ExpiresAt > chosen.ExpiresAt {
			chosen = ban
		}
	}
	if chosen == nil {
		return nil
	}
	exp := chosen.ExpiresAt
	return &Decision{Action: "block", Status: 403, Reason: chosen.Reason, Detail: chosen.Detail, ExpiresAt: &exp}
}

func (g *Gate) inherit(keys []string, now time.Time) {
	var found []Ban
	for _, key := range keys {
		ban, err := g.Store.GetBan(key, now)
		if err == nil && ban != nil {
			found = append(found, *ban)
		}
	}
	if len(found) == 0 {
		return
	}
	longest := found[0]
	for _, ban := range found[1:] {
		if ban.ExpiresAt > longest.ExpiresAt {
			longest = ban
		}
	}
	span := longest.ExpiresAt - now.Unix()
	if span < 0 {
		span = 0
	}
	days := int((span + 86399) / 86400)
	if days < 1 {
		days = 1
	}
	exp := longest.ExpiresAt
	for _, key := range keys {
		g.ban(key, longest.Reason, days, now, longest.Detail, longest.Intensity, &exp)
	}
}

func (g *Gate) ensureReputation(ip string, now time.Time) string {
	if rep, _ := g.Store.GetReputation(ip, now); rep != nil {
		return ""
	}
	if !IsPublic(ip) {
		_ = g.Store.SaveReputation(ip, 0, now, g.Config.BanDays, "private", "")
		log.Printf("reputation ip=%s score=0 private", ip)
		return ""
	}
	g.guard.Lock()
	lock := g.inflight[ip]
	if lock == nil {
		lock = &sync.Mutex{}
		g.inflight[ip] = lock
	}
	g.guard.Unlock()
	lock.Lock()
	defer func() {
		lock.Unlock()
		g.guard.Lock()
		if g.inflight[ip] == lock {
			delete(g.inflight, ip)
		}
		g.guard.Unlock()
	}()
	if rep, _ := g.Store.GetReputation(ip, now); rep != nil {
		return ""
	}
	result := g.Abuse.Check(ip)
	if !result.OK {
		log.Printf("abuseipdb unavailable ip=%s detail=%s; local policy", ip, result.Error)
		if result.Error == "" {
			return "reputation_unavailable"
		}
		return result.Error
	}
	_ = g.Store.SaveReputation(ip, result.Score, now, g.Config.BanDays, "", result.Country)
	country := result.Country
	if country == "" {
		country = "-"
	}
	log.Printf("reputation ip=%s score=%d country=%s", ip, result.Score, country)
	return ""
}

func (g *Gate) applyFormat(keys []string, reqErr *RequestError, now time.Time) {
	if reqErr == nil || !reqErr.Ban || g.exempt(keys) {
		return
	}
	for _, key := range keys {
		g.ban(key, "format", g.Config.BanDays, now, reqErr.Code, sql.NullFloat64{}, nil)
	}
}

func (g *Gate) ban(key, reason string, days int, now time.Time, detail string, intensity sql.NullFloat64, expires *int64) {
	ban, changed, err := g.Store.Ban(key, reason, days, now, detail, intensity, expires)
	if err != nil {
		log.Printf("ban failed id=%s err=%v", key, err)
		return
	}
	if changed {
		log.Printf("block id=%s reason=%s detail=%s days=%d expires_at=%d", key, ban.Reason, ban.Detail, days, ban.ExpiresAt)
	}
}

func itoa(n int) string {
	return strconvItoa(n)
}

func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
