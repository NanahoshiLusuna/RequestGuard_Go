package rg

import (
	"testing"
	"time"
)

type fakeAbuse struct {
	score   int
	country string
	err     string
	calls   []string
}

func (f *fakeAbuse) Check(ip string) CheckResult {
	f.calls = append(f.calls, ip)
	if f.err != "" {
		return CheckResult{Error: f.err}
	}
	return CheckResult{OK: true, Score: f.score, Country: f.country}
}

func testGate(t *testing.T, abuse *fakeAbuse) (*Gate, *Store, time.Time) {
	t.Helper()
	store, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	now := time.Unix(1_700_000_000, 0)
	cfg := DefaultConfig("test-key")
	cfg.ListenHost = "127.0.0.1"
	cfg.UpstreamPort = 9
	gate := NewGate(cfg, store, abuse)
	gate.Now = func() time.Time { return now }
	gate.Links = func(string) (string, error) { return "", nil }
	return gate, store, now
}

func good() *ParsedRequest {
	parsed, err := ParseRequestBytes([]byte("GET / HTTP/1.1\r\nHost: t\r\n\r\n"), DefaultConfig("test-key"))
	if err != nil {
		panic(err)
	}
	return &parsed
}

func TestRateBanDays(t *testing.T) {
	if RateBanDays(29, 30, 30, 365) != 0 || RateBanDays(30, 30, 30, 365) != 30 || RateBanDays(60, 30, 30, 365) != 60 || RateBanDays(10000, 30, 30, 365) != 365 {
		t.Fatal("rate formula")
	}
}

func TestFirstPublicCheckOnce(t *testing.T) {
	abuse := &fakeAbuse{}
	gate, _, _ := testGate(t, abuse)
	first := gate.Evaluate("8.8.8.8", good(), nil)
	second := gate.Evaluate("8.8.8.8", good(), nil)
	if first.Action != "allow" || second.Action != "allow" || len(abuse.calls) != 1 {
		t.Fatalf("first=%s second=%s calls=%v", first.Action, second.Action, abuse.calls)
	}
}

func TestAPIFailureUsesLocalPolicy(t *testing.T) {
	abuse := &fakeAbuse{err: "http_429"}
	gate, store, now := testGate(t, abuse)
	decision := gate.Evaluate("8.8.8.8", good(), nil)
	if decision.Action != "allow" {
		t.Fatal(decision)
	}
	if ban, _ := store.GetBan("8.8.8.8", now); ban != nil {
		t.Fatal("stored ban")
	}
	blocked := gate.Evaluate("8.8.8.8", nil, &RequestError{Code: "nul", Ban: true, Status: 400})
	if blocked.Reason != "format" {
		t.Fatal(blocked)
	}
}

func TestCountryRanks(t *testing.T) {
	abuse := &fakeAbuse{country: "KR", score: 89}
	gate, _, _ := testGate(t, abuse)
	if gate.Evaluate("1.0.0.1", good(), nil).Action != "allow" {
		t.Fatal("kr 89")
	}
	abuse.score = 90
	blocked := gate.Evaluate("1.0.0.2", good(), nil)
	if blocked.Reason != "blacklist" {
		t.Fatal(blocked)
	}
	abuse.country = "CN"
	abuse.score = 24
	if gate.Evaluate("1.0.0.3", good(), nil).Action != "allow" {
		t.Fatal("cn 24")
	}
	abuse.score = 25
	low := gate.Evaluate("1.0.0.4", good(), nil)
	if low.Reason != "blacklist" {
		t.Fatal(low)
	}
}

func TestLowCountryRate(t *testing.T) {
	abuse := &fakeAbuse{country: "CN"}
	gate, _, _ := testGate(t, abuse)
	var last Decision
	for i := 0; i < 10; i++ {
		last = gate.Evaluate("8.8.8.8", good(), nil)
	}
	if last.Reason != "rate" {
		t.Fatal(last)
	}
}

func TestHostileHTTP(t *testing.T) {
	cfg := DefaultConfig("test-key")
	samples := [][]byte{
		[]byte("\x00\r\n\r\n"),
		[]byte("GET /a/../b HTTP/1.1\r\nHost: t\r\n\r\n"),
		[]byte("GET /%2e%2e/secret HTTP/1.1\r\nHost: t\r\n\r\n"),
		[]byte("POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"),
	}
	for _, raw := range samples {
		_, err := ParseRequestBytes(raw, cfg)
		re, ok := err.(*RequestError)
		if !ok || !re.Ban {
			t.Fatalf("expected ban for %q got %v", raw, err)
		}
	}
	_, err := ParseRequestBytes([]byte("GET / HTTP/1.1\r\n\r\n"), cfg)
	re, ok := err.(*RequestError)
	if !ok || re.Ban {
		t.Fatal(err)
	}
	parsed, err := ParseRequestBytes([]byte("POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"), cfg)
	if err != nil || string(parsed.Body) != "hello" {
		t.Fatal(err, parsed.Body)
	}
}

func TestNormalize(t *testing.T) {
	ip, err := NormalizeIP("::ffff:8.8.8.8")
	if err != nil || ip != "8.8.8.8" || IsPublic("10.1.2.3") || !IsPublic("8.8.8.8") {
		t.Fatal(ip, err)
	}
	if NormalizeMAC("AA-BB-CC-DD-EE-FF") != "aa:bb:cc:dd:ee:ff" || NormalizeMAC("00:00:00:00:00:00") != "" {
		t.Fatal("mac")
	}
	ports, err := ParsePorts("80,443,8000-8002")
	if err != nil || len(ports) != 5 || ports[4] != 8002 {
		t.Fatal(ports, err)
	}
}
