package rg

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

var phrases = map[int]string{
	400: "Bad Request",
	403: "Forbidden",
	405: "Method Not Allowed",
	413: "Payload Too Large",
	414: "URI Too Long",
	431: "Request Header Fields Too Large",
	502: "Bad Gateway",
	503: "Service Unavailable",
	505: "HTTP Version Not Supported",
}

type connReader struct {
	c net.Conn
}

func (r connReader) Read(p []byte) (int, error) { return r.c.Read(p) }

func Serve(cfg Config, gate *Gate) error {
	logPolicy(cfg)
	if cfg.SamePort {
		return serveSamePort(cfg, gate)
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.ListenHost, cfg.ListenPort))
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Printf("listen %s upstream %s:%d", ln.Addr(), cfg.UpstreamHost, cfg.UpstreamPort)
	return acceptLoop(ln, cfg, gate, cfg.UpstreamPort)
}

func logPolicy(cfg Config) {
	log.Printf("rate %d/s ban %dd max %dd threshold %d", cfg.RateLimitPerSec, cfg.BanDays, cfg.MaxBanDays, cfg.AbuseScoreThreshold)
	log.Printf("country trust %s score %d rate %d/s; mixed %s score %d rate %d/s; low score %d rate %d/s",
		joinKeys(cfg.TrustCountries), cfg.TrustScoreThreshold, cfg.TrustRateLimitPerSec,
		joinKeys(cfg.MixedCountries), cfg.AbuseScoreThreshold, cfg.RateLimitPerSec,
		cfg.LowScoreThreshold, cfg.LowRateLimitPerSec)
}

func serveSamePort(cfg Config, gate *Gate) error {
	hosts := bindHosts(cfg)
	if len(hosts) == 0 {
		return fmt.Errorf("열 수 있는 주소가 없습니다. 앱은 127.0.0.1에서만 받고, 이 기기에는 바깥 주소가 있어야 합니다.")
	}
	if err := rejectOverlap(cfg, hosts); err != nil {
		return err
	}
	ports := cfg.ListenPorts
	if cfg.ListenAll {
		ports = make([]int, 0, 65535)
		for p := 1; p <= 65535; p++ {
			ports = append(ports, p)
		}
	}
	var listeners []net.Listener
	busy := 0
	for _, host := range hosts {
		for _, port := range ports {
			ln, err := net.Listen("tcp", net.JoinHostPort(host, itoa(port)))
			if err != nil {
				busy++
				continue
			}
			listeners = append(listeners, ln)
		}
	}
	label := itoa(len(ports))
	if cfg.ListenAll {
		label = "all"
	}
	log.Printf("listen %s port-count %s bound %d busy %d upstream %s:<same>", strings.Join(hosts, ","), label, len(listeners), busy, cfg.UpstreamHost)
	if len(listeners) == 0 {
		return fmt.Errorf("열 수 있는 포트가 없습니다. 앱은 127.0.0.1에서만 받고, 이 기기에는 바깥 주소가 있어야 합니다.")
	}
	var wg sync.WaitGroup
	for _, ln := range listeners {
		wg.Add(1)
		go func(ln net.Listener) {
			defer wg.Done()
			port := ln.Addr().(*net.TCPAddr).Port
			_ = acceptLoop(ln, cfg, gate, port)
		}(ln)
	}
	wg.Wait()
	return nil
}

func bindHosts(cfg Config) []string {
	host := strings.Trim(cfg.ListenHost, "[]")
	if host == "0.0.0.0" || host == "::" || host == "*" {
		return InterfaceIPs()
	}
	return []string{host}
}

func rejectOverlap(cfg Config, hosts []string) error {
	name := strings.Trim(cfg.UpstreamHost, "[]")
	ip := net.ParseIP(name)
	if ip == nil {
		return nil
	}
	text := ip.String()
	if v4 := ip.To4(); v4 != nil {
		text = v4.String()
	}
	for _, host := range hosts {
		if host == text {
			return fmt.Errorf("넘기는 주소가 검사 주소와 같습니다. 앱은 127.0.0.1에서만 받으세요.")
		}
	}
	return nil
}

func acceptLoop(ln net.Listener, cfg Config, gate *Gate, upstreamPort int) error {
	defer ln.Close()
	slots := make(chan struct{}, cfg.MaxConnections)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				handleConn(conn, cfg, gate, upstreamPort)
			}()
		default:
			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			_ = gate.NoteAttempt(host)
			conn.Close()
		}
	}
}

func handleConn(conn net.Conn, cfg Config, gate *Gate, upstreamPort int) {
	defer conn.Close()
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		host = conn.RemoteAddr().String()
	}
	ip, err := NormalizeIP(host)
	if err != nil {
		writeDecision(conn, Decision{Action: "reject", Status: 400, Reason: "bad_request", Detail: "bad_ip"})
		return
	}
	_ = conn.SetDeadline(time.Now().Add(time.Duration(cfg.RequestTimeoutSec * float64(time.Second))))
	if early := gate.NoteAttempt(ip); early != nil {
		log.Printf("deny ip=%s mac=%s status=%d reason=%s detail=%s", ip, macOrDash(ip), early.Status, early.Reason, early.Detail)
		writeDecision(conn, *early)
		return
	}
	parsed, rest, err := ReadHead(connReader{conn}, cfg)
	if IsClosed(err) {
		return
	}
	if re, ok := err.(*RequestError); ok {
		decision := gate.Decide(ip, nil, re)
		log.Printf("deny ip=%s mac=%s status=%d reason=%s detail=%s", ip, macOrDash(ip), decision.Status, decision.Reason, decision.Detail)
		writeDecision(conn, decision)
		return
	}
	if err != nil {
		log.Printf("request failed ip=%s err=%v", ip, err)
		writeDecision(conn, Decision{Action: "unavailable", Status: 503, Reason: "unavailable", Detail: "internal"})
		return
	}
	decision := gate.Decide(ip, &parsed, nil)
	if decision.Action != "allow" {
		log.Printf("deny ip=%s mac=%s status=%d reason=%s detail=%s", ip, macOrDash(ip), decision.Status, decision.Reason, decision.Detail)
		writeDecision(conn, decision)
		return
	}
	body, err := ReadBody(connReader{conn}, parsed, rest, cfg)
	if re, ok := err.(*RequestError); ok {
		decision = gate.NoteFormat(ip, re)
		log.Printf("deny ip=%s mac=%s status=%d reason=%s detail=%s", ip, macOrDash(ip), decision.Status, decision.Reason, decision.Detail)
		writeDecision(conn, decision)
		return
	}
	if err != nil {
		return
	}
	parsed.Body = body
	port := upstreamPort
	if cfg.SamePort {
		if tcp, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			port = tcp.Port
		}
	}
	path := parsed.Target
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if len(path) > 200 {
		path = path[:200]
	}
	log.Printf("allow ip=%s mac=%s %s %s port=%d", ip, macOrDash(ip), parsed.Method, path, port)
	if err := forward(conn, parsed, ip, cfg, port); err != nil {
		writeDecision(conn, Decision{Action: "unavailable", Status: 502, Reason: "unavailable", Detail: "upstream"})
	}
}

func macOrDash(ip string) string {
	if mac := LinkAddress(ip); mac != "" {
		return mac
	}
	return "-"
}

func writeDecision(conn net.Conn, decision Decision) {
	public := "bad_request"
	switch decision.Action {
	case "block":
		public = decision.Reason
	case "unavailable":
		public = "unavailable"
	}
	payload := decisionJSON{Blocked: decision.Action == "block", Reason: public}
	headers := []string{
		"Content-Type: application/json; charset=utf-8",
		"Connection: close",
		"Cache-Control: no-store",
	}
	if decision.ExpiresAt != nil {
		payload.ExpiresAt = decision.ExpiresAt
		retry := *decision.ExpiresAt - time.Now().Unix()
		if retry < 0 {
			retry = 0
		}
		headers = append(headers, fmtInt("Retry-After: ", retry))
	}
	body, _ := json.Marshal(payload)
	phrase := phrases[decision.Status]
	if phrase == "" {
		phrase = "Error"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", decision.Status, phrase)
	for _, h := range headers {
		b.WriteString(h)
		b.WriteString("\r\n")
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(body))
	_, _ = io.WriteString(conn, b.String())
	_, _ = conn.Write(body)
}

func forward(conn net.Conn, parsed ParsedRequest, peer string, cfg Config, port int) error {
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(cfg.UpstreamHost, itoa(port)), time.Duration(cfg.RequestTimeoutSec*float64(time.Second)))
	if err != nil {
		return err
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(time.Now().Add(time.Duration(cfg.RequestTimeoutSec * float64(time.Second))))
	if _, err := upstream.Write(buildUpstream(parsed, peer, cfg, port)); err != nil {
		return err
	}
	buf := make([]byte, 65536)
	started := false
	for {
		n, err := upstream.Read(buf)
		if n > 0 {
			started = true
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return nil
			}
		}
		if err != nil {
			if err == io.EOF && started {
				return nil
			}
			if started {
				return nil
			}
			return err
		}
	}
}

func buildUpstream(parsed ParsedRequest, peer string, cfg Config, port int) []byte {
	drop := map[string]struct{}{}
	for name := range hopByHop {
		drop[name] = struct{}{}
	}
	for _, value := range parsed.HeaderValues("connection") {
		for _, token := range strings.Split(value, ",") {
			name := strings.ToLower(strings.TrimSpace(token))
			if name != "" {
				drop[name] = struct{}{}
			}
		}
	}
	var lines []string
	lines = append(lines, parsed.Method+" "+parsed.Target+" "+parsed.Version)
	hasHost := false
	for _, h := range parsed.Headers {
		low := strings.ToLower(h.Name)
		if _, ok := drop[low]; ok || low == "x-forwarded-for" || low == "x-forwarded-proto" {
			continue
		}
		if low == "host" {
			hasHost = true
		}
		lines = append(lines, h.Name+": "+h.Value)
	}
	if !hasHost {
		host := cfg.UpstreamHost
		if port != 80 && port != 443 {
			host = fmtHost(host, port)
		}
		lines = append(lines, "Host: "+host)
	}
	if len(parsed.Body) > 0 || (parsed.Method != "GET" && parsed.Method != "HEAD" && parsed.Method != "OPTIONS") {
		lines = append(lines, "Content-Length: "+itoa(len(parsed.Body)))
	}
	lines = append(lines, "X-Forwarded-For: "+peer, "X-Forwarded-Proto: http", "Connection: close")
	return []byte(strings.Join(lines, "\r\n") + "\r\n\r\n" + string(parsed.Body))
}

type decisionJSON struct {
	Blocked   bool   `json:"blocked"`
	Reason    string `json:"reason"`
	ExpiresAt *int64 `json:"expires_at,omitempty"`
}

func fmtHost(host string, port int) string {
	return net.JoinHostPort(host, itoa(port))
}

func fmtInt(prefix string, n int64) string {
	return prefix + itoa64(n)
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
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

func joinKeys(set map[string]struct{}) string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && out[j] < out[j-1] {
			out[j], out[j-1] = out[j-1], out[j]
			j--
		}
	}
	return strings.Join(out, ",")
}
