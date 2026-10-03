package rg

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestProxyForwards(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	got := make(chan []byte, 1)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		got <- append([]byte{}, buf[:n]...)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
	}()

	_, port, _ := net.SplitHostPort(upstream.Addr().String())
	var upstreamPort int
	for _, c := range port {
		upstreamPort = upstreamPort*10 + int(c-'0')
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	store, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := DefaultConfig("test-key")
	cfg.UpstreamHost = "127.0.0.1"
	cfg.UpstreamPort = upstreamPort
	cfg.RequestTimeoutSec = 2
	gate := NewGate(cfg, store, &fakeAbuse{})
	gate.Links = func(string) (string, error) { return "", nil }
	go acceptLoop(ln, cfg, gate, upstreamPort)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("GET /hi HTTP/1.1\r\nHost: t\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	body, err := io.ReadAll(conn)
	if err != nil && len(body) == 0 {
		t.Fatal(err)
	}
	if !contains(body, []byte("200")) || !contains(body, []byte("ok")) {
		t.Fatalf("response %q", body)
	}
	select {
	case seen := <-got:
		if !contains(seen, []byte("X-Forwarded-For: 127.0.0.1")) || !contains(seen, []byte("GET /hi")) {
			t.Fatalf("upstream %q", seen)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream timeout")
	}
}

func contains(b, sub []byte) bool {
	return len(b) >= len(sub) && (string(b) == string(sub) || len(sub) == 0 || indexOf(b, sub) >= 0)
}

func indexOf(b, sub []byte) int {
	for i := 0; i+len(sub) <= len(b); i++ {
		ok := true
		for j := range sub {
			if b[i+j] != sub[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}
