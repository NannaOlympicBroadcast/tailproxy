package panel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsTailnetHost(t *testing.T) {
	for host, want := range map[string]bool{
		"100.101.102.103:7708":            true,
		"100.64.0.1":                      true,
		"[fd7a:115c:a1e0::1]:7708":        true,
		"tailproxy.tail1234.ts.net:7708":  true,
		"tailproxy.tail1234.ts.net.:7708": true,
		"tailproxy:7708":                  true, // short MagicDNS name
		"127.0.0.1:7708":                  false,
		"localhost:7708":                  false,
		"192.168.1.10:7708":               false,
		"evil.example:7708":               false,
		"[fd00::1]:7708":                  false,
		"":                                false,
	} {
		if got := isTailnetHost(host); got != want {
			t.Errorf("isTailnetHost(%q) = %v, want %v", host, got, want)
		}
	}
}

// ServeTailnet: token required, tailnet Host headers only, status shows
// the address, and the server stops with the listener's context.
func TestServeTailnet(t *testing.T) {
	s, _ := newTestServer(t, testConfig+"panel: {tailnet: true}\n")
	if !s.TailnetRequested() {
		t.Fatal("panel.tailnet not read")
	}
	if c := s.components()[0]; !strings.Contains(c.Detail, "等待") {
		t.Fatalf("panel component before listening: %+v", c)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0") // stands in for the tsnet listener
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.ServeTailnet(ctx, ln) }()

	get := func(host, token string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/api/v1/status", ln.Addr()), nil)
		req.Host = host
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.TailnetAddr() == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if code, body := get("100.101.102.103:7708", s.Token()); code != 200 || !strings.Contains(body, "tailnet：http://") {
		t.Fatalf("tailnet host with token: %d %s", code, body)
	}
	if code, _ := get("tailproxy.tail1234.ts.net:7708", ""); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := get("127.0.0.1:7708", s.Token()); code != http.StatusForbidden {
		t.Fatalf("loopback Host on the tailnet listener: %d", code)
	}
	if code, _ := get("evil.example", s.Token()); code != http.StatusForbidden {
		t.Fatalf("foreign Host: %d", code)
	}
	// The loopback listener still refuses tailnet Host headers.
	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	req.Host = "100.101.102.103:7708"
	rec := httptest.NewRecorder()
	authed(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tailnet Host on the loopback listener: %d", rec.Code)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeTailnet: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ServeTailnet did not stop")
	}
	if s.TailnetAddr() != "" {
		t.Fatal("tailnet address kept after stopping")
	}
}
