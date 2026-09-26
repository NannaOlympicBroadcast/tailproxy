package mobile

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	xproxy "golang.org/x/net/proxy"
)

type logs struct {
	mu    sync.Mutex
	lines []string
}

func (l *logs) Log(line string) { l.mu.Lock(); l.lines = append(l.lines, line); l.mu.Unlock() }

type protector struct{ n int }

func (p *protector) Protect(fd int) bool { p.n++; return true }

func TestEngine(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "mobile") }))
	defer origin.Close()
	if _, err := NewEngine("rules: [{bogus: 1}", t.TempDir(), nil, nil); err == nil {
		t.Fatal("bad YAML accepted")
	}
	l, p := &logs{}, &protector{}
	m, err := NewEngine("rules:\n  - {domain_keyword: [blocked], egress: reject}\n  - {final: direct}\n", t.TempDir(), l, p)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	addr, err := m.StartSOCKS("127.0.0.1:0")
	if err != nil || !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("StartSOCKS: %q %v", addr, err)
	}
	d, _ := xproxy.SOCKS5("tcp", addr, nil, xproxy.Direct)
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: d.(xproxy.ContextDialer).DialContext, DisableKeepAlives: true}}
	resp, err := c.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "mobile" || p.n == 0 {
		t.Fatalf("body %q, Protect called %d times", body, p.n)
	}

	if js, err := m.MatchJSON("x.blocked.example", "", 443); err != nil || !strings.Contains(js, `"target":"reject"`) {
		t.Fatalf("MatchJSON: %s %v", js, err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(m.ConnectionsJSON(), `"inbound":"socks5"`) {
		if time.Now().After(deadline) {
			t.Fatalf("ConnectionsJSON: %s", m.ConnectionsJSON())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if js := m.AccountJSON(); !strings.Contains(js, `"main"`) {
		t.Fatalf("AccountJSON: %s", js)
	}
	if js := m.EgressJSON(); js != "[]" && js != "null" {
		t.Fatalf("EgressJSON without egresses: %s", js)
	}
	if err := m.StartTUN(-1, 1500, "not-an-ip", ""); err == nil {
		t.Fatal("bad DNS address accepted")
	}
	if err := m.UpdateConfig("rules: [{final: reject}]\n"); err != nil {
		t.Fatal(err)
	}
	if js, _ := m.MatchJSON("example.com", "", 443); !strings.Contains(js, `"target":"reject"`) {
		t.Fatalf("after UpdateConfig: %s", js)
	}
}
