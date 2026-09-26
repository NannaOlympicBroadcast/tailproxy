package sdk

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	xproxy "golang.org/x/net/proxy"
)

const testConfig = `
rules:
  - {domain_keyword: [blocked], egress: reject}
  - {final: direct}
`

func newEngine(t *testing.T, yaml string, protect func(int) bool) *Engine {
	t.Helper()
	cfg, err := ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(Options{Config: cfg, StateDir: t.TempDir(), Logf: t.Logf, Protect: protect})
	if err != nil {
		t.Fatal(err)
	}
	// Not started: direct dials need no Tailscale node, and a started
	// main node would contact the coordination server.
	t.Cleanup(func() { e.Close() })
	return e
}

func waitRecent(t *testing.T, e *Engine, n int) Connections {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		s := e.Connections()
		if len(s.Recent) >= n && len(s.Active) == 0 {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("connections: %+v", s)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDialThroughRules(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello") }))
	defer origin.Close()
	var protected atomic.Int32
	e := newEngine(t, testConfig, func(fd int) bool { protected.Add(1); return fd > 0 })

	c := e.HTTPClient()
	resp, err := c.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	c.CloseIdleConnections()
	if string(body) != "hello" {
		t.Fatalf("body %q", body)
	}
	s := waitRecent(t, e, 1)
	r := s.Recent[0]
	if r.Inbound != "sdk" || r.Target != "direct" || r.Up == 0 || r.Down == 0 {
		t.Fatalf("record %+v", r)
	}
	if protected.Load() == 0 {
		t.Fatal("Protect was not called for the direct dial")
	}

	if _, err := e.DialContext(context.Background(), "tcp", "www.blocked.example:443"); !errors.Is(err, ErrRejected) {
		t.Fatalf("rejected name: %v", err)
	}
	if m, err := e.Match("api.blocked.example", "", 443); err != nil || m.Target != "reject" {
		t.Fatalf("match: %+v %v", m, err)
	}
	if _, err := e.DialContext(context.Background(), "unix", "x:1"); err == nil {
		t.Fatal("unix network accepted")
	}

	// UDP: a connected socket through the rules.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 64)
		n, from, err := pc.ReadFrom(buf)
		if err == nil {
			pc.WriteTo(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	uc, err := e.DialContext(context.Background(), "udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	uc.Write([]byte("ping"))
	uc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := uc.Read(buf)
	uc.Close()
	if err != nil || string(buf[:n]) != "echo:ping" {
		t.Fatalf("udp: %q %v", buf[:n], err)
	}

	// A new configuration applies to the next dial.
	cfg, _ := ParseConfig([]byte("rules: [{final: reject}]\n"))
	if err := e.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := e.DialContext(context.Background(), "tcp", strings.TrimPrefix(origin.URL, "http://")); !errors.Is(err, ErrRejected) {
		t.Fatalf("after SetConfig: %v", err)
	}
	if a := e.Account(); a.Main.State == "" || a.KeysURL == "" {
		t.Fatalf("main node account: %+v", a)
	}
}

func TestServeSOCKS(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "via socks") }))
	defer origin.Close()
	e := newEngine(t, testConfig, nil)
	ln, err := ListenSOCKS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.ServeSOCKS(ctx, ln)
	d, _ := xproxy.SOCKS5("tcp", ln.Addr().String(), nil, xproxy.Direct)
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: d.(xproxy.ContextDialer).DialContext}}
	resp, err := c.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "via socks" {
		t.Fatalf("body %q", body)
	}
	if _, err := ListenSOCKS("0.0.0.0:0"); err == nil {
		t.Fatal("non-loopback SOCKS listener accepted")
	}
}

func TestOptionsRequired(t *testing.T) {
	cfg, _ := ParseConfig([]byte("rules: []\n"))
	if _, err := New(Options{Config: cfg}); err == nil {
		t.Fatal("missing StateDir accepted")
	}
	if _, err := New(Options{StateDir: t.TempDir()}); err == nil {
		t.Fatal("missing Config accepted")
	}
}
