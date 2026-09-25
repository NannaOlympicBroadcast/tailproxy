package egress

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/relay"
)

// startRelay runs a `tailproxy relay` on loopback that may reach loopback
// destinations (only for the test's local origin).
func startRelay(t *testing.T, tok string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := &relay.Server{Token: tok, AllowPrivate: true, Logf: t.Logf}
	go srv.Serve(ctx, ln)
	return ln.Addr().String()
}

func waitState(t *testing.T, m *Manager, name, want string) Status {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, st := range m.Status() {
			if st.Name == name && st.State == want {
				return st
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never reached %s: %+v", name, want, m.Status())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func get(t *testing.T, m *Manager, target, url string) (string, string) {
	t.Helper()
	var via string
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, port, _ := net.SplitHostPort(addr)
			var p uint16
			fmt.Sscan(port, &p)
			c, v, err := m.Dial(ctx, target, host, p)
			via = v
			return c, err
		},
		DisableKeepAlives: true,
	}}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET via %s: %v", target, err)
	}
	defer resp.Body.Close()
	line, _ := bufio.NewReader(resp.Body).ReadString('\n')
	return line, via
}

func TestRelayEgress(t *testing.T) {
	const tok = "relay-test-token-0123456789"
	addr := startRelay(t, tok)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello from origin")
	}))
	defer origin.Close()
	_, originPort, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	dir := t.TempDir()
	m, err := New(mustParse(t, fmt.Sprintf(`
egress:
  - {name: vps, relay: '%s'}
  - {name: g, type: fallback, members: [vps]}
rules: []
`, addr)), dir, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	st := m.Status()
	if st[0].Kind != "relay" || st[0].State != StateNoToken || st[0].Relay != addr {
		t.Fatalf("before token: %+v", st[0])
	}
	if _, _, err := m.Dial(context.Background(), "g", "127.0.0.1", 80); err == nil {
		t.Fatal("group dialed without a ready member")
	}

	// Run only the relay's probe loop; the main tsnet node stays offline
	// (a loopback relay does not need it).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.mu.Lock()
	m.ctx = ctx
	m.mu.Unlock()
	m.relays["vps"].start(ctx)
	defer m.Close()

	if err := m.SetRelayToken("vps", "short"); err == nil {
		t.Fatal("short token accepted")
	}
	if err := m.SetRelayToken("nope", tok); err == nil {
		t.Fatal("token for unknown relay accepted")
	}
	if err := m.SetRelayToken("vps", "wrong-token-0123456789"); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "vps", StateAuthFailed)
	if err := m.SetRelayToken("vps", tok); err != nil {
		t.Fatal(err)
	}
	st0 := waitState(t, m, "vps", StateReady)
	if st0.TokenSource != "file" {
		t.Fatalf("token source %q", st0.TokenSource)
	}
	tokenPath := filepath.Join(dir, "relay", "vps.token")
	if fi, err := os.Stat(tokenPath); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatalf("token file: %v %v", fi, err)
	}

	// Names are resolved on the relay side.
	for _, target := range []string{"vps", "g"} {
		body, via := get(t, m, target, "http://localhost:"+originPort+"/")
		if body != "hello from origin\n" || via != "vps" {
			t.Fatalf("%s: body %q via %q", target, body, via)
		}
	}
	g := waitState(t, m, "g", StateReady)
	if g.Selected != "vps" {
		t.Fatalf("group: %+v", g)
	}

	// Health check through the relay.
	m.relays["vps"].checkHealth(ctx, origin.URL)
	if h := m.relays["vps"].Status().Health; h == nil || !h.OK {
		t.Fatalf("health: %+v", h)
	}

	// A token file readable by others is refused.
	m2dir := t.TempDir()
	os.MkdirAll(filepath.Join(m2dir, "relay"), 0o700)
	os.WriteFile(filepath.Join(m2dir, "relay", "x.token"), []byte(tok), 0o644)
	m2, err := New(mustParse(t, "egress: [{name: x, relay: '127.0.0.1:1'}]\nrules: []\n"), m2dir, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if st := m2.Status()[0]; st.State != StateError || !strings.Contains(st.Detail, "chmod 600") {
		t.Fatalf("world-readable token: %+v", st)
	}

	// Removing the relay forgets its token.
	if err := m.Apply(mustParse(t, "rules: []\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatal("token file kept after the relay was removed")
	}
	if len(m.Status()) != 0 {
		t.Fatalf("status after removal: %+v", m.Status())
	}
}

func TestRelayTokenFromEnv(t *testing.T) {
	const tok = "env-relay-token-0123456789"
	addr := startRelay(t, tok)
	t.Setenv("TP_TEST_RELAY", tok)
	m, err := New(mustParse(t, fmt.Sprintf("egress: [{name: vps, relay: '%s', relay_token_env: TP_TEST_RELAY}]\nrules: []\n", addr)), t.TempDir(), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if st := m.Status()[0]; st.TokenSource != "env:TP_TEST_RELAY" {
		t.Fatalf("status: %+v", st)
	}
	if err := m.SetRelayToken("vps", "another-token-0123456789"); err == nil || !strings.Contains(err.Error(), "环境变量") {
		t.Fatalf("panel overwrote an env token: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.relays["vps"].start(ctx)
	defer m.Close()
	waitState(t, m, "vps", StateReady)
}

// A relay that is not on loopback is reached over the tailnet; with no node
// connected that fails as not ready instead of using the local network.
func TestRelayNeedsTailnet(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "relay"), 0o700)
	os.WriteFile(filepath.Join(dir, "relay", "us.token"), []byte("tok-0123456789abcdef\n"), 0o600)
	m, err := New(mustParse(t, "egress: [{name: us, relay: '100.98.60.52:1081'}]\nrules: []\n"), dir, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Dial(context.Background(), "us", "example.com", 443); err == nil {
		t.Fatal("a stopped relay dialed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.relays["us"].start(ctx)
	defer m.Close()
	deadline := time.Now().Add(5 * time.Second)
	for st := m.Status()[0]; !strings.Contains(st.Detail, "主节点"); st = m.Status()[0] {
		if time.Now().After(deadline) {
			t.Fatalf("status: %+v", st)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, _, err := m.Dial(context.Background(), "us", "example.com", 443); err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("dial without tailnet: %v", err)
	}
}
