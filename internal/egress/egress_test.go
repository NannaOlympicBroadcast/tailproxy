package egress

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
)

// dohServer is a minimal RFC 8484 server answering from a fixed table.
func dohServer(t *testing.T, a map[string]string, hits *atomic.Int64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad content type", 415)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var q dnsmessage.Message
		if err := q.Unpack(body); err != nil || len(q.Questions) != 1 {
			http.Error(w, "bad query", 400)
			return
		}
		qn := strings.TrimSuffix(q.Questions[0].Name.String(), ".")
		resp := dnsmessage.Message{Header: dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeSuccess}, Questions: q.Questions}
		ip, ok := a[qn]
		ip6, ok6 := a[qn+"/6"]
		switch {
		case !ok && !ok6:
			resp.RCode = dnsmessage.RCodeNameError
		case q.Questions[0].Type == dnsmessage.TypeA && ip == "fail":
			http.Error(w, "A broken", 502)
			return
		case q.Questions[0].Type == dnsmessage.TypeA && ok:
			resp.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.AResource{A: netip.MustParseAddr(ip).As4()},
			}}
		case q.Questions[0].Type == dnsmessage.TypeAAAA && ok6:
			resp.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr(ip6).As16()},
			}}
		}
		out, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(out)
	}))
}

func TestDoHLookupAndCache(t *testing.T) {
	var hits atomic.Int64
	srv := dohServer(t, map[string]string{"api.example.com": "203.0.113.7"}, &hits)
	defer srv.Close()
	d := NewDoH(srv.URL, srv.Client())
	addrs, err := d.Lookup(context.Background(), "API.example.com.")
	if err != nil || len(addrs) != 1 || addrs[0].String() != "203.0.113.7" {
		t.Fatalf("lookup: %v %v", addrs, err)
	}
	if _, err := d.Lookup(context.Background(), "api.example.com"); err != nil || hits.Load() != 2 {
		t.Fatalf("second lookup should be cached (A + AAAA = 2 queries): hits=%d err=%v", hits.Load(), err)
	}
	if _, err := d.Lookup(context.Background(), "nx.example.com"); err == nil || !strings.Contains(err.Error(), "no such host") {
		t.Fatalf("NXDOMAIN: %v", err)
	}
}

// IPv4 comes first; when one family fails the answer is used but not
// cached, and the failed query is retried once.
func TestDoHOrderAndPartialFailure(t *testing.T) {
	var hits atomic.Int64
	srv := dohServer(t, map[string]string{
		"dual.example": "203.0.113.8", "dual.example/6": "2001:db8::8",
		"v6only.example": "fail", "v6only.example/6": "2001:db8::9",
	}, &hits)
	defer srv.Close()
	d := NewDoH(srv.URL, srv.Client())
	var logged []string
	d.Logf = func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }
	addrs, err := d.Lookup(context.Background(), "dual.example")
	if err != nil || len(addrs) != 2 || !addrs[0].Is4() || !addrs[1].Is6() {
		t.Fatalf("dual: %v %v", addrs, err)
	}
	hits.Store(0)
	for i := 0; i < 2; i++ {
		addrs, err = d.Lookup(context.Background(), "v6only.example")
		if err != nil || len(addrs) != 1 || addrs[0].String() != "2001:db8::9" {
			t.Fatalf("v6only: %v %v", addrs, err)
		}
	}
	// per lookup: A, A retry, AAAA; nothing cached
	if hits.Load() != 6 {
		t.Fatalf("partial answer must not be cached and A must be retried once: hits=%d", hits.Load())
	}
	if len(logged) == 0 || !strings.Contains(strings.Join(logged, "\n"), "TypeA via") {
		t.Fatalf("failed A query not logged: %q", logged)
	}
}

func TestFindExitNode(t *testing.T) {
	mk := func(id, host, dns, ip string, exit bool) *ipnstate.PeerStatus {
		return &ipnstate.PeerStatus{ID: tailcfg.StableNodeID(id), HostName: host, DNSName: dns,
			TailscaleIPs: []netip.Addr{netip.MustParseAddr(ip)}, ExitNodeOption: exit}
	}
	st := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{
		key.NewNode().Public(): mk("nTOKYO", "tokyo-vps", "tokyo-vps.tail1234.ts.net.", "100.101.1.1", true),
		key.NewNode().Public(): mk("nLAPTOP", "laptop", "laptop.tail1234.ts.net.", "100.101.1.2", false),
	}}
	for _, spec := range []string{"tokyo-vps", "TOKYO-VPS", "tokyo-vps.tail1234.ts.net", "100.101.1.1", "nTOKYO"} {
		p, err := findExitNode(st, spec)
		if err != nil || p.ID != "nTOKYO" {
			t.Fatalf("%q: %v %v", spec, p, err)
		}
	}
	if _, err := findExitNode(st, "laptop"); err == nil || !strings.Contains(err.Error(), "没有提供出口节点") {
		t.Fatalf("non-exit peer: %v", err)
	}
	if _, err := findExitNode(st, "nope"); err == nil || !strings.Contains(err.Error(), "找不到") {
		t.Fatalf("missing peer: %v", err)
	}
}

func mustParse(t *testing.T, y string) *config.Config {
	t.Helper()
	c, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestManagerNotStarted(t *testing.T) {
	cfg := mustParse(t, `
egress:
  - {name: us, exit_node: a}
  - {name: jp, exit_node: b}
  - {name: auto, type: fallback, members: [us, jp]}
rules: []
`)
	m, err := New(cfg, t.TempDir(), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	st := m.Status()
	if len(st) != 3 || st[0].State != StateStopped || st[0].Hostname != "tailproxy-us" || st[2].Kind != "group" || st[2].State == StateReady {
		t.Fatalf("status: %+v", st)
	}
	for _, target := range []string{"us", "auto"} {
		if _, _, err := m.Dial(context.Background(), target, "example.com", 443); err == nil || !strings.Contains(err.Error(), "not ready") {
			t.Fatalf("%s: %v", target, err)
		}
	}
	if _, _, err := m.Dial(context.Background(), "nope", "example.com", 443); err == nil {
		t.Fatal("unknown egress")
	}
	if state, detail := m.Summary(); state != "degraded" || !strings.Contains(detail, "主节点") {
		t.Fatalf("summary %s %s", state, detail)
	}
	if a := m.Account(); a.Main.Kind != "main" || a.Main.Hostname != DefaultMainHostname || a.AutoLogin {
		t.Fatalf("account: %+v", a)
	}
	if peers, err := m.Peers(context.Background()); peers != nil || err != nil {
		t.Fatalf("peers before login: %v %v", peers, err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("close never-started manager: %v", err)
	}
}

func TestApplyAddsRemovesAndSwitches(t *testing.T) {
	dir := t.TempDir()
	m, err := New(mustParse(t, `
egress:
  - {name: us, exit_node: a}
  - {name: jp, exit_node: b}
`), dir, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	jpDir := filepath.Join(dir, "tsnet", "jp")
	if _, err := os.Stat(jpDir); err != nil {
		t.Fatalf("jp state dir: %v", err)
	}
	err = m.Apply(mustParse(t, `
egress:
  - {name: cn, exit_node: VM-0-5-opencloudos, doh: 'https://223.5.5.5/dns-query'}
  - {name: us, exit_node: ser647557941975}
  - {name: g, type: latency, members: [us, cn]}
`))
	if err != nil {
		t.Fatal(err)
	}
	st := m.Status()
	var names []string
	for _, x := range st {
		names = append(names, x.Name)
	}
	if strings.Join(names, ",") != "cn,us,g" {
		t.Fatalf("order after apply: %v", names)
	}
	if st[1].ExitNode.Spec != "ser647557941975" || st[0].ExitNode.Spec != "VM-0-5-opencloudos" {
		t.Fatalf("specs: %+v %+v", st[0].ExitNode, st[1].ExitNode)
	}
	if strings.Join(st[2].Members, ",") != "us,cn" {
		t.Fatalf("group members: %v", st[2].Members)
	}
	if _, err := os.Stat(jpDir); !os.IsNotExist(err) {
		t.Fatal("removed slot's state dir was not deleted")
	}
	if _, err := os.Stat(filepath.Join(dir, "tsnet", "cn")); err != nil {
		t.Fatalf("new slot's state dir: %v", err)
	}
}

func TestAuthKey(t *testing.T) {
	dir := t.TempDir()
	m, err := New(mustParse(t, "rules: []\n"), dir, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetAuthKey("not-a-key"); err == nil {
		t.Fatal("invalid key accepted")
	}
	key := "tskey-auth-kABCDEF123456-secretsecretsecret"
	if err := m.SetAuthKey(key); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "tailscale.authkey")
	if info, err := os.Stat(f); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("key file: %v %v", info, err)
	}
	a := m.Account()
	if a.AuthKeySource != "file" || !a.AutoLogin || strings.Contains(a.AuthKeyHint, "secret") {
		t.Fatalf("account after set: %+v", a)
	}
	// A new manager picks the saved key up.
	m2, _ := New(mustParse(t, "rules: []\n"), dir, t.Logf)
	if m2.Account().AuthKeySource != "file" {
		t.Fatal("saved key not loaded")
	}
	if err := m.ClearAuthKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) || m.Account().AutoLogin {
		t.Fatal("key not cleared")
	}

	t.Setenv("TP_TEST_AUTHKEY", key)
	m3, _ := New(mustParse(t, "tailnet: {auth_key_env: TP_TEST_AUTHKEY}\n"), t.TempDir(), t.Logf)
	if a := m3.Account(); a.AuthKeySource != "env:TP_TEST_AUTHKEY" || !a.AutoLogin {
		t.Fatalf("env key: %+v", a)
	}
	if err := m3.SetAuthKey(key); err == nil || !strings.Contains(err.Error(), "环境变量") {
		t.Fatalf("env key must not be replaced from the panel: %v", err)
	}
}
