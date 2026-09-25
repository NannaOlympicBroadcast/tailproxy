package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/service"
)

// fakePanel records requests and serves a small egress section.
type fakePanel struct {
	mu       sync.Mutex
	egress   []config.Egress
	revision string
	tokens   map[string]string
	auth     string
	lastTest map[string]any // body of the last POST /api/v1/rules/test
}

func (f *fakePanel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+f.auth {
		http.Error(w, `{"error":"unauthorized"}`, 401)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/v1/egress":
		json.NewEncoder(w).Encode(map[string]any{"configured": f.egress, "runtime": []any{}, "revision": f.revision})
	case r.Method == "PUT" && r.URL.Path == "/api/v1/egress":
		var req struct {
			Revision string          `json:"revision"`
			Egress   []config.Egress `json:"egress"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Revision != f.revision {
			w.WriteHeader(409)
			io.WriteString(w, `{"error":"stale"}`)
			return
		}
		f.egress, f.revision = req.Egress, f.revision+"x"
		io.WriteString(w, `{"ok":true}`)
	case r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/relay-token"):
		var req struct{ Token string }
		json.NewDecoder(r.Body).Decode(&req)
		f.tokens[strings.Split(r.URL.Path, "/")[4]] = req.Token
		io.WriteString(w, `{"ok":true}`)
	case r.Method == "GET" && r.URL.Path == "/api/v1/connections":
		io.WriteString(w, `{"active":[{"host":"quic.example","port":443,"network":"udp","inbound":"tproxy","target":"us","up":1,"down":2}],
			"recent":[],"total":1,"failed":0,"bypass":{"transparent":5,"fakeip":1,"sniffed":1,"learned":1,"unknown":2,"ech":1,"doh_blocked":3}}`)
	case r.Method == "POST" && r.URL.Path == "/api/v1/rules/test":
		f.lastTest = nil
		json.NewDecoder(r.Body).Decode(&f.lastTest)
		io.WriteString(w, `{"rule_index":0,"target":"us","reason":"domain_suffix \"openai.com\""}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"no route"}`)
	}
}

func setup(t *testing.T) (*fakePanel, string) {
	t.Helper()
	f := &fakePanel{revision: "r1", tokens: map[string]string{}, auth: "panel-token-0123456789"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	p := service.NewPaths(dir)
	os.WriteFile(p.Token, []byte(f.auth+"\n"), 0o600)
	if err := p.WriteState(service.State{PID: os.Getpid(), URL: srv.URL + "/", TokenFile: p.Token, Started: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return f, dir
}

func withStdin(t *testing.T, s string, fn func()) {
	t.Helper()
	r, w, _ := os.Pipe()
	io.WriteString(w, s)
	w.Close()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	fn()
}

func TestEgressCommands(t *testing.T) {
	f, dir := setup(t)
	tp := func(args ...string) error { return run("tpctl", append([]string{"--state-dir", dir}, args...)) }

	withStdin(t, "relay-token-0123456789\n", func() {
		if err := tp("egress", "add", "us", "--relay", "100.98.60.52:1081", "--token-stdin"); err != nil {
			t.Fatal(err)
		}
	})
	if len(f.egress) != 1 || f.egress[0].Relay != "100.98.60.52:1081" || f.tokens["us"] != "relay-token-0123456789" {
		t.Fatalf("add: %+v %v", f.egress, f.tokens)
	}
	if err := tp("egress", "add", "us", "--exit-node", "x"); err == nil {
		t.Fatal("duplicate accepted")
	}
	if err := tp("egress", "add", "jp", "--exit-node", "a", "--relay", "b:1"); err == nil {
		t.Fatal("both exit-node and relay accepted")
	}
	if err := tp("egress", "set", "us", "--exit-node", "ser647557941975"); err != nil {
		t.Fatal(err)
	}
	if f.egress[0].ExitNode != "ser647557941975" || f.egress[0].Relay != "" {
		t.Fatalf("set: %+v", f.egress[0])
	}
	if err := tp("egress", "rm", "nope"); err == nil {
		t.Fatal("rm of unknown accepted")
	}
	if err := tp("egress", "rm", "us"); err != nil || len(f.egress) != 0 {
		t.Fatalf("rm: %v %+v", err, f.egress)
	}
	if err := tp("rules", "test", "chat.openai.com", "443"); err != nil {
		t.Fatal(err)
	}
	if f.lastTest["domain"] != "chat.openai.com" || f.lastTest["port"] != 443.0 || f.lastTest["outer_sni"] != nil {
		t.Fatalf("rules test body: %v", f.lastTest)
	}
	if err := tp("rules", "test", "104.16.1.1", "443", "--outer-sni", "cloudflare-ech.com"); err != nil {
		t.Fatal(err)
	}
	if f.lastTest["ip"] != "104.16.1.1" || f.lastTest["outer_sni"] != "cloudflare-ech.com" {
		t.Fatalf("rules test --outer-sni: %v", f.lastTest)
	}
	if err := tp("rules", "test", "-", "--outer-sni", "cloudflare-ech.com"); err != nil {
		t.Fatal(err)
	}
	if f.lastTest["ip"] != nil || f.lastTest["domain"] != nil || f.lastTest["outer_sni"] != "cloudflare-ech.com" {
		t.Fatalf("rules test -: %v", f.lastTest)
	}
	if err := tp("rules", "test", "-"); err == nil {
		t.Fatal("rules test - without --outer-sni accepted")
	}
	if err := tp("frobnicate"); err == nil || !strings.Contains(err.Error(), "未知命令") {
		t.Fatalf("unknown command: %v", err)
	}
}

func TestNotRunningAndBadToken(t *testing.T) {
	if err := run("tpctl", []string{"--state-dir", t.TempDir(), "status"}); err == nil || !strings.Contains(err.Error(), "没有在运行") {
		t.Fatalf("not running: %v", err)
	}
	f, dir := setup(t)
	f.auth = "different-token-0123456789"
	err := run("tpctl", []string{"--state-dir", dir, "egress", "list"})
	var ae *APIError
	if err == nil || !errorsAs(err, &ae) || ae.Status != 401 {
		t.Fatalf("bad token: %v", err)
	}
}

func errorsAs(err error, target **APIError) bool {
	e, ok := err.(*APIError)
	if ok {
		*target = e
	}
	return ok
}

func TestTSGuardAndMissingSocket(t *testing.T) {
	dir := t.TempDir()
	g, _ := defaultGlobals(dir)
	if err := runTS(g, []string{"status"}); err == nil || !strings.Contains(err.Error(), "LocalAPI") {
		t.Fatalf("missing socket: %v", err)
	}
	// Risky commands need --yes (checked before touching the socket).
	os.WriteFile(filepath.Join(dir, "tailscaled.sock"), nil, 0o600)
	for _, c := range []string{"down", "logout", "set", "up", "switch"} {
		if err := runTS(g, []string{c}); err == nil || !strings.Contains(err.Error(), "--yes") {
			t.Errorf("%s: %v", c, err)
		}
	}
}

func TestLookupAndSchema(t *testing.T) {
	if c, rest := lookup([]string{"egress", "add", "us", "--relay", "x:1"}); c == nil || c.Name != "egress add" || len(rest) != 3 {
		t.Fatalf("lookup: %v %v", c, rest)
	}
	if c, _ := lookup([]string{"egress"}); c == nil || c.Name != "egress list" {
		t.Fatal("egress alone")
	}
	if c, rest := lookup([]string{"rules", "test", "x"}); c.Name != "rules test" || len(rest) != 1 {
		t.Fatal("rules test")
	}
	for _, c := range commands {
		if c.run == nil || c.Summary == "" {
			t.Errorf("command %q incomplete", c.Name)
		}
	}
	for _, what := range []string{"config", "api", "commands"} {
		if err := cmdSchema(globals{}, []string{what}); err != nil {
			t.Fatal(err)
		}
	}
}

// withStdout captures what fn prints.
func withStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	fn()
	os.Stdout = old
	w.Close()
	return <-done
}

func TestConns(t *testing.T) {
	_, dir := setup(t)
	out := withStdout(t, func() {
		if err := run("tpctl", []string{"--state-dir", dir, "conns"}); err != nil {
			t.Error(err)
		}
	})
	for _, want := range []string{"quic.example:443/udp", "未知 2", "ECH 1", "拦截 DoH 3"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}
