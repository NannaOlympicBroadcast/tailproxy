package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	xproxy "golang.org/x/net/proxy"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/egress"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
)

// startSOCKS runs a SOCKS5 inbound with the given rules and a real (never
// started) egress manager for the given config.
func startSOCKS(t *testing.T, cfgYAML string) (addr string, tr *Tracker) {
	t.Helper()
	cfg, err := config.Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := rule.Compile(cfg.Rules)
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := egress.New(cfg, t.TempDir(), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	tr = NewTracker()
	r := &Router{Rules: func() *rule.Engine { return eng }, Egress: mgr, Tracker: tr}
	ln, err := ListenSOCKS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go (&SOCKS{Router: r, Logf: t.Logf}).Serve(ctx, ln)
	return ln.Addr().String(), tr
}

func httpViaSOCKS(t *testing.T, socksAddr, url string) (string, error) {
	t.Helper()
	d, err := xproxy.SOCKS5("tcp", socksAddr, nil, xproxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext:       d.(xproxy.ContextDialer).DialContext,
		DisableKeepAlives: true,
	}}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func waitFinished(t *testing.T, tr *Tracker, n int) Snapshot {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		s := tr.Snapshot()
		if len(s.Recent) >= n && len(s.Active) == 0 {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("connections did not finish: %+v", s)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSOCKSDirectAndReject(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from origin")
	}))
	defer origin.Close()
	addr, tr := startSOCKS(t, `
rules:
  - {domain_keyword: [blocked], egress: reject}
  - {port: [9], egress: reject}
  - {final: direct}
`)
	body, err := httpViaSOCKS(t, addr, origin.URL)
	if err != nil || body != "hello from origin" {
		t.Fatalf("direct via IP: %q %v", body, err)
	}
	port := origin.URL[strings.LastIndex(origin.URL, ":")+1:]
	body, err = httpViaSOCKS(t, addr, "http://localhost:"+port+"/")
	if err != nil || body != "hello from origin" {
		t.Fatalf("direct via domain: %q %v", body, err)
	}
	if _, err := httpViaSOCKS(t, addr, "http://blocked.example:"+port+"/"); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("reject rule: %v", err)
	}

	s := waitFinished(t, tr, 3)
	byHost := map[string]ConnView{}
	for _, c := range s.Recent {
		byHost[c.Host] = c
	}
	ok := byHost["127.0.0.1"]
	if ok.Target != "direct" || ok.Error != "" || ok.Down == 0 || ok.Up == 0 {
		t.Fatalf("direct conn record: %+v", ok)
	}
	if lh := byHost["localhost"]; lh.Target != "direct" || lh.RuleIndex != 2 {
		t.Fatalf("domain conn record: %+v", lh)
	}
	if bl := byHost["blocked.example"]; bl.Target != "reject" || bl.RuleIndex != 0 || !strings.Contains(bl.Error, "rejected") {
		t.Fatalf("rejected conn record: %+v", bl)
	}
	if s.Total != 3 || s.Failed != 1 {
		t.Fatalf("totals: %d total, %d failed", s.Total, s.Failed)
	}
}

func TestSOCKSEgressNotReady(t *testing.T) {
	addr, tr := startSOCKS(t, `
egress: [{name: us, exit_node: some-exit-node}]
rules: [{domain_suffix: [example.com], egress: us}, {final: direct}]
`)
	_, err := httpViaSOCKS(t, addr, "http://www.example.com/")
	if err == nil {
		t.Fatal("expected failure for an egress slot that is not connected")
	}
	s := waitFinished(t, tr, 1)
	c := s.Recent[0]
	if c.Target != "us" || !strings.Contains(c.Error, "egress not ready") {
		t.Fatalf("record: %+v", c)
	}
}

func TestSOCKSProtocolErrors(t *testing.T) {
	addr, _ := startSOCKS(t, "rules: [{final: direct}]\n")
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// no-auth, then UDP ASSOCIATE (3) to 0.0.0.0:0
	c.Write([]byte{5, 1, 0})
	reply := make([]byte, 2)
	io.ReadFull(c, reply)
	c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil || rep[1] != repCmdNotSupported {
		t.Fatalf("UDP ASSOCIATE reply %v, %v", rep, err)
	}

	c2, _ := net.Dial("tcp", addr)
	defer c2.Close()
	c2.Write([]byte{5, 1, 2}) // only username/password offered
	io.ReadFull(c2, reply)
	if reply[1] != 0xFF {
		t.Fatalf("no acceptable method reply %v", reply)
	}
}

func TestListenSOCKSLoopbackOnly(t *testing.T) {
	if _, err := ListenSOCKS("0.0.0.0:0"); err == nil || !strings.Contains(err.Error(), "回环") {
		t.Fatalf("non-loopback: %v", err)
	}
}

func TestReplyCode(t *testing.T) {
	if replyCode(ErrRejected) != repNotAllowed {
		t.Fatal("rejected")
	}
	_, err := net.DialTimeout("tcp", "127.0.0.1:1", time.Second)
	if err != nil && replyCode(err) != repConnRefused {
		t.Fatalf("refused: %v -> %d", err, replyCode(err))
	}
	if replyCode(errors.New("x")) != repGeneralFailure {
		t.Fatal("general")
	}
}
