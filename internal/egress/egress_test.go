package egress

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
)

// dohServer is a minimal RFC 8484 server answering from a fixed table.
func dohServer(t *testing.T, a map[string]string, hits *int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hits++
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
		if !ok {
			resp.RCode = dnsmessage.RCodeNameError
		} else if q.Questions[0].Type == dnsmessage.TypeA {
			resp.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.AResource{A: netip.MustParseAddr(ip).As4()},
			}}
		}
		out, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(out)
	}))
}

func TestDoHLookupAndCache(t *testing.T) {
	hits := 0
	srv := dohServer(t, map[string]string{"api.example.com": "203.0.113.7"}, &hits)
	defer srv.Close()
	d := NewDoH(srv.URL, srv.Client())
	addrs, err := d.Lookup(context.Background(), "API.example.com.")
	if err != nil || len(addrs) != 1 || addrs[0].String() != "203.0.113.7" {
		t.Fatalf("lookup: %v %v", addrs, err)
	}
	if _, err := d.Lookup(context.Background(), "api.example.com"); err != nil || hits != 1 {
		t.Fatalf("second lookup should be cached: hits=%d err=%v", hits, err)
	}
	if _, err := d.Lookup(context.Background(), "nx.example.com"); err == nil || !strings.Contains(err.Error(), "no such host") {
		t.Fatalf("NXDOMAIN: %v", err)
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

func TestManagerNotStarted(t *testing.T) {
	cfg, err := config.Parse([]byte(`
egress:
  - {name: us, exit_node: a}
  - {name: jp, exit_node: b}
  - {name: auto, type: fallback, members: [us, jp]}
rules: []
`))
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(cfg, t.TempDir(), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	st := m.Status()
	if len(st) != 3 || st[0].State != StateStarting || st[2].Kind != "group" || st[2].State == StateReady {
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
	if state, _ := m.Summary(); state != "degraded" {
		t.Fatalf("summary %s", state)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("close never-started manager: %v", err)
	}
}

func TestHealthIntervalValidation(t *testing.T) {
	cfg, _ := config.Parse([]byte(`
egress:
  - {name: us, exit_node: a}
  - {name: g, type: latency, members: [us], health_check: {url: "https://x", interval: 1s}}
`))
	if _, err := New(cfg, t.TempDir(), t.Logf); err == nil || !strings.Contains(err.Error(), "at least 5s") {
		t.Fatalf("got %v", err)
	}
}
