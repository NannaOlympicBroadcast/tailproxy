package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
)

// fakeEgress records dials and fails them, so connections end at once.
type fakeEgress struct {
	mu    sync.Mutex
	dials []string
}

func (f *fakeEgress) Dial(_ context.Context, target, host string, port uint16) (net.Conn, string, error) {
	f.mu.Lock()
	f.dials = append(f.dials, target+" "+net.JoinHostPort(host, strconv.Itoa(int(port))))
	f.mu.Unlock()
	return nil, "", errors.New("fake egress")
}

func (f *fakeEgress) DialUDP(ctx context.Context, target, host string, port uint16) (net.Conn, string, error) {
	return f.Dial(ctx, "udp "+target, host, port)
}

func (f *fakeEgress) DialTailnet(ctx context.Context, host string, port uint16) (net.Conn, string, error) {
	return f.Dial(ctx, config.TargetTailnet, host, port)
}

// origConn is one end of a pipe that reports dst as its local address, as
// a TPROXY socket reports the original destination.
type origConn struct {
	net.Conn
	dst *net.TCPAddr
}

func (c origConn) LocalAddr() net.Addr { return c.dst }
func (c origConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(192, 168, 1, 10), Port: 50000}
}

// hello is a minimal ClientHello with server_name sni and, if ech, an
// encrypted_client_hello extension.
func hello(sni string, ech bool) []byte {
	name := []byte(sni)
	sn := append([]byte{0, byte(len(name) + 3), 0, 0, byte(len(name))}, name...)
	ext := append([]byte{0, 0, 0, byte(len(sn))}, sn...)
	if ech {
		ext = append(ext, 0xfe, 0x0d, 0, 1, 0)
	}
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func runTransparent(t *testing.T, rules []config.Rule, unknown string, learned map[string]string, dst string, first []byte) (ConnView, []string) {
	t.Helper()
	eng, err := rule.Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	eg := &fakeEgress{}
	tr := NewTracker()
	r := &Router{Rules: func() *rule.Engine { return eng }, Egress: eg, Tracker: tr, UnknownDomain: unknown}
	in := &Transparent{Router: r, ListenPort: 7893, SniffTimeout: time.Second, Logf: t.Logf,
		Learned: func(ip netip.Addr) (string, bool) { n, ok := learned[ip.String()]; return n, ok }}
	a, b := net.Pipe()
	defer a.Close()
	go a.Write(first)
	in.handle(context.Background(), origConn{Conn: b, dst: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(dst))})
	s := waitFinished(t, tr, 1)
	eg.mu.Lock()
	defer eg.mu.Unlock()
	return s.Recent[0], eg.dials
}

func TestTransparentECHOuterSNI(t *testing.T) {
	rules := []config.Rule{
		{DomainSuffix: []string{"cloudflare-ech.com"}, Egress: "jp"}, // must not see the outer name
		{OuterSNI: []string{"cloudflare-ech.com"}, Egress: "us"},
	}
	ech := hello("cloudflare-ech.com", true)

	// Unknown site behind ECH: only outer_sni matches; the address is
	// dialed at the exit (no domain to resolve there).
	c, dials := runTransparent(t, rules, "reject", nil, "104.16.1.1:443", ech)
	if c.Target != "us" || c.OuterSNI != "cloudflare-ech.com" || !c.ECH || c.Host != "104.16.1.1" || c.Reason != `outer_sni "cloudflare-ech.com"` {
		t.Fatalf("conn %+v", c)
	}
	if len(dials) != 1 || dials[0] != "us 104.16.1.1:443" {
		t.Fatalf("dials %v", dials)
	}

	// A learned name for the address wins over the outer name.
	c, dials = runTransparent(t, []config.Rule{{DomainSuffix: []string{"openai.com"}, Egress: "jp"}, rules[1]}, "", map[string]string{"104.16.1.1": "chat.openai.com"}, "104.16.1.1:443", ech)
	if c.Target != "jp" || c.Host != "chat.openai.com" || c.DomainSrc != "learned" || c.OuterSNI != "cloudflare-ech.com" {
		t.Fatalf("learned: %+v", c)
	}
	if len(dials) != 1 || dials[0] != "jp chat.openai.com:443" {
		t.Fatalf("learned dials %v", dials)
	}

	// No outer_sni rule: the domain is unknown and the policy applies,
	// instead of the outer name matching a domain rule.
	c, _ = runTransparent(t, rules[:1], "reject", nil, "104.16.1.1:443", ech)
	if c.Target != "reject" || c.Host != "104.16.1.1" {
		t.Fatalf("unknown policy: %+v", c)
	}

	// Without ECH the SNI is the site and domain rules see it.
	c, _ = runTransparent(t, rules, "reject", nil, "104.16.1.1:443", hello("www.cloudflare-ech.com", false))
	if c.Target != "jp" || c.Host != "www.cloudflare-ech.com" || c.ECH || c.OuterSNI != "" {
		t.Fatalf("plain TLS: %+v", c)
	}
}
