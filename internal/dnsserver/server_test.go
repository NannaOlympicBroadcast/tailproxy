package dnsserver

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/fakeip"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
)

// upstream answers every A query with 203.0.113.9 and counts queries.
func upstream(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	var n atomic.Int64
	go func() {
		buf := make([]byte, 1500)
		for {
			l, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			n.Add(1)
			var q dnsmessage.Message
			if q.Unpack(buf[:l]) != nil {
				continue
			}
			r := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
			switch q.Questions[0].Type {
			case dnsmessage.TypeA:
				r.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
					Body:   &dnsmessage.AResource{A: [4]byte{203, 0, 113, 9}},
				}}
			case typeHTTPS:
				r.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: typeHTTPS, Class: dnsmessage.ClassINET, TTL: 300},
					Body: &dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{Priority: 1, Target: dnsmessage.MustNewName("."),
						Params: []dnsmessage.SVCParam{
							{Key: dnsmessage.SVCParamALPN, Value: []byte{2, 'h', '2'}},
							{Key: dnsmessage.SVCParamIPv4Hint, Value: []byte{203, 0, 113, 9}},
							{Key: dnsmessage.SVCParamECH, Value: []byte{0, 3, 1, 2, 3}},
						}}},
				}}
			}
			b, _ := r.Pack()
			pc.WriteTo(b, from)
		}
	}()
	return pc.LocalAddr().String(), &n
}

func startServer(t *testing.T, s *Server) string {
	t.Helper()
	pc, ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Serve(ctx, pc, ln)
	return pc.LocalAddr().String()
}

func query(t *testing.T, network, server, name string, qt dnsmessage.Type) dnsmessage.Message {
	t.Helper()
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 0x4242, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name + "."), Type: qt, Class: dnsmessage.ClassINET}}}
	b, _ := q.Pack()
	c, err := net.Dial(network, server)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	var resp []byte
	if network == "tcp" {
		writeTCPMsg(c, b)
		resp, err = readTCPMsg(c)
	} else {
		c.Write(b)
		buf := make([]byte, 1500)
		var n int
		n, err = c.Read(buf)
		resp = buf[:n]
	}
	if err != nil {
		t.Fatalf("%s %s: %v", network, name, err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil || m.ID != 0x4242 {
		t.Fatalf("bad response: %v", err)
	}
	return m
}

func addrOf(t *testing.T, m dnsmessage.Message) netip.Addr {
	t.Helper()
	if len(m.Answers) != 1 {
		t.Fatalf("answers: %+v", m.Answers)
	}
	switch b := m.Answers[0].Body.(type) {
	case *dnsmessage.AResource:
		return netip.AddrFrom4(b.A)
	case *dnsmessage.AAAAResource:
		return netip.AddrFrom16(b.AAAA)
	}
	t.Fatalf("answer type %T", m.Answers[0].Body)
	return netip.Addr{}
}

func testServer(t *testing.T, ups ...string) (*Server, *fakeip.Pool) {
	t.Helper()
	engine, err := rule.Compile([]config.Rule{
		{DomainSuffix: []string{"openai.com"}, Egress: "us"},
		{Domain: []string{"direct.example"}, Egress: config.TargetDirect},
	})
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := fakeip.New(fakeip.DefaultInet4, fakeip.DefaultInet6)
	return &Server{Pool: pool, Rules: func() *rule.Engine { return engine }, Upstreams: ups, Canary: true, Logf: t.Logf}, pool
}

func TestFakeAndForward(t *testing.T) {
	up, hits := upstream(t)
	s, pool := testServer(t, up)
	addr := startServer(t, s)

	m := query(t, "udp", addr, "chat.openai.com", dnsmessage.TypeA)
	a := addrOf(t, m)
	if !fakeip.DefaultInet4.Contains(a) || m.Answers[0].Header.TTL != 10 {
		t.Fatalf("routed name got %s ttl %d", a, m.Answers[0].Header.TTL)
	}
	if name, ok := pool.Lookup(a); !ok || name != "chat.openai.com" {
		t.Fatalf("reverse: %q", name)
	}
	if a6 := addrOf(t, query(t, "tcp", addr, "chat.openai.com", dnsmessage.TypeAAAA)); !fakeip.DefaultInet6.Contains(a6) {
		t.Fatalf("aaaa: %s", a6)
	}
	if m := query(t, "udp", addr, "chat.openai.com", typeHTTPS); m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Fatalf("HTTPS record must be empty for routed names: %+v", m)
	}
	if hits.Load() != 0 {
		t.Fatalf("routed names must not reach the upstream: %d", hits.Load())
	}

	for _, name := range []string{"direct.example", "unrelated.org"} {
		if a := addrOf(t, query(t, "udp", addr, name, dnsmessage.TypeA)); a.String() != "203.0.113.9" {
			t.Fatalf("%s forwarded: %s", name, a)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream hits %d", hits.Load())
	}
	if m := query(t, "udp", addr, CanaryDomain, dnsmessage.TypeA); m.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("canary: %v", m.RCode)
	}
	if s.Fake.Load() != 3 || s.Forwarded.Load() != 2 || s.CanaryHits.Load() != 1 {
		t.Fatalf("stats fake=%d fwd=%d canary=%d", s.Fake.Load(), s.Forwarded.Load(), s.CanaryHits.Load())
	}
}

func TestRealModeAndUpstreamFailure(t *testing.T) {
	up, _ := upstream(t)
	// First upstream is dead (nothing listens): the second answers.
	dead, _ := net.ListenPacket("udp", "127.0.0.1:0")
	deadAddr := dead.LocalAddr().String()
	dead.Close()
	s, _ := testServer(t, deadAddr, up)
	s.Pool = nil // real mode
	addr := startServer(t, s)
	if a := addrOf(t, query(t, "udp", addr, "chat.openai.com", dnsmessage.TypeA)); a.String() != "203.0.113.9" {
		t.Fatalf("real mode: %s", a)
	}
	s2, _ := testServer(t, deadAddr)
	addr2 := startServer(t, s2)
	if m := query(t, "udp", addr2, "x.org", dnsmessage.TypeA); m.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("dead upstream: %v", m.RCode)
	}
}

func TestParseUpstreams(t *testing.T) {
	got, err := ParseUpstreams("223.5.5.5, 119.29.29.29:5353 [2400:3200::1]:53")
	if err != nil || len(got) != 3 || got[0] != "223.5.5.5:53" || got[1] != "119.29.29.29:5353" || got[2] != "[2400:3200::1]:53" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := ParseUpstreams("dns.google"); err == nil {
		t.Fatal("hostname accepted")
	}

	dir := t.TempDir()
	stub := filepath.Join(dir, "stub.conf")
	real := filepath.Join(dir, "real.conf")
	os.WriteFile(stub, []byte("nameserver 127.0.0.53\noptions edns0\n"), 0o644)
	os.WriteFile(real, []byte("# resolved\nnameserver 10.0.0.2\nnameserver ::1\nnameserver fe80::1%eth0\n"), 0o644)
	old := resolvConfPaths
	defer func() { resolvConfPaths = old }()

	// resolv.conf parsing (what "system" means except on Windows, which
	// reads the adapters: sysresolv_windows.go).
	resolvConfPaths = []string{filepath.Join(dir, "missing"), stub}
	if got := resolvConfResolvers(nil); len(got) != 0 {
		t.Fatalf("loopback-only system resolver accepted: %v", got)
	}
	resolvConfPaths = []string{real, stub}
	if got := resolvConfResolvers(nil); len(got) != 2 || got[0] != "10.0.0.2:53" || got[1] != "[fe80::1%eth0]:53" {
		t.Fatalf("resolv.conf: %v", got)
	}
	if runtime.GOOS != "windows" {
		if got, err := ParseUpstreams("system"); err != nil || len(got) != 2 {
			t.Fatalf("system: %v %v", got, err)
		}
		resolvConfPaths = []string{stub}
		if _, err := ParseUpstreams("system"); err == nil {
			t.Fatal("system with only a loopback resolver accepted")
		}
		resolvConfPaths = []string{real, stub}
	}
	// TUN mode's DNS address (system DNS points there) is never an upstream.
	os.WriteFile(real, []byte("nameserver 172.19.0.2\nnameserver 10.0.0.2\n"), 0o644)
	if got := resolvConfResolvers([]netip.Addr{netip.MustParseAddr("172.19.0.2")}); len(got) != 1 || got[0] != "10.0.0.2:53" {
		t.Fatalf("resolv.conf without the TUN DNS: %v", got)
	}
}

func TestStripECHAndObserve(t *testing.T) {
	up, _ := upstream(t)
	s, _ := testServer(t, up)
	s.Pool = nil // real mode
	s.StripECH = true
	var mu sync.Mutex
	seen := map[string][]netip.Addr{}
	s.Observe = func(name string, addrs []netip.Addr, ttl time.Duration) {
		mu.Lock()
		seen[name] = addrs
		mu.Unlock()
		if ttl != 300*time.Second {
			t.Errorf("ttl %v", ttl)
		}
	}
	addr := startServer(t, s)
	m := query(t, "udp", addr, "chat.openai.com", typeHTTPS)
	if len(m.Answers) != 1 {
		t.Fatalf("answers: %+v", m.Answers)
	}
	h := m.Answers[0].Body.(*dnsmessage.HTTPSResource)
	if _, ok := h.GetParam(dnsmessage.SVCParamECH); ok {
		t.Fatal("ech not stripped")
	}
	if _, ok := h.GetParam(dnsmessage.SVCParamALPN); !ok {
		t.Fatal("alpn lost")
	}
	if s.ECHStripped.Load() != 1 {
		t.Fatalf("stripped %d", s.ECHStripped.Load())
	}
	query(t, "udp", addr, "Chat.OpenAI.com", dnsmessage.TypeA)
	mu.Lock()
	defer mu.Unlock()
	if a := seen["chat.openai.com"]; len(a) != 1 || a[0].String() != "203.0.113.9" {
		t.Fatalf("observed: %v", seen)
	}

	// Without StripECH the record passes through unchanged.
	s2, _ := testServer(t, up)
	s2.Pool = nil
	addr2 := startServer(t, s2)
	m = query(t, "udp", addr2, "x.example", typeHTTPS)
	if _, ok := m.Answers[0].Body.(*dnsmessage.HTTPSResource).GetParam(dnsmessage.SVCParamECH); !ok {
		t.Fatal("ech stripped without StripECH")
	}
}

func TestListenRetriesEphemeralPort(t *testing.T) {
	// Hold TCP ports so that some UDP picks collide; Listen must still
	// return a UDP/TCP pair on one port.
	for i := 0; i < 20; i++ {
		pc, ln, err := Listen("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		if pc.LocalAddr().String() != ln.Addr().String() {
			t.Fatalf("udp %s, tcp %s", pc.LocalAddr(), ln.Addr())
		}
		defer pc.Close()
		defer ln.Close()
	}
	// A fixed port that is taken for TCP fails without retrying elsewhere.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	if pc, ln, err := Listen(busy.Addr().String()); err == nil {
		pc.Close()
		ln.Close()
		t.Fatal("Listen on a taken fixed port succeeded")
	}
}
