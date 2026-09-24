//go:build linux

package capture_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jsimonetti/rtnetlink"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/capture"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/dnsserver"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/fakeip"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/proxy"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
)

// TestTProxyIntegration runs real nftables TPROXY, policy routing and DNS
// hijacking inside a private network namespace (only lo). It re-executes
// the test binary under `unshare -n`; it needs root and nft.
func TestTProxyIntegration(t *testing.T) {
	if os.Getenv("TP_IN_NETNS") == "" {
		if os.Geteuid() != 0 {
			t.Skip("needs root")
		}
		for _, bin := range []string{"unshare", "nft"} {
			if _, err := exec.LookPath(bin); err != nil {
				t.Skipf("needs %s", bin)
			}
		}
		cmd := exec.Command("unshare", "-n", os.Args[0], "-test.run", "^TestTProxyIntegration$", "-test.v")
		cmd.Env = append(os.Environ(), "TP_IN_NETNS=1")
		out, err := cmd.CombinedOutput()
		t.Logf("in netns:\n%s", out)
		if err != nil {
			t.Fatalf("netns run failed: %v", err)
		}
		return
	}
	netnsTest(t)
}

// setupLoopback returns whether IPv6 routing could be set up too.
func setupLoopback(t *testing.T) (v6 bool) {
	t.Helper()
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Link.Set(&rtnetlink.LinkMessage{Family: unix.AF_UNSPEC, Index: uint32(lo.Index), Flags: unix.IFF_UP, Change: unix.IFF_UP}); err != nil {
		t.Fatalf("lo up: %v", err)
	}
	// A host address that is not loopback (like a real NIC's), used as the
	// source of the default route: replies de-NATed from a redirect must
	// not come back to 127.0.0.1 from a foreign address.
	if err := conn.Address.New(&rtnetlink.AddressMessage{Family: unix.AF_INET, PrefixLength: 32, Scope: unix.RT_SCOPE_UNIVERSE, Index: uint32(lo.Index),
		Attributes: &rtnetlink.AddressAttributes{Address: net.IPv4(10, 200, 0, 1).To4(), Local: net.IPv4(10, 200, 0, 1).To4()}}); err != nil && !errors.Is(err, unix.EEXIST) {
		t.Fatalf("add 10.200.0.1: %v", err)
	}
	// A default route, so connect() to non-local addresses gets as far as
	// the OUTPUT hook (the capture reroutes marked packets to lo).
	v6 = true
	for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
		attrs := rtnetlink.RouteAttributes{OutIface: uint32(lo.Index)}
		if fam == unix.AF_INET {
			attrs.Src = net.IPv4(10, 200, 0, 1).To4()
		}
		err := conn.Route.Add(&rtnetlink.RouteMessage{Family: fam, Table: unix.RT_TABLE_MAIN, Protocol: unix.RTPROT_BOOT,
			Scope: unix.RT_SCOPE_LINK, Type: unix.RTN_UNICAST, Attributes: attrs})
		switch {
		case err == nil, errors.Is(err, unix.EEXIST):
		case fam == unix.AF_INET6:
			t.Logf("IPv6 default route via lo not supported here (%v): IPv6 case skipped", err)
			v6 = false
		default:
			t.Fatalf("default route (family %d): %v", fam, err)
		}
	}
	return v6
}

// upstreamDNS answers every A query with 127.0.0.1 and AAAA with ::1.
func upstreamDNS(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil || len(q.Questions) == 0 {
				continue
			}
			qq := q.Questions[0]
			r := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true}, Questions: q.Questions}
			h := dnsmessage.ResourceHeader{Name: qq.Name, Type: qq.Type, Class: dnsmessage.ClassINET, TTL: 60}
			switch qq.Type {
			case dnsmessage.TypeA:
				r.Answers = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}}}
			case dnsmessage.TypeAAAA:
				r.Answers = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AAAAResource{AAAA: netip.IPv6Loopback().As16()}}}
			}
			b, _ := r.Pack()
			pc.WriteTo(b, from)
		}
	}()
	return pc.LocalAddr().String()
}

// testEgress stands in for the egress manager: it dials the (loopback)
// origin by name, the way an exit would, and records what it was asked.
type testEgress struct {
	resolver *net.Resolver
	mu       sync.Mutex
	seen     []string
}

func (e *testEgress) Dial(ctx context.Context, target, host string, port uint16) (net.Conn, string, error) {
	e.mu.Lock()
	e.seen = append(e.seen, target+" "+host)
	e.mu.Unlock()
	d := net.Dialer{Control: capture.BypassControl, Resolver: e.resolver}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	return c, target, err
}

func (e *testEgress) DialTailnet(context.Context, string, uint16) (net.Conn, string, error) {
	return nil, "", errors.New("no tailnet in test")
}

func netnsTest(t *testing.T) {
	v6 := setupLoopback(t)
	upstream := upstreamDNS(t)

	// Origin: echoes the Host header it received.
	oln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	originPort := oln.Addr().(*net.TCPAddr).Port
	go http.Serve(oln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "origin saw %s", r.Host) }))

	engine, err := rule.Compile([]config.Rule{
		{Domain: []string{"mixed.test"}, Port: []uint16{uint16(originPort)}, Egress: config.TargetDirect},
		{DomainSuffix: []string{"egress.test", "mixed.test"}, Egress: "vps"},
		{IPCIDR: []string{"203.0.113.0/24"}, Egress: "vps"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rules := func() *rule.Engine { return engine }
	pool, _ := fakeip.New(fakeip.DefaultInet4, fakeip.DefaultInet6)
	bypass := net.Dialer{Control: capture.BypassControl}
	upResolver := dnsserver.Resolver([]string{upstream}, &bypass)
	eg := &testEgress{resolver: upResolver}
	tracker := proxy.NewTracker()
	router := &proxy.Router{Rules: rules, Egress: eg, Tracker: tracker,
		Direct: net.Dialer{Control: capture.BypassControl, Resolver: upResolver}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dns := &dnsserver.Server{Pool: pool, Rules: rules, Upstreams: []string{upstream}, Canary: true, Dialer: bypass, Logf: t.Logf}
	pc, dln, err := dnsserver.Listen("127.0.0.1:11053")
	if err != nil {
		t.Fatal(err)
	}
	go dns.Serve(ctx, pc, dln)
	const tport = 17893
	lns, err := capture.ListenTProxy(tport)
	if err != nil {
		t.Fatal(err)
	}
	in := &proxy.Transparent{Router: router, Pool: pool, ListenPort: tport, Logf: t.Logf}
	for _, ln := range lns {
		go in.Serve(ctx, ln)
	}

	opts := capture.Options{Scope: capture.ScopeSelective, TProxyPort: tport, DNSPort: 11053,
		FakeIP: pool.Prefixes(), Route: append(pool.Prefixes(), netip.MustParsePrefix("203.0.113.0/24"))}
	if err := capture.Setup(opts); err != nil {
		t.Fatal(err)
	}
	defer capture.Teardown()

	// Applications use "the system resolver" at some external address: the
	// DNS hijack sends it to tailproxy's DNS front end.
	sysResolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, "192.0.2.53:53")
	}}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext:       (&net.Dialer{Resolver: sysResolver}).DialContext,
		DisableKeepAlives: true,
	}}
	get := func(url string, host string) string {
		t.Helper()
		req, _ := http.NewRequest("GET", url, nil)
		if host != "" {
			req.Host = host
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	// 1. DNS hijack + FakeIP.
	direct := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, "127.0.0.1:11053")
	}}
	if a, err := direct.LookupNetIP(ctx, "ip4", "www.egress.test"); err != nil {
		t.Fatalf("direct query to the DNS front end: %v (queries=%d fake=%d)", err, dns.Queries.Load(), dns.Fake.Load())
	} else {
		t.Logf("direct query: %v", a)
	}
	addrs, err := sysResolver.LookupNetIP(ctx, "ip4", "www.egress.test")
	if err != nil || len(addrs) != 1 || !fakeip.DefaultInet4.Contains(addrs[0]) {
		out, _ := exec.Command("nft", "list", "table", "inet", capture.TableName).CombinedOutput()
		t.Fatalf("hijacked DNS: %v %v (dns queries=%d fwd=%d fail=%d)\n%s", addrs, err, dns.Queries.Load(), dns.Forwarded.Load(), dns.Failed.Load(), out)
	}
	if _, err := sysResolver.LookupNetIP(ctx, "ip4", dnsserver.CanaryDomain); err == nil {
		t.Fatal("canary resolved")
	}
	t.Logf("www.egress.test -> %s (FakeIP via hijacked DNS)", addrs[0])

	// 2. FakeIP connection -> egress, by name.
	url := fmt.Sprintf("http://www.egress.test:%d/", originPort)
	if body := get(url, ""); body != fmt.Sprintf("origin saw www.egress.test:%d", originPort) {
		t.Fatalf("fakeip via egress: %q", body)
	}
	// 3. Routed ip_cidr, domain from the HTTP Host header (sniffing).
	if body := get(fmt.Sprintf("http://203.0.113.7:%d/", originPort), "api.sniffed.test"); body != "origin saw api.sniffed.test" {
		t.Fatalf("sniffed: %q", body)
	}
	// 4. FakeIP name whose rule for this port is direct: dialed by name
	// with the bypass mark and the upstream resolver (not the FakeIP).
	if body := get(fmt.Sprintf("http://mixed.test:%d/", originPort), ""); body != fmt.Sprintf("origin saw mixed.test:%d", originPort) {
		t.Fatalf("direct in capture: %q", body)
	}
	// 5. IPv6 FakeIP.
	a6, err := sysResolver.LookupNetIP(ctx, "ip6", "v6.egress.test")
	if err != nil || len(a6) != 1 || !fakeip.DefaultInet6.Contains(a6[0]) {
		t.Fatalf("AAAA: %v %v", a6, err)
	}
	if v6 {
		if body := get(fmt.Sprintf("http://[%s]:%d/", a6[0], originPort), "v6.egress.test"); !strings.HasPrefix(body, "origin saw") {
			t.Fatalf("v6 fakeip: %q", body)
		}
	}
	// 6. UDP to a FakeIP is refused at once (only TCP is proxied).
	start := time.Now()
	u, werr := net.Dial("udp", net.JoinHostPort(addrs[0].String(), "443"))
	if werr == nil {
		_, werr = u.Write([]byte("quic"))
		if werr == nil {
			u.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, werr = u.Read(make([]byte, 10))
		}
		u.Close()
	}
	if !errors.Is(werr, syscall.ENETUNREACH) && !errors.Is(werr, syscall.EHOSTUNREACH) && !errors.Is(werr, syscall.ECONNREFUSED) {
		t.Fatalf("UDP to FakeIP: want an immediate unreachable error, got %v", werr)
	}
	t.Logf("UDP to FakeIP refused after %v: %v", time.Since(start).Round(time.Millisecond), werr)
	// TCP to the same FakeIP still works (checked above), so the rule is UDP-only.

	snap := tracker.Snapshot()
	got := map[string]proxy.ConnView{}
	for _, c := range snap.Recent {
		got[c.Host] = c
		t.Logf("conn: %s:%d src=%s domain_source=%s dest_ip=%s -> %s via %s err=%q", c.Host, c.Port, c.DomainSrc, c.Inbound+"/"+c.DomainSrc, c.DestIP, c.Target, c.Via, c.Error)
	}
	check := func(host, src, target string) {
		t.Helper()
		c, ok := got[host]
		if !ok || c.Inbound != "tproxy" || c.DomainSrc != src || c.Target != target || c.Error != "" {
			t.Errorf("%s: want tproxy/%s -> %s, got %+v", host, src, target, c)
		}
	}
	check("www.egress.test", "fakeip", "vps")
	check("api.sniffed.test", "http", "vps")
	check("mixed.test", "fakeip", "direct")
	if v6 {
		check("v6.egress.test", "fakeip", "vps")
	}
	if c := got["api.sniffed.test"]; c.DestIP != "203.0.113.7" {
		t.Errorf("dest ip: %+v", c)
	}

	// 7. "all" scope: an address outside every rule is captured too and
	// goes direct (it fails here: nothing answers 198.51.100.1 in the netns).
	opts.Scope = capture.ScopeAll
	if err := capture.Setup(opts); err != nil {
		t.Fatal(err)
	}
	c, _ := net.DialTimeout("tcp", fmt.Sprintf("198.51.100.1:%d", originPort), 3*time.Second)
	if c != nil {
		c.Write([]byte("GET / HTTP/1.1\r\nHost: any.test\r\n\r\n"))
		time.Sleep(500 * time.Millisecond)
		c.Close()
	}
	found := false
	for _, v := range append(tracker.Snapshot().Recent, tracker.Snapshot().Active...) {
		if v.Host == "any.test" && v.Inbound == "tproxy" && v.Target == config.TargetDirect && v.DestIP == "198.51.100.1" {
			found = true
		}
	}
	if !found {
		t.Error("all scope: connection to 198.51.100.1 was not captured")
	}

	// 8. Teardown leaves nothing behind.
	if err := capture.Teardown(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("nft", "list", "table", "inet", capture.TableName).CombinedOutput(); err == nil {
		t.Fatalf("table still present:\n%s", out)
	}
	conn, _ := rtnetlink.Dial(nil)
	defer conn.Close()
	rules4, _ := conn.Rule.List()
	for _, r := range rules4 {
		if r.Attributes != nil && r.Attributes.FwMark != nil && *r.Attributes.FwMark == capture.RouteMark {
			t.Fatalf("policy rule left behind: %+v", r)
		}
	}
	t.Logf("eg saw: %v", eg.seen)
}
