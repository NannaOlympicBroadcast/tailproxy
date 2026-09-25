//go:build linux || darwin || windows

package tunstack_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/dnsserver"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/fakeip"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/proxy"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/tunstack"
)

// egress stands in for an exit: every name is served by the local origin,
// kept out of the TUN routes (tunstack.BypassControl).
type egress struct {
	mu   sync.Mutex
	seen []string
}

func (e *egress) Dial(ctx context.Context, target, host string, port uint16) (net.Conn, string, error) {
	e.mu.Lock()
	e.seen = append(e.seen, "tcp "+target+" "+host)
	e.mu.Unlock()
	d := net.Dialer{Control: tunstack.BypassControl}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
	return c, target, err
}

func (e *egress) DialUDP(ctx context.Context, target, host string, port uint16) (net.Conn, string, error) {
	e.mu.Lock()
	e.seen = append(e.seen, "udp "+target+" "+host)
	e.mu.Unlock()
	d := net.Dialer{Control: tunstack.BypassControl}
	c, err := d.DialContext(ctx, "udp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
	return c, target, err
}

func (e *egress) DialTailnet(context.Context, string, uint16) (net.Conn, string, error) {
	return nil, "", errors.New("no tailnet")
}

// testLogf logs until the test returns; handlers may still run after.
func testLogf(t *testing.T) (logf func(string, ...any), done func()) {
	var mu sync.Mutex
	stopped := false
	return func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			if !stopped {
				t.Logf(format, args...)
			}
		}, func() {
			mu.Lock()
			stopped = true
			mu.Unlock()
		}
}

// escapeIP is a public address the host scenarios route into the device.
const escapeIP = "1.1.1.1"

// tunScenario creates a real TUN device named devName ("utun" on macOS
// picks a free utunN), routes the FakeIP pool and the stack's DNS address
// into it, and checks DNS, HTTP and UDP through it to the egress. With
// systemDNS it then points system DNS at the stack, resolves through the
// system resolver and checks the settings are restored. It needs root /
// administrator rights.
func tunScenario(t *testing.T, devName string, systemDNS bool) {
	logf, done := testLogf(t)
	defer done()
	// Origins: HTTP echoing the Host header, and UDP echo.
	oln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := oln.Addr().(*net.TCPAddr).Port
	go http.Serve(oln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "origin saw %s", r.Host) }))
	uo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer uo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := uo.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			uo.WriteToUDPAddrPort(append([]byte("echo:"), buf[:n]...), from)
		}
	}()

	engine, err := rule.Compile([]config.Rule{{DomainSuffix: []string{"egress.test"}, Egress: "vps"}})
	if err != nil {
		t.Fatal(err)
	}
	rules := func() *rule.Engine { return engine }
	pool, _ := fakeip.New(fakeip.DefaultInet4, fakeip.DefaultInet6)
	eg := &egress{}
	tracker := proxy.NewTracker()
	// Direct dials leave through the physical interface (BypassControl),
	// as in tailproxy.
	router := &proxy.Router{Rules: rules, Egress: eg, Tracker: tracker, Direct: net.Dialer{Control: tunstack.BypassControl}}
	dns := &dnsserver.Server{Pool: pool, Rules: rules, Upstreams: []string{"127.0.0.1:1"}, Logf: logf}

	dev, err := tun.CreateTUN(devName, 1500)
	if err != nil {
		t.Fatal(err)
	}
	st, err := tunstack.New(dev, tunstack.Options{DNSAddr: netip.MustParseAddr("172.19.0.2"), DNS: dns, Logf: logf})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rt, err := tunstack.NewRouter(dev, netip.MustParsePrefix("172.19.0.1/30"))
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	routes := append(pool.Prefixes(), netip.MustParsePrefix("172.19.0.2/32"))
	if systemDNS {
		// A real Internet address routed into the device (host scenarios).
		routes = append(routes, netip.MustParsePrefix(escapeIP+"/32"))
	}
	if err := rt.SetRoutes(routes); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go (&proxy.Transparent{Router: router, Pool: pool, Logf: logf}).Serve(ctx, st.Listener())
	go (&proxy.TransparentUDP{Router: router, Pool: pool, Reply: st.Reply, Logf: logf}).Serve(ctx, st.UDPListener())

	// The system resolver points at the stack's DNS address.
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, "172.19.0.2:53")
	}}
	lctx, lcancel := context.WithTimeout(ctx, 5*time.Second)
	addrs, err := resolver.LookupNetIP(lctx, "ip4", "www.egress.test.")
	lcancel()
	if err != nil || len(addrs) != 1 || !pool.Contains(addrs[0]) {
		t.Fatalf("DNS through the TUN: %v %v", addrs, err)
	}
	t.Logf("www.egress.test -> %s via the in-stack DNS", addrs[0])

	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: (&net.Dialer{Resolver: resolver}).DialContext, DisableKeepAlives: true}}
	resp, err := client.Get(fmt.Sprintf("http://www.egress.test:%d/", port))
	if err != nil {
		t.Fatalf("HTTP through the TUN: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != fmt.Sprintf("origin saw www.egress.test:%d", port) {
		t.Fatalf("HTTP body %q", body)
	}

	uc, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(addrs[0], uint16(port))))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uc.Write([]byte("ping"))
	uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := uc.Read(buf) // connected: only accepts replies from the FakeIP
	if err != nil || string(buf[:n]) != "echo:ping" {
		t.Fatalf("UDP through the TUN: %q %v", buf[:n], err)
	}

	eg.mu.Lock()
	seen := strings.Join(eg.seen, ", ")
	eg.mu.Unlock()
	if !strings.Contains(seen, "tcp vps www.egress.test") || !strings.Contains(seen, "udp vps www.egress.test") {
		t.Fatalf("egress saw %q", seen)
	}
	t.Logf("egress saw: %s", seen)

	if !systemDNS {
		return
	}
	// tailproxy's own direct dials leave the device: a plain HTTP request
	// to an address routed into the TUN is served through the stack by a
	// direct dial bound to the physical interface; if that dial looped
	// back into the device, it would never connect. This is what capture
	// scope all relies on.
	hc := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err = hc.Get("http://" + escapeIP + "/")
	if err != nil {
		t.Fatalf("HTTP to %s through the TUN: %v", escapeIP, err)
	}
	resp.Body.Close()
	var direct bool
	snap := tracker.Snapshot()
	for _, c := range append(snap.Recent, snap.Active...) {
		if c.Target == "direct" && (c.Host == escapeIP || c.DestIP == escapeIP) && c.Inbound == "tproxy" {
			direct = true
		}
	}
	if !direct {
		t.Fatalf("no direct connection to %s recorded: %+v", escapeIP, snap.Recent)
	}
	t.Logf("HTTP %s through the TUN, direct dial out of it: %s", escapeIP, resp.Status)

	before := systemDNSSnapshot(t)
	if err := rt.SetSystemDNS(netip.MustParseAddr("172.19.0.2")); err != nil {
		t.Fatal(err)
	}
	// A fresh name per attempt: a negative answer cached before the
	// change must not hide the new resolver.
	deadline := time.Now().Add(20 * time.Second)
	for i := 0; ; i++ {
		name := fmt.Sprintf("sys%d.egress.test.", i)
		lctx, lcancel := context.WithTimeout(ctx, 3*time.Second)
		got, err := net.DefaultResolver.LookupNetIP(lctx, "ip4", name)
		lcancel()
		if err == nil && len(got) > 0 && pool.Contains(got[0]) {
			t.Logf("system resolver: %s -> %s via the stack", name, got[0])
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("system resolver after SetSystemDNS: %s -> %v %v", name, got, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	if after := systemDNSSnapshot(t); after != before {
		t.Fatalf("system DNS not restored:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}
