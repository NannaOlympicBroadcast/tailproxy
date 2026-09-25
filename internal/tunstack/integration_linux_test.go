//go:build linux

package tunstack_test

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
	"testing"
	"time"

	"github.com/jsimonetti/rtnetlink"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/capture"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/dnsserver"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/fakeip"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/proxy"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/tunstack"
)

// TestTUNIntegration runs a real TUN device, policy routing and the stack
// in a private network namespace. It re-executes the test binary under
// `unshare -n`; it needs root and /dev/net/tun.
func TestTUNIntegration(t *testing.T) {
	if os.Getenv("TP_IN_NETNS") == "" {
		if os.Geteuid() != 0 {
			t.Skip("needs root")
		}
		if _, err := os.Stat("/dev/net/tun"); err != nil {
			t.Skip("needs /dev/net/tun")
		}
		if _, err := exec.LookPath("unshare"); err != nil {
			t.Skip("needs unshare")
		}
		cmd := exec.Command("unshare", "-n", os.Args[0], "-test.run", "^TestTUNIntegration$", "-test.v")
		cmd.Env = append(os.Environ(), "TP_IN_NETNS=1")
		out, err := cmd.CombinedOutput()
		t.Logf("in netns:\n%s", out)
		if err != nil {
			t.Fatalf("netns run failed: %v", err)
		}
		return
	}
	netnsTUN(t)
}

// egress stands in for an exit: every name is served by the local origin,
// dialed with the bypass mark as tsnet's sockets are.
type egress struct {
	mu   sync.Mutex
	seen []string
}

func (e *egress) Dial(ctx context.Context, target, host string, port uint16) (net.Conn, string, error) {
	e.mu.Lock()
	e.seen = append(e.seen, "tcp "+target+" "+host)
	e.mu.Unlock()
	d := net.Dialer{Control: capture.BypassControl}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
	return c, target, err
}

func (e *egress) DialUDP(ctx context.Context, target, host string, port uint16) (net.Conn, string, error) {
	e.mu.Lock()
	e.seen = append(e.seen, "udp "+target+" "+host)
	e.mu.Unlock()
	d := net.Dialer{Control: capture.BypassControl}
	c, err := d.DialContext(ctx, "udp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
	return c, target, err
}

func (e *egress) DialTailnet(context.Context, string, uint16) (net.Conn, string, error) {
	return nil, "", errors.New("no tailnet")
}

func netnsTUN(t *testing.T) {
	var logMu sync.Mutex
	logDone := false
	logf := func(format string, args ...any) {
		logMu.Lock()
		defer logMu.Unlock()
		if !logDone {
			t.Logf(format, args...)
		}
	}
	defer func() {
		logMu.Lock()
		logDone = true
		logMu.Unlock()
	}()

	// lo up (the origin listens there).
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		t.Fatal(err)
	}
	lo, _ := net.InterfaceByName("lo")
	if err := conn.Link.Set(&rtnetlink.LinkMessage{Family: unix.AF_UNSPEC, Index: uint32(lo.Index), Flags: unix.IFF_UP, Change: unix.IFF_UP}); err != nil {
		t.Fatal(err)
	}
	conn.Close()

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
	router := &proxy.Router{Rules: rules, Egress: eg, Tracker: tracker}
	dns := &dnsserver.Server{Pool: pool, Rules: rules, Upstreams: []string{"127.0.0.1:1"}, Logf: logf}

	const name = "tptest0"
	dev, err := tun.CreateTUN(name, 1500)
	if err != nil {
		t.Fatal(err)
	}
	st, err := tunstack.New(dev, tunstack.Options{DNSAddr: netip.MustParseAddr("172.19.0.2"), DNS: dns, Logf: logf})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rt, err := tunstack.NewRouter(name, netip.MustParsePrefix("172.19.0.1/30"))
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if err := rt.SetRoutes(append(pool.Prefixes(), netip.MustParsePrefix("172.19.0.2/32"))); err != nil {
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

	// capture.udp: block — a second device whose stack refuses UDP: the
	// kernel turns its ICMP port unreachable into ECONNREFUSED at once.
	dev2, err := tun.CreateTUN("tptest1", 1500)
	if err != nil {
		t.Fatal(err)
	}
	st2, err := tunstack.New(dev2, tunstack.Options{RejectUDP: true, Logf: logf})
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	rt2, err := tunstack.NewRouter("tptest1", netip.MustParsePrefix("172.19.1.1/30"))
	if err != nil {
		t.Fatal(err)
	}
	if err := rt2.SetRoutes([]netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}); err != nil {
		t.Fatal(err)
	}
	rc, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	rc.Write([]byte("quic"))
	rc.SetReadDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	_, err = rc.Read(buf)
	rc.Close()
	if !errors.Is(err, unix.ECONNREFUSED) {
		t.Fatalf("UDP with RejectUDP: want ECONNREFUSED, got %v", err)
	}
	t.Logf("UDP refused after %v", time.Since(start).Round(time.Millisecond))

	// Closing removes the policy rules.
	rt.Close()
	c2, _ := rtnetlink.Dial(nil)
	defer c2.Close()
	rs, _ := c2.Rule.List()
	for _, r := range rs {
		if r.Attributes != nil && r.Attributes.Priority != nil && (*r.Attributes.Priority == 9894 || *r.Attributes.Priority == 9895) {
			t.Errorf("rule priority %d left after Close", *r.Attributes.Priority)
		}
	}
}
