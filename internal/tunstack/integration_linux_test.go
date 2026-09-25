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
	"testing"
	"time"

	"github.com/jsimonetti/rtnetlink"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
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

// TestTUNSystemDNS runs the scenario in the host namespace, where
// systemd-resolved runs, and points system DNS at the stack. It changes
// host routing and DNS for a moment, so it only runs when
// TP_TUN_INTEGRATION=1 (CI).
func TestTUNSystemDNS(t *testing.T) {
	if os.Getenv("TP_TUN_INTEGRATION") != "1" {
		t.Skip("set TP_TUN_INTEGRATION=1 (needs root and systemd-resolved)")
	}
	if err := exec.Command("resolvectl", "status").Run(); err != nil {
		t.Skipf("systemd-resolved not available: %v", err)
	}
	tunScenario(t, "tptest2", true)
}

// systemDNSSnapshot is resolved's per-link DNS servers.
func systemDNSSnapshot(t *testing.T) string {
	out, err := exec.Command("resolvectl", "dns").CombinedOutput()
	if err != nil {
		t.Fatalf("resolvectl dns: %v: %s", err, out)
	}
	return string(out)
}

func netnsTUN(t *testing.T) {
	logf, done := testLogf(t)
	defer done()

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

	tunScenario(t, "tptest0", false)

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
	rt2, err := tunstack.NewRouter(dev2, netip.MustParsePrefix("172.19.1.1/30"))
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
	_, err = rc.Read(make([]byte, 64))
	rc.Close()
	if !errors.Is(err, unix.ECONNREFUSED) {
		t.Fatalf("UDP with RejectUDP: want ECONNREFUSED, got %v", err)
	}
	t.Logf("UDP refused after %v", time.Since(start).Round(time.Millisecond))

	// Closing removes the policy rules.
	rt2.Close()
	c2, _ := rtnetlink.Dial(nil)
	defer c2.Close()
	rs, _ := c2.Rule.List()
	for _, r := range rs {
		if r.Attributes != nil && r.Attributes.Priority != nil && (*r.Attributes.Priority == 9894 || *r.Attributes.Priority == 9895) {
			t.Errorf("rule priority %d left after Close", *r.Attributes.Priority)
		}
	}

	netnsTUNAll(t)
}

// netnsTUNAll is capture scope all: the default route (two halves) goes
// into the device, an excluded range is thrown back to the main table.
// Captured TCP to a real address reaches the egress chosen by an ip_cidr
// rule; the excluded range never enters the device (the namespace's main
// table has no route for it, so connecting fails at once).
func netnsTUNAll(t *testing.T) {
	logf, done := testLogf(t)
	defer done()
	oln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer oln.Close()
	port := oln.Addr().(*net.TCPAddr).Port
	go http.Serve(oln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "origin") }))

	engine, err := rule.Compile([]config.Rule{{IPCIDR: []string{"192.0.2.0/24"}, Egress: "vps"}})
	if err != nil {
		t.Fatal(err)
	}
	eg := &egress{}
	tracker := proxy.NewTracker()
	router := &proxy.Router{Rules: func() *rule.Engine { return engine }, Egress: eg, Tracker: tracker, Direct: net.Dialer{Control: tunstack.BypassControl}}
	dev, err := tun.CreateTUN("tptest3", 1500)
	if err != nil {
		t.Fatal(err)
	}
	st, err := tunstack.New(dev, tunstack.Options{DNSAddr: netip.MustParseAddr("172.19.2.2"), RejectUDP: true,
		RejectUDPTo: netip.MustParsePrefix("198.18.0.0/15").Contains, Logf: logf})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rt, err := tunstack.NewRouter(dev, netip.MustParsePrefix("172.19.2.1/30"))
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	excluded := netip.MustParsePrefix("203.0.113.0/24")
	if err := rt.SetExcludes([]netip.Prefix{excluded}); err != nil {
		t.Fatal(err)
	}
	if err := rt.SetRoutes([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go (&proxy.Transparent{Router: router, Logf: logf}).Serve(ctx, st.Listener())

	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := c.Get(fmt.Sprintf("http://192.0.2.10:%d/", port))
	if err != nil {
		t.Fatalf("captured address: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "origin" {
		t.Fatalf("body %q", body)
	}
	eg.mu.Lock()
	seen := strings.Join(eg.seen, ", ")
	eg.mu.Unlock()
	if !strings.Contains(seen, "tcp vps 192.0.2.10") {
		t.Fatalf("egress saw %q", seen)
	}
	_, err = net.DialTimeout("tcp", "203.0.113.9:80", 2*time.Second)
	if !errors.Is(err, unix.ENETUNREACH) {
		t.Fatalf("excluded range: want ENETUNREACH (not captured), got %v", err)
	}
	t.Logf("scope all: 192.0.2.10 captured (%s), 203.0.113.9 excluded (%v)", seen, err)

	rt.Close()
	conn, _ := rtnetlink.Dial(nil)
	defer conn.Close()
	routes, _ := conn.Route.List()
	for _, r := range routes {
		if r.Attributes.Table == tunstack.RouteTable && r.Type == unix.RTN_THROW {
			t.Errorf("throw route %v/%d left after Close", r.Attributes.Dst, r.DstLength)
		}
	}
}
