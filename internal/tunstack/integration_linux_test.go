//go:build linux

package tunstack_test

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/jsimonetti/rtnetlink"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"

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

	tunScenario(t, "tptest0")

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
}
