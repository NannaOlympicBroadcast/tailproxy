//go:build linux

package sdk

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jsimonetti/rtnetlink"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/tunstack"
)

// TestServeTUNFD hands the engine a real TUN file descriptor, as a VPN
// app would, in a private network namespace (root, /dev/net/tun).
func TestServeTUNFD(t *testing.T) {
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
		cmd := exec.Command("unshare", "-n", os.Args[0], "-test.run", "^TestServeTUNFD$", "-test.v")
		cmd.Env = append(os.Environ(), "TP_IN_NETNS=1")
		out, err := cmd.CombinedOutput()
		t.Logf("in netns:\n%s", out)
		if err != nil {
			t.Fatalf("netns run failed: %v", err)
		}
		return
	}

	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		t.Fatal(err)
	}
	lo, _ := net.InterfaceByName("lo")
	conn.Link.Set(&rtnetlink.LinkMessage{Family: unix.AF_UNSPEC, Index: uint32(lo.Index), Flags: unix.IFF_UP, Change: unix.IFF_UP})
	conn.Close()

	// The "VPN": a device with its address and routes; the engine only
	// gets a file descriptor for it.
	dev, err := tun.CreateTUN("sdktun0", 1500)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := tunstack.NewRouter(dev, netip.MustParsePrefix("172.19.9.1/30"))
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if err := rt.SetRoutes([]netip.Prefix{netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("172.19.9.2/32")}); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Dup(int(dev.(interface{ File() *os.File }).File().Fd()))
	if err != nil {
		t.Fatal(err)
	}
	dev.Close() // the dup keeps the interface

	upstream := dnsStub(t, netip.MustParseAddr("127.0.0.9"))
	var protected atomic.Int32
	cfg, err := ParseConfig([]byte("rules:\n  - {domain_keyword: [blocked], egress: reject}\n  - {final: direct}\n"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(Options{Config: cfg, StateDir: t.TempDir(), Logf: t.Logf, Protect: func(fd int) bool {
		protected.Add(1)
		// The app's sockets leave the VPN: the bypass mark sends them to
		// the main table (Android: VpnService.protect).
		return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, 0x80000) == nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- e.ServeTUNFD(ctx, fd, 1500, TUNOptions{DNSAddr: netip.MustParseAddr("172.19.9.2"), DNSUpstreams: []string{upstream}})
	}()

	res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, "172.19.9.2:53")
	}}
	lookup := func(name string) []netip.Addr {
		t.Helper()
		lctx, lcancel := context.WithTimeout(ctx, 5*time.Second)
		defer lcancel()
		addrs, err := res.LookupNetIP(lctx, "ip4", name)
		if err != nil {
			t.Fatalf("lookup %s: %v", name, err)
		}
		return addrs
	}
	fake := lookup("www.blocked.test.")
	if len(fake) != 1 || !netip.MustParsePrefix("198.18.0.0/15").Contains(fake[0]) {
		t.Fatalf("routed name: %v, want a FakeIP", fake)
	}
	if real := lookup("plain.test."); len(real) != 1 || real[0].String() != "127.0.0.9" {
		t.Fatalf("unrouted name: %v, want the upstream's answer", real)
	}
	if protected.Load() == 0 {
		t.Fatal("Protect not called for the upstream DNS query")
	}

	// TCP to the FakeIP: routed by name to reject.
	c, err := net.DialTimeout("tcp", netip.AddrPortFrom(fake[0], 443).String(), 3*time.Second)
	if err == nil {
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		c.Read(make([]byte, 1))
		c.Close()
	}
	s := waitRecent(t, e, 1)
	if r := s.Recent[0]; r.Inbound != "tun" || r.Host != "www.blocked.test" || r.DomainSrc != "fakeip" || r.Target != "reject" {
		t.Fatalf("TUN connection record %+v", r)
	}
	// UDP to a FakeIP is refused at once (capture.udp: block).
	uc, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(fake[0], 443)))
	if err != nil {
		t.Fatal(err)
	}
	uc.Write([]byte("quic"))
	uc.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = uc.Read(make([]byte, 16))
	uc.Close()
	if !errors.Is(err, unix.ECONNREFUSED) {
		t.Fatalf("UDP to a FakeIP: want ECONNREFUSED, got %v", err)
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("ServeTUNFD: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeTUNFD did not return")
	}
	t.Logf("TUN fd: FakeIP %s for the routed name, upstream answer for the other, Protect called %d times", fake[0], protected.Load())
}

// dnsStub answers every A query with ip; it returns its address.
func dnsStub(t *testing.T, ip netip.Addr) string {
	t.Helper()
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
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
			b.StartQuestions()
			b.Question(q)
			b.StartAnswers()
			if q.Type == dnsmessage.TypeA {
				b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: ip.As4()})
			}
			msg, _ := b.Finish()
			pc.WriteTo(msg, from)
		}
	}()
	return pc.LocalAddr().String()
}
