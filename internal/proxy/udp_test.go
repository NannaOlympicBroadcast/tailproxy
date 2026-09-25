package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/fakeip"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
)

type udpPacket struct {
	data         []byte
	client, orig netip.AddrPort
}

// fakeUDPListener hands out packets pushed by the test, each with the
// original destination the test chose (what TPROXY would report).
type fakeUDPListener struct {
	ch   chan udpPacket
	once sync.Once
	done chan struct{}
}

func newFakeUDPListener() *fakeUDPListener {
	return &fakeUDPListener{ch: make(chan udpPacket, 16), done: make(chan struct{})}
}

func (l *fakeUDPListener) ReadFrom(b []byte) (int, netip.AddrPort, netip.AddrPort, error) {
	select {
	case p := <-l.ch:
		return copy(b, p.data), p.client, p.orig, nil
	case <-l.done:
		return 0, netip.AddrPort{}, netip.AddrPort{}, net.ErrClosed
	}
}

func (l *fakeUDPListener) Close() error { l.once.Do(func() { close(l.done) }); return nil }

// udpEcho answers every packet with "echo:" + payload.
func udpEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			pc.WriteToUDPAddrPort(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

// udpEgress sends every UDP flow to the local echo server, like an exit
// that serves every name; target "relay" fails like a relay egress.
type udpEgress struct {
	fakeEgress
	echo netip.AddrPort
}

func (e *udpEgress) DialUDP(ctx context.Context, target, host string, port uint16) (net.Conn, string, error) {
	e.mu.Lock()
	e.dials = append(e.dials, "udp "+target+" "+host)
	e.mu.Unlock()
	if target == "relay" {
		return nil, "", errors.New("relay egress does not carry UDP")
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", e.echo.String())
	return c, target, err
}

func TestTransparentUDP(t *testing.T) {
	echo := udpEcho(t)
	eng, err := rule.Compile([]config.Rule{
		{DomainSuffix: []string{"egress.test"}, Egress: "vps"},
		{IPCIDR: []string{"203.0.113.0/24"}, Egress: "relay"},
		{IPCIDR: []string{"198.51.100.0/24"}, Egress: config.TargetReject},
	})
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := fakeip.New(fakeip.DefaultInet4, fakeip.DefaultInet6)
	eg := &udpEgress{echo: echo}
	tr := NewTracker()
	r := &Router{Rules: func() *rule.Engine { return eng }, Egress: eg, Tracker: tr}
	var replyMu sync.Mutex
	replies := map[netip.AddrPort]netip.AddrPort{} // client -> orig asked for
	in := &TransparentUDP{Router: r, Pool: pool, Timeout: 300 * time.Millisecond, Logf: t.Logf,
		// Without TPROXY the reply socket cannot bind the original
		// destination; any socket connected to the client will do.
		Reply: func(orig, client netip.AddrPort) (net.Conn, error) {
			replyMu.Lock()
			replies[client] = orig
			replyMu.Unlock()
			return net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(client))
		}}
	ln := newFakeUDPListener()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go in.Serve(ctx, ln)

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	caddr := client.LocalAddr().(*net.UDPAddr).AddrPort()
	send := func(orig netip.AddrPort, msg string) { ln.ch <- udpPacket{[]byte(msg), caddr, orig} }
	recv := func(want string) {
		t.Helper()
		client.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 2048)
		n, err := client.Read(buf)
		if err != nil || string(buf[:n]) != want {
			t.Fatalf("got %q %v, want %q", buf[:n], err, want)
		}
	}

	// FakeIP name -> egress, several packets on one flow.
	fake := netip.AddrPortFrom(pool.V4("quic.egress.test"), 443)
	send(fake, "a")
	recv("echo:a")
	send(fake, "b")
	recv("echo:b")
	if in.Flows() != 1 {
		t.Fatalf("flows %d, want 1", in.Flows())
	}
	// Direct: an address no rule matches, dialed as is.
	send(echo, "direct")
	recv("echo:direct")

	// Relay egress and reject: no reply, and the flow is not retried per packet.
	relay := netip.MustParseAddrPort("203.0.113.9:443")
	send(relay, "x")
	send(relay, "y")
	send(netip.MustParseAddrPort("198.51.100.1:443"), "z")
	client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := client.Read(make([]byte, 64)); err == nil {
		t.Fatal("got a reply for a flow that cannot be routed")
	}

	// Idle flows end and are recorded.
	deadline := time.Now().Add(3 * time.Second)
	for len(tr.Snapshot().Active) > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("flows did not expire: %+v", tr.Snapshot().Active)
		}
		time.Sleep(50 * time.Millisecond)
	}
	byHost := map[string]ConnView{}
	for _, c := range tr.Snapshot().Recent {
		if c.Network != "udp" {
			t.Errorf("network %q", c.Network)
		}
		byHost[c.Host] = c
	}
	if c := byHost["quic.egress.test"]; c.Target != "vps" || c.DomainSrc != "fakeip" || c.Up != 2 || c.Down != 12 || c.Error != "" {
		t.Errorf("egress flow: %+v", c)
	}
	if c := byHost[echo.Addr().String()]; c.Target != config.TargetDirect || c.Up != 6 {
		t.Errorf("direct flow: %+v", c)
	}
	if c := byHost["203.0.113.9"]; c.Target != "relay" || !strings.Contains(c.Error, "does not carry UDP") {
		t.Errorf("relay flow: %+v", c)
	}
	if c := byHost["198.51.100.1"]; c.Target != config.TargetReject {
		t.Errorf("reject flow: %+v", c)
	}
	if n := len(tr.Snapshot().Recent); n != 4 {
		t.Errorf("recorded %d flows, want 4 (one per flow, not per packet)", n)
	}
	eg.mu.Lock()
	if len(eg.dials) != 2 || eg.dials[0] != "udp vps quic.egress.test" || eg.dials[1] != "udp relay 203.0.113.9" {
		t.Errorf("dials %v", eg.dials)
	}
	eg.mu.Unlock()
	replyMu.Lock()
	if replies[caddr] == (netip.AddrPort{}) {
		t.Error("reply socket not opened for the client")
	}
	replyMu.Unlock()
}
