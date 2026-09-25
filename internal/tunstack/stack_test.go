package tunstack

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// clientHost is a userspace host (172.19.0.1) whose every packet goes to
// its device: the Stack under test reads them as a TUN device would.
type clientHost struct {
	st     *stack.Stack
	ep     *channel.Endpoint
	ctx    context.Context
	cancel context.CancelFunc // closing the device ends pending reads, as for a real TUN
}

func newClientHost(t *testing.T) *clientHost {
	t.Helper()
	h := &clientHost{
		st: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		}),
		ep: channel.New(256, 1420, ""),
	}
	h.ctx, h.cancel = context.WithCancel(context.Background())
	t.Cleanup(h.cancel)
	if e := h.st.CreateNIC(1, h.ep); e != nil {
		t.Fatal(e)
	}
	h.st.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4([4]byte{172, 19, 0, 1}).WithPrefix()}, stack.AddressProperties{})
	h.st.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	return h
}

func full(ap netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(ap.Addr().As4()), Port: ap.Port()}
}

func (h *clientHost) dialTCP(ctx context.Context, dst string) (net.Conn, error) {
	return gonet.DialContextTCP(ctx, h.st, full(netip.MustParseAddrPort(dst)), ipv4.ProtocolNumber)
}

func (h *clientHost) dialUDP(dst string) (net.Conn, error) {
	r := full(netip.MustParseAddrPort(dst))
	return gonet.DialUDP(h.st, nil, &r, ipv4.ProtocolNumber)
}

// device adapts the host's link to tun.Device.
func (h *clientHost) device() tun.Device { return &hostDevice{h: h, events: make(chan tun.Event, 1)} }

type hostDevice struct {
	h      *clientHost
	events chan tun.Event
}

func (d *hostDevice) File() *os.File { return nil }
func (d *hostDevice) Read(bufs [][]byte, sizes []int, off int) (int, error) {
	pb := d.h.ep.ReadContext(d.h.ctx)
	if pb == nil {
		return 0, os.ErrClosed
	}
	n := off
	for _, v := range pb.AsSlices() {
		n += copy(bufs[0][n:], v)
	}
	pb.DecRef()
	sizes[0] = n - off
	return 1, nil
}

// sniffWrites, if set, sees every packet the stack sends to the client.
var sniffWrites func([]byte)

func (d *hostDevice) Write(bufs [][]byte, off int) (int, error) {
	for _, b := range bufs {
		if sniffWrites != nil {
			sniffWrites(append([]byte(nil), b[off:]...))
		}
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), b[off:]...))})
		d.h.ep.InjectInbound(header.IPv4ProtocolNumber, pb)
		pb.DecRef()
	}
	return len(bufs), nil
}
func (d *hostDevice) MTU() (int, error)        { return 1420, nil }
func (d *hostDevice) Name() (string, error)    { return "test", nil }
func (d *hostDevice) Events() <-chan tun.Event { return d.events }
func (d *hostDevice) Close() error             { d.h.cancel(); return nil }
func (d *hostDevice) BatchSize() int           { return 1 }

// fakeDNS answers every A query with 198.18.0.9.
type fakeDNS struct{}

func (fakeDNS) Answer(_ context.Context, q []byte) []byte {
	var m dnsmessage.Message
	if m.Unpack(q) != nil || len(m.Questions) == 0 {
		return nil
	}
	m.Response = true
	m.Answers = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 10},
		Body:   &dnsmessage.AResource{A: [4]byte{198, 18, 0, 9}},
	}}
	b, _ := m.Pack()
	return b
}

func (d fakeDNS) ServeConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return
	}
	q := make([]byte, int(l[0])<<8|int(l[1]))
	if _, err := io.ReadFull(c, q); err != nil {
		return
	}
	r := d.Answer(ctx, q)
	c.Write(append([]byte{byte(len(r) >> 8), byte(len(r))}, r...))
}

// A client host is a second userspace stack whose TUN device is the one
// the Stack under test reads and writes: its packets to any address reach
// the Stack, like an OS routing those addresses into the TUN.
func TestStack(t *testing.T) {
	client := newClientHost(t)
	s, err := New(client.device(), Options{DNSAddr: netip.MustParseAddr("172.19.0.2"), DNS: fakeDNS{}, UDPTimeout: time.Second, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// TCP: echo server on the Stack side, reporting the destination.
	go func() {
		ln := s.Listener()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				io.WriteString(c, c.LocalAddr().String()+" "+string(buf[:n]))
			}()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, dst := range []string{"198.18.0.5:443", "203.0.113.7:80"} {
		c, err := client.dialTCP(ctx, dst)
		if err != nil {
			t.Fatalf("dial %s: %v", dst, err)
		}
		io.WriteString(c, "hi")
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		b, _ := io.ReadAll(c)
		c.Close()
		if string(b) != dst+" hi" {
			t.Fatalf("tcp %s: got %q", dst, b)
		}
	}

	// UDP: packets arrive with the original destination; replies go out
	// from it (the client's connected socket accepts nothing else).
	ul := s.UDPListener()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, cl, orig, err := ul.ReadFrom(buf)
			if err != nil {
				return
			}
			r, err := s.Reply(orig, cl)
			if err != nil {
				t.Error(err)
				return
			}
			r.Write(append([]byte("echo "+orig.String()+" "), buf[:n]...))
		}
	}()
	uc, err := client.dialUDP("198.18.0.6:443")
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uc.Write([]byte("q"))
	uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, err := uc.Read(buf)
	if err != nil || string(buf[:n]) != "echo 198.18.0.6:443 q" {
		t.Fatalf("udp: %q %v", buf[:n], err)
	}

	// DNS on the stack's DNS address, over UDP and TCP.
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 7, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("chat.openai.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	qb, _ := q.Pack()
	dc, err := client.dialUDP("172.19.0.2:53")
	if err != nil {
		t.Fatal(err)
	}
	defer dc.Close()
	dc.Write(qb)
	dc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err = dc.Read(buf); err != nil {
		t.Fatalf("dns udp: %v", err)
	}
	checkA := func(b []byte) {
		t.Helper()
		var m dnsmessage.Message
		if err := m.Unpack(b); err != nil || len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{198, 18, 0, 9} {
			t.Fatalf("dns answer: %+v %v", m, err)
		}
	}
	checkA(buf[:n])
	tc, err := client.dialTCP(ctx, "172.19.0.2:53")
	if err != nil {
		t.Fatal(err)
	}
	tc.Write(append([]byte{byte(len(qb) >> 8), byte(len(qb))}, qb...))
	tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, _ := io.ReadAll(tc)
	tc.Close()
	if len(resp) < 2 {
		t.Fatalf("dns tcp: %q", resp)
	}
	checkA(resp[2:])

	// An idle UDP flow is closed.
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		n := len(s.flows)
		s.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d UDP flows still open", n)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// capture.udp: block — the stack answers UDP with ICMP port unreachable
// from the original destination (an OS then fails the client's socket with
// ECONNREFUSED at once), but in-stack DNS still answers.
func TestStackRejectUDP(t *testing.T) {
	icmp := make(chan []byte, 4)
	sniffWrites = func(p []byte) {
		if len(p) >= 28 && p[9] == 1 { // IPv4 + ICMP
			icmp <- p
		}
	}
	defer func() { sniffWrites = nil }()
	client := newClientHost(t)
	// Only UDP to the FakeIP pool is refused (the default-route case);
	// other UDP reaches the UDP listener.
	fake := netip.MustParsePrefix("198.18.0.0/15")
	s, err := New(client.device(), Options{DNSAddr: netip.MustParseAddr("172.19.0.2"), DNS: fakeDNS{}, RejectUDP: true, RejectUDPTo: fake.Contains})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	uc, err := client.dialUDP("198.18.0.6:443")
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uc.Write([]byte("quic"))
	select {
	case p := <-icmp:
		ihl := int(p[0]&0x0f) * 4
		src := netip.AddrFrom4([4]byte(p[12:16]))
		if typ, code := p[ihl], p[ihl+1]; typ != 3 || code != 3 || src.String() != "198.18.0.6" {
			t.Fatalf("ICMP type %d code %d from %s, want port unreachable from 198.18.0.6", typ, code, src)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no ICMP port unreachable")
	}

	got := make(chan netip.AddrPort, 1)
	go func() {
		buf := make([]byte, 64)
		if _, _, orig, err := s.UDPListener().ReadFrom(buf); err == nil {
			got <- orig
		}
	}()
	oc, err := client.dialUDP("203.0.113.5:9")
	if err != nil {
		t.Fatal(err)
	}
	defer oc.Close()
	oc.Write([]byte("other"))
	select {
	case orig := <-got:
		if orig.String() != "203.0.113.5:9" {
			t.Fatalf("UDP listener got %s", orig)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("UDP outside RejectUDPTo was not delivered")
	}

	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 1}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("a.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	qb, _ := q.Pack()
	dc, err := client.dialUDP("172.19.0.2:53")
	if err != nil {
		t.Fatal(err)
	}
	defer dc.Close()
	dc.Write(qb)
	dc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := dc.Read(make([]byte, 512)); err != nil {
		t.Fatalf("DNS with RejectUDP: %v", err)
	}
}

func TestIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:80": true, "[::1]:443": true, "[::ffff:127.0.0.1]:1": true,
		"198.18.0.1:443": false, "example.com:80": false, "": false,
	} {
		if got := isLoopback(addr); got != want {
			t.Errorf("isLoopback(%q) = %v", addr, got)
		}
	}
}
