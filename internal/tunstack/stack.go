// Package tunstack terminates the TCP and UDP that a TUN device receives in
// a userspace TCP/IP stack (gVisor's netstack), DESIGN §4.1 TUN mode. It
// accepts connections to any address routed into the device and hands
// them to tailproxy's transparent inbounds: TCP connections report the
// original destination as their local address, like TPROXY sockets, and
// UDP flows come through a listener with the original destination.
//
// DNS to the stack's own DNS address is answered in the stack, so the
// operating system's resolver can point at it.
package tunstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const nicID = 1

// offset is headroom before each packet in device buffers: Linux TUN
// devices with offloads need room for a virtio header.
const offset = 16

// DNS answers the stack's DNS traffic (dnsserver.Server).
type DNS interface {
	Answer(ctx context.Context, q []byte) []byte
	ServeConn(ctx context.Context, c net.Conn)
}

// Options configure a Stack.
type Options struct {
	// DNSAddr is the address the stack answers DNS on (UDP and TCP 53),
	// e.g. 172.19.0.2; route it into the device and point the system
	// resolver at it. Zero disables in-stack DNS.
	DNSAddr netip.Addr
	DNS     DNS
	// UDPTimeout closes an idle UDP flow (default 5 minutes).
	UDPTimeout time.Duration
	// RejectUDP answers UDP (except in-stack DNS) with ICMP port
	// unreachable, so clients fall back to TCP at once (capture.udp: block).
	RejectUDP bool
	Logf      func(string, ...any)
}

// Stack is a netstack attached to a TUN device.
type Stack struct {
	dev  tun.Device
	ep   *channel.Endpoint
	st   *stack.Stack
	opts Options
	mtu  int

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	tcpConns chan net.Conn
	udpPkts  chan udpPacket

	mu    sync.Mutex
	flows map[flowKey]*gonet.UDPConn
}

type flowKey struct{ client, orig netip.AddrPort }

type udpPacket struct {
	data         []byte
	client, orig netip.AddrPort
}

// New attaches a netstack to dev and starts moving packets. Close stops
// it; the device is closed too.
func New(dev tun.Device, o Options) (*Stack, error) {
	mtu, err := dev.MTU()
	if err != nil {
		return nil, err
	}
	s := &Stack{
		dev: dev, opts: o, mtu: mtu,
		ep: channel.New(1024, uint32(mtu), ""),
		st: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		}),
		tcpConns: make(chan net.Conn),
		udpPkts:  make(chan udpPacket, 256),
		flows:    map[flowKey]*gonet.UDPConn{},
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	sack := tcpip.TCPSACKEnabled(true)
	s.st.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	if e := s.st.CreateNIC(nicID, s.ep); e != nil {
		return nil, fmt.Errorf("tunstack: create NIC: %v", e)
	}
	// Accept packets to any address, and answer from any address: the
	// stack stands in for every destination routed into the device.
	if e := s.st.SetPromiscuousMode(nicID, true); e != nil {
		return nil, fmt.Errorf("tunstack: promiscuous mode: %v", e)
	}
	if e := s.st.SetSpoofing(nicID, true); e != nil {
		return nil, fmt.Errorf("tunstack: spoofing: %v", e)
	}
	s.st.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	tcpFwd := tcp.NewForwarder(s.st, 0, 1024, s.acceptTCP)
	udpFwd := udp.NewForwarder(s.st, s.acceptUDP)
	s.st.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	s.st.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	s.wg.Add(2)
	go s.fromDevice()
	go s.toDevice()
	return s, nil
}

func (s *Stack) logf(format string, args ...any) {
	if s.opts.Logf != nil {
		s.opts.Logf(format, args...)
	}
}

// fromDevice injects packets read from the device into the stack.
func (s *Stack) fromDevice() {
	defer s.wg.Done()
	batch := s.dev.BatchSize()
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, offset+65535)
	}
	sizes := make([]int, batch)
	for {
		n, err := s.dev.Read(bufs, sizes, offset)
		if err != nil {
			if s.ctx.Err() == nil && !errors.Is(err, tun.ErrTooManySegments) {
				s.logf("tunstack: read: %v", err)
			}
			if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		for i := 0; i < n; i++ {
			pkt := bufs[i][offset : offset+sizes[i]]
			if len(pkt) == 0 {
				continue
			}
			var proto tcpip.NetworkProtocolNumber
			switch pkt[0] >> 4 {
			case 4:
				proto = header.IPv4ProtocolNumber
			case 6:
				proto = header.IPv6ProtocolNumber
			default:
				continue
			}
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), pkt...))})
			s.ep.InjectInbound(proto, pb)
			pb.DecRef()
		}
	}
}

// toDevice writes the stack's outgoing packets to the device.
func (s *Stack) toDevice() {
	defer s.wg.Done()
	buf := make([]byte, offset+65535)
	for {
		pb := s.ep.ReadContext(s.ctx)
		if pb == nil {
			return
		}
		n := offset
		for _, v := range pb.AsSlices() {
			n += copy(buf[n:], v)
		}
		pb.DecRef()
		if _, err := s.dev.Write([][]byte{buf[:n]}, offset); err != nil && s.ctx.Err() == nil {
			s.logf("tunstack: write: %v", err)
		}
	}
}

func addrPort(a tcpip.Address, port uint16) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return netip.AddrPortFrom(ip.Unmap(), port)
}

func (s *Stack) isDNS(dst netip.AddrPort) bool {
	return s.opts.DNS != nil && s.opts.DNSAddr.IsValid() && dst.Port() == 53 && dst.Addr() == s.opts.DNSAddr.Unmap()
}

func (s *Stack) acceptTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true) // RST
		return
	}
	r.Complete(false)
	ep.SocketOptions().SetKeepAlive(true)
	c := gonet.NewTCPConn(&wq, ep)
	if s.isDNS(addrPort(id.LocalAddress, id.LocalPort)) {
		go s.opts.DNS.ServeConn(s.ctx, c)
		return
	}
	select {
	case s.tcpConns <- c:
	case <-s.ctx.Done():
		c.Close()
	}
}

// acceptUDP opens an endpoint for a new UDP flow: bound to the original
// destination and connected to the client, so replies carry the source the
// client expects. Its packets go to the UDP listener.
func (s *Stack) acceptUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	k := flowKey{client: addrPort(id.RemoteAddress, id.RemotePort), orig: addrPort(id.LocalAddress, id.LocalPort)}
	if s.opts.RejectUDP && !s.isDNS(k.orig) {
		return false // unhandled: the stack replies port unreachable
	}
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return false
	}
	c := gonet.NewUDPConn(&wq, ep)
	if s.isDNS(k.orig) {
		go s.serveDNS(c)
		return true
	}
	s.mu.Lock()
	if old := s.flows[k]; old != nil {
		old.Close()
	}
	s.flows[k] = c
	s.mu.Unlock()
	go s.readFlow(k, c)
	return true
}

func (s *Stack) udpTimeout() time.Duration {
	if s.opts.UDPTimeout > 0 {
		return s.opts.UDPTimeout
	}
	return 5 * time.Minute
}

// readFlow forwards a flow's packets to the listener until the flow is
// idle or closed.
func (s *Stack) readFlow(k flowKey, c *gonet.UDPConn) {
	defer func() {
		s.mu.Lock()
		if s.flows[k] == c {
			delete(s.flows, k)
		}
		s.mu.Unlock()
		c.Close()
	}()
	buf := make([]byte, 65535)
	for {
		c.SetReadDeadline(time.Now().Add(s.udpTimeout()))
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		select {
		case s.udpPkts <- udpPacket{append([]byte(nil), buf[:n]...), k.client, k.orig}:
		case <-s.ctx.Done():
			return
		default: // listener congested: drop
		}
	}
}

func (s *Stack) serveDNS(c *gonet.UDPConn) {
	defer c.Close()
	buf := make([]byte, 65535)
	for {
		c.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			if resp := s.opts.DNS.Answer(s.ctx, q); resp != nil {
				c.Write(resp)
			}
		}()
	}
}

// Close stops the stack and closes the device.
func (s *Stack) Close() error {
	s.cancel()
	err := s.dev.Close()
	s.ep.Close()
	s.mu.Lock()
	for _, c := range s.flows {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	s.st.Close()
	return err
}

// Listener returns the stack's TCP connections. Their LocalAddr is the
// destination the client connected to.
func (s *Stack) Listener() net.Listener { return tcpListener{s} }

type tcpListener struct{ s *Stack }

func (l tcpListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.s.tcpConns:
		return c, nil
	case <-l.s.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (l tcpListener) Close() error   { return nil } // the stack owns it
func (l tcpListener) Addr() net.Addr { return &net.TCPAddr{} }

// UDPListener returns the stack's UDP packets with their original
// destinations (proxy.UDPListener).
func (s *Stack) UDPListener() *UDPListener { return &UDPListener{s} }

// UDPListener delivers UDP packets from the stack.
type UDPListener struct{ s *Stack }

// ReadFrom returns the next packet, its client and its original destination.
func (l *UDPListener) ReadFrom(b []byte) (int, netip.AddrPort, netip.AddrPort, error) {
	select {
	case p := <-l.s.udpPkts:
		return copy(b, p.data), p.client, p.orig, nil
	case <-l.s.ctx.Done():
		return 0, netip.AddrPort{}, netip.AddrPort{}, net.ErrClosed
	}
}

// Close is a no-op: the stack owns the listener.
func (l *UDPListener) Close() error { return nil }

// Reply returns the socket that answers a flow's client (proxy.TransparentUDP
// Reply). Its writes go out from the original destination; it yields no
// packets (they all come through the listener) and closing it ends the flow.
func (s *Stack) Reply(orig, client netip.AddrPort) (net.Conn, error) {
	s.mu.Lock()
	c := s.flows[flowKey{client, orig}]
	s.mu.Unlock()
	if c == nil {
		return nil, fmt.Errorf("tunstack: no UDP flow %s -> %s", client, orig)
	}
	return &replyConn{UDPConn: c, done: make(chan struct{})}, nil
}

type replyConn struct {
	*gonet.UDPConn
	once sync.Once
	done chan struct{}
}

func (r *replyConn) Read([]byte) (int, error) {
	<-r.done
	return 0, net.ErrClosed
}

func (r *replyConn) Close() error {
	r.once.Do(func() { close(r.done) })
	return r.UDPConn.Close()
}
