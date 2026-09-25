//go:build linux

package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"golang.org/x/sys/unix"
)

// UDPListener receives UDP diverted by TPROXY. Each packet comes with its
// original destination (IP_RECVORIGDSTADDR), since one socket receives
// every flow.
type UDPListener struct {
	c *net.UDPConn
}

// ListenTProxyUDP listens for TPROXY-diverted UDP on 127.0.0.1:port and
// [::1]:port, like ListenTProxy for TCP.
func ListenTProxyUDP(port uint16) ([]*UDPListener, error) {
	var out []*UDPListener
	closeAll := func() {
		for _, l := range out {
			l.Close()
		}
	}
	for _, host := range []string{"127.0.0.1", "::1"} {
		v6 := host == "::1"
		fam, level, transparent, origdst := unix.AF_INET, unix.SOL_IP, unix.IP_TRANSPARENT, unix.IP_RECVORIGDSTADDR
		if v6 {
			fam, level, transparent, origdst = unix.AF_INET6, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, unix.IPV6_RECVORIGDSTADDR
		}
		c, err := udpSocket(fam, func(fd int) error {
			if err := unix.SetsockoptInt(fd, level, transparent, 1); err != nil {
				return err
			}
			if err := unix.SetsockoptInt(fd, level, origdst, 1); err != nil {
				return err
			}
			return bind(fd, netip.AddrPortFrom(netip.MustParseAddr(host), port))
		})
		if err != nil {
			if v6 && len(out) > 0 && (errors.Is(err, unix.EADDRNOTAVAIL) || errors.Is(err, unix.EAFNOSUPPORT)) {
				continue // IPv6 disabled: IPv4 only
			}
			closeAll()
			if errors.Is(err, unix.EPERM) {
				return nil, fmt.Errorf("capture: TPROXY needs root (CAP_NET_ADMIN): %w", err)
			}
			return nil, fmt.Errorf("capture: listen udp %s: %w", host, err)
		}
		out = append(out, &UDPListener{c: c})
	}
	return out, nil
}

// ReadFrom reads one packet and returns the client's address and the
// destination the client sent it to.
func (l *UDPListener) ReadFrom(b []byte) (n int, client, orig netip.AddrPort, err error) {
	oob := make([]byte, 128)
	for {
		var oobn int
		n, oobn, _, client, err = l.c.ReadMsgUDPAddrPort(b, oob)
		if err != nil {
			return 0, client, orig, err
		}
		var ok bool
		if orig, ok = origDst(oob[:oobn]); ok {
			return n, netip.AddrPortFrom(client.Addr().Unmap(), client.Port()), orig, nil
		}
		// No original destination: not diverted by TPROXY (someone sent to
		// the port directly). Drop it.
	}
}

// Close closes the listener.
func (l *UDPListener) Close() error { return l.c.Close() }

// LocalAddr is the listening address.
func (l *UDPListener) LocalAddr() net.Addr { return l.c.LocalAddr() }

// origDst finds IP_ORIGDSTADDR / IPV6_ORIGDSTADDR in control messages.
func origDst(oob []byte) (netip.AddrPort, bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}, false
	}
	for _, m := range msgs {
		d := m.Data
		switch {
		case m.Header.Level == unix.SOL_IP && m.Header.Type == unix.IP_ORIGDSTADDR && len(d) >= unix.SizeofSockaddrInet4:
			// struct sockaddr_in: family, port (network order), address.
			return netip.AddrPortFrom(netip.AddrFrom4([4]byte(d[4:8])), binary.BigEndian.Uint16(d[2:4])), true
		case m.Header.Level == unix.SOL_IPV6 && m.Header.Type == unix.IPV6_ORIGDSTADDR && len(d) >= unix.SizeofSockaddrInet6:
			// struct sockaddr_in6: family, port, flowinfo, address, scope.
			a := netip.AddrFrom16([16]byte(d[8:24])).Unmap()
			return netip.AddrPortFrom(a, binary.BigEndian.Uint16(d[2:4])), true
		}
	}
	return netip.AddrPort{}, false
}

// DialUDPReply opens the socket that serves one UDP flow: bound to the
// flow's original destination (a foreign address, hence IP_TRANSPARENT)
// and connected to the client. Replies written to it carry the source the
// client expects; and because TPROXY looks up connected sockets first,
// the flow's later packets are delivered to it instead of the listener.
// It carries the bypass mark, so the capture never takes it back.
func DialUDPReply(orig, client netip.AddrPort) (*net.UDPConn, error) {
	orig = netip.AddrPortFrom(orig.Addr().Unmap(), orig.Port())
	client = netip.AddrPortFrom(client.Addr().Unmap(), client.Port())
	if orig.Addr().Is4() != client.Addr().Is4() {
		return nil, fmt.Errorf("capture: udp reply: address families differ (%s, %s)", orig, client)
	}
	fam, level, transparent := unix.AF_INET, unix.SOL_IP, unix.IP_TRANSPARENT
	if !orig.Addr().Is4() {
		fam, level, transparent = unix.AF_INET6, unix.SOL_IPV6, unix.IPV6_TRANSPARENT
	}
	return udpSocket(fam, func(fd int) error {
		for _, o := range []struct{ level, opt, v int }{
			{level, transparent, 1},
			// Several clients may talk to the same destination.
			{unix.SOL_SOCKET, unix.SO_REUSEADDR, 1},
			{unix.SOL_SOCKET, unix.SO_MARK, BypassMark},
		} {
			if err := unix.SetsockoptInt(fd, o.level, o.opt, o.v); err != nil {
				return err
			}
		}
		if err := bind(fd, orig); err != nil {
			return fmt.Errorf("bind %s: %w", orig, err)
		}
		if err := unix.Connect(fd, sockaddr(client)); err != nil {
			return fmt.Errorf("connect %s: %w", client, err)
		}
		return nil
	})
}

// udpSocket creates a UDP socket, runs setup on it and wraps it.
func udpSocket(fam int, setup func(fd int) error) (*net.UDPConn, error) {
	fd, err := unix.Socket(fam, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_UDP)
	if err != nil {
		return nil, err
	}
	if err := setup(fd); err != nil {
		unix.Close(fd)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "udp")
	defer f.Close() // FileConn dups the descriptor
	c, err := net.FileConn(f)
	if err != nil {
		return nil, err
	}
	return c.(*net.UDPConn), nil
}

func bind(fd int, ap netip.AddrPort) error { return unix.Bind(fd, sockaddr(ap)) }

func sockaddr(ap netip.AddrPort) unix.Sockaddr {
	if ap.Addr().Is4() {
		return &unix.SockaddrInet4{Port: int(ap.Port()), Addr: ap.Addr().As4()}
	}
	return &unix.SockaddrInet6{Port: int(ap.Port()), Addr: ap.Addr().As16()}
}
