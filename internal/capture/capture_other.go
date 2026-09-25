//go:build !linux

package capture

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
)

// Supported reports whether transparent capture is available here.
const Supported = false

var errUnsupported = errors.New("capture: transparent capture (TPROXY) is only implemented on Linux; use capture.socks_listen")

// BypassControl is a no-op outside Linux.
func BypassControl(network, address string, c syscall.RawConn) error { return nil }

// ListenTProxy is Linux-only.
func ListenTProxy(port uint16) ([]net.Listener, error) { return nil, errUnsupported }

// Setup is Linux-only.
func Setup(o Options) error { return errUnsupported }

// Teardown is a no-op outside Linux.
func Teardown() error { return nil }

// UDPListener is Linux-only.
type UDPListener struct{}

// ListenTProxyUDP is Linux-only.
func ListenTProxyUDP(port uint16) ([]*UDPListener, error) { return nil, errUnsupported }

// ReadFrom is Linux-only.
func (l *UDPListener) ReadFrom(b []byte) (int, netip.AddrPort, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, netip.AddrPort{}, errUnsupported
}

// Close is Linux-only.
func (l *UDPListener) Close() error { return nil }

// LocalAddr is Linux-only.
func (l *UDPListener) LocalAddr() net.Addr { return nil }

// DialUDPReply is Linux-only.
func DialUDPReply(orig, client netip.AddrPort) (*net.UDPConn, error) { return nil, errUnsupported }
