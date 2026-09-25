//go:build windows

package tunstack

import (
	"encoding/binary"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"tailscale.com/net/netmon"
)

// ipUnicastIf is IP_UNICAST_IF / IPV6_UNICAST_IF.
const ipUnicastIf = 31

// BypassControl keeps a socket out of the TUN routes: Windows has no
// fwmark, so the socket is bound to the interface of the default route
// (IP_UNICAST_IF), as Tailscale binds its own sockets. Use it for direct
// dials and upstream DNS.
func BypassControl(network, address string, c syscall.RawConn) error {
	if isLoopback(address) {
		return nil // binding to the physical interface would make loopback unreachable
	}
	dr, err := netmon.DefaultRoute()
	if err != nil || dr.InterfaceIndex == 0 {
		return nil
	}
	idx := uint32(dr.InterfaceIndex)
	v6 := strings.HasSuffix(network, "6") || strings.Contains(address, "]:")
	var serr error
	err = c.Control(func(fd uintptr) {
		if v6 {
			serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, ipUnicastIf, int(idx))
			return
		}
		// IPv4 takes the index in network byte order (an address in 0.0.0.0/8).
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], idx)
		serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, int(binary.NativeEndian.Uint32(b[:])))
	})
	if err != nil {
		return err
	}
	return serr
}
