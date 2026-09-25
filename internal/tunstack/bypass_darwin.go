//go:build darwin

package tunstack

import (
	"fmt"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"tailscale.com/net/netmon"
)

// BypassControl keeps a socket out of the TUN routes: macOS has no fwmark,
// so the socket is bound to the interface of the default route
// (IP_BOUND_IF), as Tailscale binds its own sockets. Use it for direct
// dials and upstream DNS.
func BypassControl(network, address string, c syscall.RawConn) error {
	idx, err := netmon.DefaultRouteInterfaceIndex()
	if err != nil || idx == 0 {
		return nil // no default route: nothing to bind to
	}
	proto, opt := unix.IPPROTO_IP, unix.IP_BOUND_IF
	if strings.HasSuffix(network, "6") || strings.Contains(address, "]:") {
		proto, opt = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	}
	var serr error
	if err := c.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), proto, opt, idx) }); err != nil {
		return err
	}
	if serr != nil {
		return fmt.Errorf("bind to interface %d: %w", idx, serr)
	}
	return nil
}
