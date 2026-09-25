//go:build linux

package tunstack

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// BypassControl keeps a socket out of the TUN routes: Linux marks it, and
// the policy rule before the TUN table sends marked packets to main. Use
// it for direct dials and upstream DNS.
func BypassControl(network, address string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, bypassMark)
	}); err != nil {
		return err
	}
	return serr
}
