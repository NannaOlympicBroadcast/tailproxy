package tunstack

import "net/netip"

// isLoopback reports whether a dial address (host:port) is a loopback
// address: such sockets are never routed into the TUN and must not be
// bound to the physical interface.
func isLoopback(address string) bool {
	ap, err := netip.ParseAddrPort(address)
	return err == nil && ap.Addr().Unmap().IsLoopback()
}
