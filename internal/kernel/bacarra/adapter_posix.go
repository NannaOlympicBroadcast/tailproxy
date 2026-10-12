//go:build !windows

package bacarra

import (
	"net/netip"
)

// AdapterInfo represents the discovered official Tailscale network interface.
type AdapterInfo struct {
	Name  string
	Index int
	IPs   []netip.Addr
	LUID  uint64
}
