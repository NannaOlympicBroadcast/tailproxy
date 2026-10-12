//go:build windows

package bacarra

import (
	"net/netip"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// AdapterInfo represents the discovered official Tailscale network interface.
type AdapterInfo struct {
	Name  string
	Index int
	IPs   []netip.Addr
	LUID  winipcfg.LUID
}
