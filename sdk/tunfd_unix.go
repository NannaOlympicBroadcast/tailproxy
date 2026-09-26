//go:build linux || darwin || freebsd || openbsd

package sdk

import (
	"context"
	"os"

	"github.com/tailscale/wireguard-go/tun"
)

// ServeTUNFD is ServeTUN for a TUN file descriptor, as a platform VPN
// hands it out (Android VpnService.Builder.establish().detachFd(); on iOS
// the utun socket of NEPacketTunnelProvider). The engine owns fd from
// then on and closes it.
func (e *Engine) ServeTUNFD(ctx context.Context, fd int, mtu int, o TUNOptions) error {
	if mtu <= 0 {
		mtu = 1500
	}
	dev, err := tun.CreateTUNFromFile(os.NewFile(uintptr(fd), "tun"), mtu)
	if err != nil {
		return err
	}
	return e.ServeTUN(ctx, dev, o)
}
