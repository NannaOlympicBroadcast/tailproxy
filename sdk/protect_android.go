//go:build android

package sdk

import (
	"errors"

	"tailscale.com/net/netns"
)

// setPlatformProtect makes the Tailscale nodes' sockets bypass the VPN
// too (tailscale.com/net/netns.SetAndroidProtectFunc, as the Tailscale
// Android app does).
func setPlatformProtect(protect func(fd int) bool) {
	netns.SetAndroidProtectFunc(func(fd int) error {
		if !protect(fd) {
			return errors.New("VpnService.protect refused the socket")
		}
		return nil
	})
}
