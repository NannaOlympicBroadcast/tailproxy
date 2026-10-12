//go:build windows

package bacarra

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func discoverAdapterPlatform(ctx context.Context) (*AdapterInfo, error) {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, 0)
	if err != nil {
		return nil, fmt.Errorf("winipcfg get adapters: %w", err)
	}

	for _, iface := range adapters {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		friendly := iface.FriendlyName()
		desc := iface.Description()

		// Match adapter named "Tailscale" or description mentioning "Tailscale" / "Wintun"
		isMatch := strings.EqualFold(friendly, "Tailscale") ||
			strings.Contains(strings.ToLower(friendly), "tailscale") ||
			strings.Contains(strings.ToLower(desc), "tailscale") ||
			strings.Contains(strings.ToLower(desc), "wintun")

		if !isMatch {
			continue
		}

		// Operational status check: adapter must be active and up
		if iface.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}

		var ips []netip.Addr
		for cur := iface.FirstUnicastAddress; cur != nil; cur = cur.Next {
			rawIP := cur.Address.IP()
			if len(rawIP) > 0 {
				if addr, ok := netip.AddrFromSlice(rawIP); ok {
					ips = append(ips, addr.Unmap())
				}
			}
		}

		validIPs, err := ValidateAdapterIPs(ips)
		if err != nil {
			continue
		}

		return &AdapterInfo{
			Name:  friendly,
			Index: int(iface.IfIndex),
			IPs:   validIPs,
			LUID:  iface.LUID,
		}, nil
	}

	return nil, ErrTailscaleNotDetected
}
