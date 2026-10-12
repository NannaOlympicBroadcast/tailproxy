//go:build linux

package bacarra

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

func discoverAdapterPlatform(ctx context.Context) (*AdapterInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	for _, ifc := range ifaces {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Linux: match tailscale0 or tailscale* interfaces
		if !strings.HasPrefix(ifc.Name, "tailscale") {
			continue
		}

		// Operational status check: interface must be UP
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}

		var ips []netip.Addr
		for _, a := range addrs {
			var ip netip.Addr
			switch v := a.(type) {
			case *net.IPNet:
				if parsed, ok := netip.AddrFromSlice(v.IP); ok {
					ip = parsed.Unmap()
				}
			case *net.IPAddr:
				if parsed, ok := netip.AddrFromSlice(v.IP); ok {
					ip = parsed.Unmap()
				}
			default:
				if p, err := netip.ParsePrefix(a.String()); err == nil {
					ip = p.Addr().Unmap()
				}
			}
			if ip.IsValid() {
				ips = append(ips, ip)
			}
		}

		validIPs, err := ValidateAdapterIPs(ips)
		if err != nil {
			continue
		}

		return &AdapterInfo{
			Name:  ifc.Name,
			Index: ifc.Index,
			IPs:   validIPs,
		}, nil
	}

	return nil, ErrTailscaleNotDetected
}
