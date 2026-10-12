package bacarra

import (
	"context"
	"errors"
	"net/netip"

	"tailscale.com/net/tsaddr"
)

// ErrTailscaleNotDetected is returned when no active official Tailscale interface is found on the host.
var ErrTailscaleNotDetected = errors.New("official Tailscale network interface not found")

// IsTailscaleIP checks if an address belongs to RFC 6598 CGNAT block (100.64.0.0/10)
// or Tailscale IPv6 ULA block (fd7a:115c:a1e0::/48).
func IsTailscaleIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	return tsaddr.CGNATRange().Contains(ip) || tsaddr.TailscaleULARange().Contains(ip)
}

// ValidateAdapterIPs checks a slice of IP addresses and returns only those belonging
// to the official Tailscale ranges (RFC 6598 CGNAT or ULA).
// If none match, it returns ErrTailscaleNotDetected.
func ValidateAdapterIPs(ips []netip.Addr) ([]netip.Addr, error) {
	var valid []netip.Addr
	for _, ip := range ips {
		if IsTailscaleIP(ip) {
			valid = append(valid, ip)
		}
	}
	if len(valid) == 0 {
		return nil, ErrTailscaleNotDetected
	}
	return valid, nil
}

// DiscoverAdapter detects the active official Tailscale network interface on the host.
// If the interface is missing, down, or not configured with a valid Tailscale IP,
// it returns ErrTailscaleNotDetected without mocking.
func DiscoverAdapter(ctx context.Context) (*AdapterInfo, error) {
	return discoverAdapterPlatform(ctx)
}
