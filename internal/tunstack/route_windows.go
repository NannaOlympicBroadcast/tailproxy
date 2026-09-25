//go:build windows

package tunstack

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/tailscale/wireguard-go/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Supported reports whether TUN capture can be set up on this system.
// Windows needs wintun.dll next to tailproxy.exe (https://www.wintun.net).
const Supported = true

// Router sets the Wintun adapter's address and routes through the IP
// Helper API. tailproxy's own sockets stay out of the routes by being
// bound to the physical interface (BypassControl).
type Router struct {
	luid winipcfg.LUID

	mu      sync.Mutex
	applied map[netip.Prefix]bool
}

// NewRouter gives the Wintun adapter addr (e.g. 172.19.0.1/30).
func NewRouter(dev tun.Device, addr netip.Prefix) (*Router, error) {
	nt, ok := dev.(interface{ LUID() uint64 })
	if !ok {
		return nil, errors.New("tun: not a Wintun device")
	}
	luid := winipcfg.LUID(nt.LUID())
	if err := luid.SetIPAddresses([]netip.Prefix{addr}); err != nil {
		return nil, fmt.Errorf("tun: address %s: %w", addr, err)
	}
	return &Router{luid: luid, applied: map[netip.Prefix]bool{}}, nil
}

func nextHop(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}

// SetRoutes makes routes exactly the prefixes routed into the adapter.
func (r *Router) SetRoutes(routes []netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	want := map[netip.Prefix]bool{}
	for _, p := range routes {
		want[p.Masked()] = true
	}
	var errs []error
	for p := range want {
		if r.applied[p] {
			continue
		}
		if err := r.luid.AddRoute(p, nextHop(p), 0); err != nil && !errors.Is(err, windowsErrObjectExists) {
			errs = append(errs, fmt.Errorf("tun: route %s: %w", p, err))
			continue
		}
		r.applied[p] = true
	}
	for p := range r.applied {
		if !want[p] {
			r.luid.DeleteRoute(p, nextHop(p))
			delete(r.applied, p)
		}
	}
	return errors.Join(errs...)
}

// Close is a no-op: the routes go with the adapter.
func (r *Router) Close() error { return nil }

// Cleanup is a no-op on Windows (no policy rules).
func Cleanup() error { return nil }
