//go:build darwin

package tunstack

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sync"

	"github.com/tailscale/wireguard-go/tun"
)

// Supported reports whether TUN capture can be set up on this system.
const Supported = true

// Router sets the utun device's address and routes with ifconfig and
// route(8). tailproxy's own sockets stay out of the routes by being bound
// to the physical interface (BypassControl).
type Router struct {
	name string

	mu      sync.Mutex
	applied map[netip.Prefix]bool
}

// NewRouter gives the utun device addr (e.g. 172.19.0.1/30) and brings it
// up. utun is point-to-point; routes name the interface directly.
func NewRouter(dev tun.Device, addr netip.Prefix) (*Router, error) {
	name, err := dev.Name()
	if err != nil {
		return nil, err
	}
	if !addr.Addr().Is4() {
		return nil, errors.New("tun: capture.tun_address must be IPv4")
	}
	ip := addr.Addr().String()
	if err := run("/sbin/ifconfig", name, "inet", ip, ip, "netmask", net4Mask(addr.Bits()), "up"); err != nil {
		return nil, fmt.Errorf("tun: %w", err)
	}
	return &Router{name: name, applied: map[netip.Prefix]bool{}}, nil
}

func net4Mask(bits int) string {
	m := ^uint32(0) << (32 - bits)
	return fmt.Sprintf("%d.%d.%d.%d", byte(m>>24), byte(m>>16), byte(m>>8), byte(m))
}

// SetRoutes makes routes exactly the prefixes routed into the device.
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
		fam := "-inet"
		if !p.Addr().Is4() {
			fam = "-inet6"
		}
		// Replace a stale route left by a crash, then add.
		exec.Command("/sbin/route", "-q", "-n", "delete", fam, p.String(), "-interface", r.name).Run()
		if err := run("/sbin/route", "-q", "-n", "add", fam, p.String(), "-interface", r.name); err != nil {
			errs = append(errs, fmt.Errorf("tun: route %s: %w", p, err))
			continue
		}
		r.applied[p] = true
	}
	for p := range r.applied {
		if !want[p] {
			fam := "-inet"
			if !p.Addr().Is4() {
				fam = "-inet6"
			}
			exec.Command("/sbin/route", "-q", "-n", "delete", fam, p.String(), "-interface", r.name).Run()
			delete(r.applied, p)
		}
	}
	return errors.Join(errs...)
}

// Close restores system DNS if SetSystemDNS changed it; the routes go
// with the utun device.
func (r *Router) Close() error { return restoreSystemDNS() }

// Cleanup restores system DNS left pointing at the stack by a crash.
func Cleanup() error { return restoreSystemDNS() }
