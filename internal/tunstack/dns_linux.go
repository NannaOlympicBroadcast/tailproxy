//go:build linux

package tunstack

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
)

// SetSystemDNS makes systemd-resolved send every query to addr, through
// the device: the device's link gets addr as its DNS server and the
// route-only domain "~.", which matches every name (resolvectl(1),
// systemd-resolved.service(8)). The link's settings go with the device;
// Close also reverts them.
func (r *Router) SetSystemDNS(addr netip.Addr) error {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return errors.New("tun: system DNS: resolvectl not found (systemd-resolved is needed to set system DNS automatically)")
	}
	if err := run("resolvectl", "dns", r.name, addr.String()); err != nil {
		return fmt.Errorf("tun: system DNS: %w", err)
	}
	if err := run("resolvectl", "domain", r.name, "~."); err != nil {
		run("resolvectl", "revert", r.name)
		return fmt.Errorf("tun: system DNS: %w", err)
	}
	run("resolvectl", "flush-caches")
	r.mu.Lock()
	r.dnsSet = true
	r.mu.Unlock()
	return nil
}

// revertDNS undoes SetSystemDNS (the device may be gone already).
func (r *Router) revertDNS() {
	r.mu.Lock()
	set := r.dnsSet
	r.dnsSet = false
	r.mu.Unlock()
	if set {
		run("resolvectl", "revert", r.name)
		run("resolvectl", "flush-caches")
	}
}
