//go:build windows

package tunstack

import (
	"fmt"
	"net/netip"

	"golang.org/x/sys/windows"
)

// SetSystemDNS gives the Wintun adapter addr as its DNS server and the
// lowest interface metric, so Windows asks it first; wireguard-windows
// sets up its tunnels the same way (tunnel/addressconfig.go). The
// settings go with the adapter; Close also clears them.
func (r *Router) SetSystemDNS(addr netip.Addr) error {
	ipif, err := r.luid.IPInterface(windows.AF_INET)
	if err != nil {
		return fmt.Errorf("tun: system DNS: %w", err)
	}
	ipif.UseAutomaticMetric = false
	ipif.Metric = 0
	if err := ipif.Set(); err != nil {
		return fmt.Errorf("tun: system DNS: interface metric: %w", err)
	}
	if err := r.luid.SetDNS(windows.AF_INET, []netip.Addr{addr}, nil); err != nil {
		return fmt.Errorf("tun: system DNS: %w", err)
	}
	flushResolverCache()
	r.mu.Lock()
	r.dnsSet = true
	r.mu.Unlock()
	return nil
}

func (r *Router) revertDNS() {
	r.mu.Lock()
	set := r.dnsSet
	r.dnsSet = false
	r.mu.Unlock()
	if set {
		r.luid.FlushDNS(windows.AF_INET) // fails harmlessly once the adapter is gone
		flushResolverCache()
	}
}

var procDnsFlushResolverCache = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")

// flushResolverCache drops cached answers (what `ipconfig /flushdns` does),
// so names resolved before the change are asked again.
func flushResolverCache() {
	if procDnsFlushResolverCache.Find() == nil {
		procDnsFlushResolverCache.Call()
	}
}
