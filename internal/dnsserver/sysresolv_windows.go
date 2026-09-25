//go:build windows

package dnsserver

import (
	"net/netip"
	"slices"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const systemResolverSource = "the network adapters' DNS settings"

// siteLocalDNS is fec0::/10, where Windows lists placeholder DNS servers
// (fec0:0:0:ffff::1-3) on adapters without IPv6 DNS.
var siteLocalDNS = netip.MustParsePrefix("fec0::/10")

// systemResolvers reads the DNS servers of the adapters that are up
// (Windows has no resolv.conf), in the order Windows lists the adapters.
func systemResolvers(exclude []netip.Addr) []string {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagDefault)
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range adapters {
		if a.OperStatus != winipcfg.IfOperStatusUp || a.IfType == winipcfg.IfTypeSoftwareLoopback {
			continue
		}
		for dns := a.FirstDNSServerAddress; dns != nil; dns = dns.Next {
			ip, ok := netip.AddrFromSlice(dns.Address.IP())
			if !ok {
				continue
			}
			ip = ip.Unmap()
			// Link-local servers would need the adapter as a zone.
			if !usableResolver(ip, exclude) || ip.IsLinkLocalUnicast() || siteLocalDNS.Contains(ip) {
				continue
			}
			if s := netip.AddrPortFrom(ip, 53).String(); !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	return out
}
