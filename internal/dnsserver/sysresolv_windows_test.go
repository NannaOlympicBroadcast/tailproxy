//go:build windows

package dnsserver

import (
	"net/netip"
	"testing"
)

// The CI runner's adapters have DNS servers; "system" must find them.
func TestSystemResolversWindows(t *testing.T) {
	ups, err := ParseUpstreams("system")
	if err != nil || len(ups) == 0 {
		t.Fatalf("system: %v %v", ups, err)
	}
	for _, u := range ups {
		ap, err := netip.ParseAddrPort(u)
		if err != nil || ap.Port() != 53 || ap.Addr().IsLoopback() || ap.Addr().IsLinkLocalUnicast() {
			t.Errorf("upstream %q", u)
		}
	}
	t.Logf("system resolvers: %v", ups)
	// An excluded address (TUN mode's DNS) is never returned.
	first, _ := netip.ParseAddrPort(ups[0])
	again, _ := ParseUpstreams("system", first.Addr())
	for _, u := range again {
		if u == ups[0] {
			t.Fatalf("excluded %s still returned: %v", ups[0], again)
		}
	}
}
