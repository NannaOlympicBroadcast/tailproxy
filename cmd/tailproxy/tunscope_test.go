package main

import (
	"net/netip"
	"testing"
)

func TestTUNExcludes(t *testing.T) {
	e := &tunExcludes{
		user: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		def:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fc00::/7")},
	}
	routed := []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("fc00::/18"), netip.MustParsePrefix("203.0.113.7/32")}
	e.routed.Store(&routed)
	for ip, want := range map[string]string{
		"203.0.113.7":          bypassUser, // user excludes win over routes
		"10.2.3.4":             bypassDefault,
		"10.1.2.3":             "", // an ip_cidr rule routes it
		"fc00::5":              "", // the FakeIP pool
		"fd00::1":              bypassDefault,
		"1.1.1.1":              "",
		"::ffff:10.2.3.4":      bypassDefault,
		"2606:4700:4700::1111": "",
	} {
		if got := e.reason(netip.MustParseAddr(ip)); got != want {
			t.Errorf("reason(%s) = %q, want %q", ip, got, want)
		}
	}
	if len(e.all()) != 3 {
		t.Fatalf("all: %v", e.all())
	}
}
