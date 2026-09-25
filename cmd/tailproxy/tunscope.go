package main

import (
	"net/netip"
	"slices"
	"sync/atomic"
)

// TUN mode with capture.scope: all routes the default route into the
// device (as two halves, so the system's own default route stays and
// keeps naming the physical interface).
var tunDefaultRoutes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1"),
	netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1"),
}

// tunExcludes decides which destinations under the TUN default route go
// direct without rules, like the ranges nftables never captures in
// tproxy's "all" scope: capture.exclude_cidr always, and the default
// excludes (local, private, link-local, multicast, tailnet) unless a
// routed prefix (FakeIP pool, ip_cidr rule, learned address) covers them.
type tunExcludes struct {
	user, def []netip.Prefix
	routed    atomic.Pointer[[]netip.Prefix]
}

const (
	bypassUser    = "capture.exclude_cidr"
	bypassDefault = "默认排除网段（本机 / 局域网 / 保留 / tailnet）"
)

func contains(ps []netip.Prefix, ip netip.Addr) bool {
	return slices.ContainsFunc(ps, func(p netip.Prefix) bool { return p.Contains(ip) })
}

// reason returns why ip bypasses the rules, or "" to route it normally.
func (e *tunExcludes) reason(ip netip.Addr) string {
	ip = ip.Unmap()
	if contains(e.user, ip) {
		return bypassUser
	}
	if contains(e.def, ip) {
		if r := e.routed.Load(); r == nil || !contains(*r, ip) {
			return bypassDefault
		}
	}
	return ""
}

// all is every excluded prefix, for the router's throw routes.
func (e *tunExcludes) all() []netip.Prefix {
	return append(slices.Clone(e.user), e.def...)
}
