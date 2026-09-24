// Package capture sets up transparent capture on Linux (DESIGN §4.1, §4.6):
// an nftables table that sends TCP to the TPROXY listener and DNS to the
// DNS front end, and the policy routing TPROXY needs. Everything lives in
// one table (inet tailproxy) and one routing table, so teardown is exact.
package capture

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Marks. BypassMark is Tailscale's LinuxBypassMark: tsnet sets it on its own
// sockets when running as root (tailscale.com/net/netns), and tailproxy sets
// it on direct dials and upstream DNS queries, so none of them is captured
// again. RouteMark tags packets that policy routing delivers locally.
const (
	BypassMark = 0x80000
	BypassMask = 0xff0000
	RouteMark  = 0x2000
	// RouteTable and RulePriority are the policy-routing table and rule.
	RouteTable   = 7893
	RulePriority = 9893
	TableName    = "tailproxy"
)

// Scopes.
const (
	ScopeSelective = "selective" // FakeIP pools + routed ip_cidr only
	ScopeAll       = "all"       // all TCP except excluded ranges
)

// DefaultExclude are ranges never captured in "all" scope: local,
// private, link-local, multicast and the tailnet (left to the system
// Tailscale client, DESIGN §4.1).
var DefaultExclude = []string{
	"0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "100.64.0.0/10",
	"::1/128", "fe80::/10", "ff00::/8", "fc00::/7", "fd7a:115c:a1e0::/48",
}

// Options describe the ruleset.
type Options struct {
	Scope      string
	TProxyPort uint16
	// DNSPort, if set, receives DNS (TCP/UDP 53) from local processes, and
	// from the LAN when HijackLANDNS is set (the DNS server must then
	// listen on a non-loopback address).
	DNSPort      uint16
	HijackLANDNS bool
	// Route are always captured: FakeIP pools and routed ip_cidr prefixes.
	Route []netip.Prefix
	// FakeIP pools; UDP to them is made unreachable by policy routing so
	// clients fall back to TCP quickly (only TCP is proxied).
	FakeIP []netip.Prefix
	// Exclude are never captured and win over Route (capture.exclude_cidr).
	Exclude []netip.Prefix
}

func split(ps []netip.Prefix) (v4, v6 []string) {
	seen := map[string]bool{}
	for _, p := range ps {
		p = p.Masked()
		s := p.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		if p.Addr().Is4() {
			v4 = append(v4, s)
		} else {
			v6 = append(v6, s)
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return
}

func set(b *strings.Builder, name, typ string, elems []string) {
	fmt.Fprintf(b, "\tset %s {\n\t\ttype %s\n\t\tflags interval\n\t\tauto-merge\n", name, typ)
	if len(elems) > 0 {
		fmt.Fprintf(b, "\t\telements = { %s }\n", strings.Join(elems, ", "))
	}
	b.WriteString("\t}\n")
}

func mustPrefixes(ss []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// Ruleset renders the nft script. It first deletes a previous tailproxy
// table (the "add table" before "delete table" makes that safe when there
// is none), so applying it is idempotent.
func Ruleset(o Options) (string, error) {
	if o.TProxyPort == 0 {
		return "", fmt.Errorf("capture: tproxy port is required")
	}
	if o.Scope != ScopeSelective && o.Scope != ScopeAll {
		return "", fmt.Errorf("capture: unknown scope %q", o.Scope)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\n", TableName, TableName)
	fmt.Fprintf(&b, "table inet %s {\n", TableName)
	ex4, ex6 := split(o.Exclude)
	rt4, rt6 := split(o.Route)
	def4, def6 := split(mustPrefixes(DefaultExclude))
	set(&b, "exclude4", "ipv4_addr", ex4)
	set(&b, "exclude6", "ipv6_addr", ex6)
	set(&b, "route4", "ipv4_addr", rt4)
	set(&b, "route6", "ipv6_addr", rt6)
	set(&b, "local4", "ipv4_addr", def4)
	set(&b, "local6", "ipv6_addr", def6)

	// Forwarded (LAN) traffic and locally generated traffic rerouted to lo.
	fmt.Fprintf(&b, `
	chain prerouting {
		type filter hook prerouting priority mangle; policy accept;
		meta l4proto != tcp return
		fib daddr type local return
		meta l4proto tcp socket transparent 1 meta mark set %#x accept
		meta mark & %#x == %#x goto divert
		jump decide_pre
	}

	chain decide_pre {
		ip daddr @exclude4 return
		ip6 daddr @exclude6 return
		ip daddr @route4 goto divert
		ip6 daddr @route6 goto divert
%s		return
	}

	chain divert {
		meta nfproto ipv4 meta l4proto tcp tproxy ip to 127.0.0.1:%d meta mark set %#x accept
		meta nfproto ipv6 meta l4proto tcp tproxy ip6 to [::1]:%d meta mark set %#x accept
	}

	chain output {
		type route hook output priority mangle; policy accept;
		meta l4proto != tcp return
		meta mark & %#x == %#x return
		fib daddr type local return
		jump mark_out
	}

	chain mark_out {
		ip daddr @exclude4 return
		ip6 daddr @exclude6 return
		ip daddr @route4 meta mark set %#x return
		ip6 daddr @route6 meta mark set %#x return
%s		return
	}
`,
		RouteMark,
		RouteMark, RouteMark,
		allScope(o.Scope, "goto divert"),
		o.TProxyPort, RouteMark, o.TProxyPort, RouteMark,
		BypassMask, BypassMark,
		RouteMark, RouteMark,
		allScope(o.Scope, fmt.Sprintf("meta mark set %#x return", RouteMark)))

	if o.DNSPort != 0 {
		fmt.Fprintf(&b, `
	chain dns_out {
		type nat hook output priority dstnat; policy accept;
		meta mark & %#x == %#x return
		ip daddr 127.0.0.0/8 return
		ip6 daddr ::1 return
		meta l4proto { tcp, udp } th dport 53 redirect to :%d
	}
`, BypassMask, BypassMark, o.DNSPort)
		if o.HijackLANDNS {
			fmt.Fprintf(&b, `
	chain dns_pre {
		type nat hook prerouting priority dstnat; policy accept;
		meta l4proto { tcp, udp } th dport 53 redirect to :%d
	}
`, o.DNSPort)
		}
	}
	b.WriteString("}\n")
	return b.String(), nil
}

func allScope(scope, action string) string {
	if scope != ScopeAll {
		return ""
	}
	return fmt.Sprintf("\t\tip daddr @local4 return\n\t\tip6 daddr @local6 return\n\t\t%s\n", action)
}

// TeardownScript removes the table (no error if it is absent).
const TeardownScript = "add table inet " + TableName + "\ndelete table inet " + TableName + "\n"
