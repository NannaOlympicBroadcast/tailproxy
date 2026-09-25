package capture

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRuleset(t *testing.T) {
	o := Options{Scope: ScopeSelective, TProxyPort: 7893, DNSPort: 1053,
		Route:   []netip.Prefix{netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("fc00::/18"), netip.MustParsePrefix("203.0.113.9/24")},
		Exclude: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}}
	s, err := Ruleset(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"add table inet tailproxy\ndelete table inet tailproxy\n", // idempotent
		"elements = { 198.18.0.0/15, 203.0.113.0/24 }",            // masked, sorted
		"elements = { fc00::/18 }",
		"tproxy ip to 127.0.0.1:7893 meta mark set 0x2000",
		"tproxy ip6 to [::1]:7893",
		"meta mark & 0xff0000 == 0x80000 return", // tsnet + direct dials not recaptured
		"ip daddr @exclude4 return",
		"th dport 53 redirect to :1053",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "@local4") || strings.Contains(s, "dns_pre") {
		t.Errorf("selective scope / loopback DNS must not capture everything or hijack LAN DNS:\n%s", s)
	}
	o.Scope, o.HijackLANDNS = ScopeAll, true
	s, _ = Ruleset(o)
	for _, want := range []string{"ip daddr @local4 return", "goto divert\n", "chain dns_pre"} {
		if !strings.Contains(s, want) {
			t.Errorf("all scope lacks %q", want)
		}
	}
	if _, err := Ruleset(Options{Scope: "x", TProxyPort: 1}); err == nil {
		t.Error("bad scope accepted")
	}
	if _, err := Ruleset(Options{Scope: ScopeAll}); err == nil {
		t.Error("missing port accepted")
	}
}

func TestRulesetUDP(t *testing.T) {
	o := Options{Scope: ScopeSelective, TProxyPort: 7893, DNSPort: 1053,
		Route: []netip.Prefix{netip.MustParsePrefix("198.18.0.0/15")}}
	s, _ := Ruleset(o)
	if strings.Contains(s, "{ tcp, udp } tproxy") || strings.Contains(s, "!= { tcp, udp } return") {
		t.Errorf("UDP diverted without Options.UDP:\n%s", s)
	}
	o.UDP = true
	s, _ = Ruleset(o)
	for _, want := range []string{
		"meta l4proto != { tcp, udp } return\n\t\tudp dport 53 return", // prerouting and output: DNS stays DNS
		"meta nfproto ipv4 meta l4proto { tcp, udp } tproxy ip to 127.0.0.1:7893",
		"meta nfproto ipv6 meta l4proto { tcp, udp } tproxy ip6 to [::1]:7893",
		"meta l4proto tcp socket transparent 1", // UDP flows use connected reply sockets instead
	} {
		if !strings.Contains(s, want) {
			t.Errorf("UDP ruleset lacks %q:\n%s", want, s)
		}
	}
	if n := strings.Count(s, "udp dport 53 return"); n != 2 {
		t.Errorf("udp dport 53 return appears %d times, want 2 (prerouting, output)", n)
	}
}

// Forwarded DoH / DoT / DoQ must not be diverted: TPROXY would deliver it
// locally and proxy it, bypassing the forward block chain.
func TestRulesetBlockedNotDiverted(t *testing.T) {
	o := Options{Scope: ScopeAll, TProxyPort: 7893, BlockDoTDoQ: true,
		DoHAddrs: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")}}
	s, _ := Ruleset(o)
	pre := s[strings.Index(s, "chain prerouting"):strings.Index(s, "chain decide_pre")]
	for _, want := range []string{"ip daddr @doh4 th dport 443 return", "ip6 daddr @doh6 th dport 443 return", "th dport 853 return"} {
		if !strings.Contains(pre, want) {
			t.Errorf("prerouting lacks %q:\n%s", want, pre)
		}
	}
	// The sets are declared before the chains that use them.
	if strings.Index(s, "set doh4") > strings.Index(s, "chain prerouting") {
		t.Error("set doh4 declared after its first use")
	}
	o.DoHAddrs, o.BlockDoTDoQ = nil, false
	s, _ = Ruleset(o)
	if strings.Contains(s, "@doh4 th dport") || strings.Contains(s, "th dport 853") {
		t.Errorf("skips present without blocking:\n%s", s)
	}
}
