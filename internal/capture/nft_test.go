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
