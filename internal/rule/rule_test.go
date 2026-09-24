package rule

import (
	"net/netip"
	"testing"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
)

func mustEngine(t *testing.T, rules []config.Rule) *Engine {
	t.Helper()
	e, err := Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestMatch(t *testing.T) {
	e := mustEngine(t, []config.Rule{
		{DomainKeyword: []string{"openai", "Anthropic"}, Egress: "us"},
		{DomainSuffix: []string{".jp", "nicovideo.jp"}, Egress: "jp"},
		{Domain: []string{"exact.example.com"}, Egress: "jp"},
		{IPCIDR: []string{"203.0.113.0/24", "2001:db8::/32"}, Egress: "jp"},
		{DomainSuffix: []string{"ts.net"}, IPCIDR: []string{"100.64.0.0/10"}, Egress: "tailnet"},
	})
	tests := []struct {
		name   string
		q      Query
		target string
		index  int
	}{
		{"keyword", Query{Domain: "chat.openai.com"}, "us", 0},
		{"keyword case-insensitive and trailing dot", Query{Domain: "API.ANTHROPIC.COM."}, "us", 0},
		{"keyword is substring", Query{Domain: "notopenai.com"}, "us", 0},
		{"suffix with leading dot", Query{Domain: "www.example.jp"}, "jp", 1},
		{"suffix exact apex", Query{Domain: "nicovideo.jp"}, "jp", 1},
		{"suffix respects label boundary", Query{Domain: "exact.example.com.cn"}, "direct", -1},
		{"exact domain", Query{Domain: "exact.example.com"}, "jp", 2},
		{"exact does not match subdomain", Query{Domain: "a.exact.example.com"}, "direct", -1},
		{"ipv4 cidr", Query{IP: netip.MustParseAddr("203.0.113.9")}, "jp", 3},
		{"ipv4-mapped ipv6", Query{IP: netip.MustParseAddr("::ffff:203.0.113.9")}, "jp", 3},
		{"ipv6 cidr", Query{IP: netip.MustParseAddr("2001:db8::1")}, "jp", 3},
		{"domain and ip are OR-ed", Query{Domain: "unknown.example", IP: netip.MustParseAddr("100.100.1.1")}, "tailnet", 4},
		{"first match wins", Query{Domain: "openai.jp"}, "us", 0},
		{"no match is implicit direct", Query{Domain: "example.org", IP: netip.MustParseAddr("192.0.2.1")}, "direct", -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := e.Match(tt.q)
			if r.Target != tt.target || r.RuleIndex != tt.index {
				t.Fatalf("Match(%+v) = %+v, want target %q index %d", tt.q, r, tt.target, tt.index)
			}
			if (tt.index == -1) != r.Implicit {
				t.Fatalf("Implicit = %v, want %v", r.Implicit, tt.index == -1)
			}
		})
	}
}

func TestPortAndFinal(t *testing.T) {
	e := mustEngine(t, []config.Rule{
		{DomainKeyword: []string{"mail"}, Port: []uint16{25, 587}, Egress: "us"},
	})
	if r := e.Match(Query{Domain: "mail.example.com", Port: 587}); r.Target != "us" {
		t.Fatalf("port rule: got %+v", r)
	}
	if r := e.Match(Query{Domain: "mail.example.com", Port: 443}); r.Target != "direct" {
		t.Fatalf("port mismatch should fall through: got %+v", r)
	}

	e = mustEngine(t, []config.Rule{
		{Port: []uint16{853}, Egress: "reject"},
		{Final: "us"},
	})
	if r := e.Match(Query{IP: netip.MustParseAddr("1.1.1.1"), Port: 853}); r.Target != "reject" || r.Reason != "port 853" {
		t.Fatalf("port-only rule: got %+v", r)
	}
	if r := e.Match(Query{Domain: "example.org"}); r.Target != "us" || r.RuleIndex != 1 || r.Implicit {
		t.Fatalf("explicit final: got %+v", r)
	}
}

func TestDomainMayRoute(t *testing.T) {
	e := mustEngine(t, []config.Rule{
		{Domain: []string{"direct.example"}, Egress: config.TargetDirect},
		{DomainSuffix: []string{"openai.com"}, Egress: "us"},
		{DomainKeyword: []string{"google"}, Port: []uint16{443}, Egress: config.TargetDirect},
		{DomainKeyword: []string{"google"}, Egress: "jp"},
		{IPCIDR: []string{"203.0.113.0/24"}, Egress: "us"},
		{DomainSuffix: []string{"corp.example"}, Egress: config.TargetReject},
	})
	for domain, want := range map[string]bool{
		"chat.openai.com":  true,
		"direct.example":   false, // first match: direct on all ports
		"www.google.com":   true,  // 443 direct, other ports to jp
		"x.corp.example":   true,  // reject counts: the proxy must see it
		"unrelated.org":    false, // implicit final direct
		"CHAT.OPENAI.COM.": true,
	} {
		if got := e.DomainMayRoute(domain); got != want {
			t.Errorf("%s: got %v want %v", domain, got, want)
		}
	}
	if p := e.RoutedPrefixes(); len(p) != 1 || p[0].String() != "203.0.113.0/24" {
		t.Errorf("routed prefixes: %v", p)
	}

	portOnly := mustEngine(t, []config.Rule{{Port: []uint16{22}, Egress: "us"}})
	if !portOnly.DomainMayRoute("anything.example") {
		t.Error("port-only rule to an egress must capture every name")
	}
	finalEgress := mustEngine(t, []config.Rule{{Domain: []string{"a.example"}, Egress: config.TargetDirect}, {Final: "us"}})
	if finalEgress.DomainMayRoute("a.example") || !finalEgress.DomainMayRoute("b.example") {
		t.Error("final egress")
	}
}
