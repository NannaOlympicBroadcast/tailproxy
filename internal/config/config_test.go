package config

import (
	"os"
	"strings"
	"testing"
)

func TestExampleConfigParses(t *testing.T) {
	c, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.Panel.Listen != "127.0.0.1:7708" {
		t.Fatalf("panel.listen = %q", c.Panel.Listen)
	}
	if len(c.Egress) != 4 || len(c.Rules) != 5 {
		t.Fatalf("got %d egress, %d rules", len(c.Egress), len(c.Rules))
	}
	if !c.Egress[2].IsRelay() || c.Egress[0].IsRelay() || c.Egress[3].IsRelay() {
		t.Fatalf("relay entries: %+v", c.Egress)
	}
}

func TestDefaults(t *testing.T) {
	c, err := Parse([]byte("rules: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Panel.Listen != DefaultPanelListen {
		t.Fatalf("default listen = %q", c.Panel.Listen)
	}
	if _, err := Parse(nil); err != nil {
		t.Fatalf("empty config: %v", err)
	}
}

func TestValidateErrors(t *testing.T) {
	tests := []struct {
		name, yaml, want string
	}{
		{"unknown field", "egres: []", "field egres not found"},
		{"reserved name", "egress: [{name: direct, exit_node: x}]", "reserved"},
		{"duplicate", "egress: [{name: a, exit_node: x}, {name: a, exit_node: y}]", "duplicate"},
		{"missing exit node", "egress: [{name: a}]", "exit_node or relay is required"},
		{"bad group member", "egress: [{name: g, type: fallback, members: [nope]}]", "not a defined exit"},
		{"unknown type", "egress: [{name: g, type: random, members: [a]}]", "unknown type"},
		{"unknown target", "rules: [{domain: [a.com], egress: nope}]", "unknown target"},
		{"both targets", "rules: [{domain: [a.com], egress: direct, final: direct}]", "not both"},
		{"no conditions", "rules: [{egress: direct}]", "no match conditions"},
		{"final not last", "rules: [{final: direct}, {domain: [a.com], egress: direct}]", "must be the last"},
		{"final with conditions", "rules: [{domain: [a.com], final: direct}]", "cannot have match conditions"},
		{"bad cidr", "rules: [{ip_cidr: [300.0.0.0/8], egress: direct}]", "invalid ip_cidr"},
		{"bad listen", "panel: {listen: '7708'}", "panel.listen"},
		{"doh hostname", "egress: [{name: cn, exit_node: x, doh: 'https://dns.alidns.com/dns-query'}]", "must be an IP"},
		{"doh http", "dns: {per_egress_doh: 'http://1.1.1.1/dns-query'}", "https://"},
		{"health interval", "egress: [{name: a, exit_node: x}, {name: g, type: latency, members: [a], health_check: {url: 'https://x', interval: 1s}}]", "at least 5s"},
		{"relay and exit node", "egress: [{name: us, exit_node: x, relay: '100.98.60.52:1081'}]", "not both"},
		{"relay bad addr", "egress: [{name: us, relay: '100.98.60.52'}]", "host:port"},
		{"relay with doh", "egress: [{name: us, relay: 'a:1081', doh: 'https://1.1.1.1/dns-query'}]", "not used with relay"},
		{"neither", "egress: [{name: us}]", "exit_node or relay is required"},
		{"bad egress name", "egress: [{name: US, exit_node: x}]", "a-z"},
		{"doh on group", "egress: [{name: a, exit_node: x}, {name: g, type: fallback, members: [a], doh: 'https://1.1.1.1/dns-query'}]", "per slot"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse(%q) error = %v, want containing %q", tt.yaml, err, tt.want)
			}
		})
	}
}

func TestParsePrefixBareIP(t *testing.T) {
	p, err := ParsePrefix("::ffff:10.0.0.1")
	if err != nil || p.String() != "10.0.0.1/32" {
		t.Fatalf("got %v, %v", p, err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("does-not-exist.yaml"); !os.IsNotExist(err) {
		t.Fatalf("got %v", err)
	}
}

func TestCaptureConfig(t *testing.T) {
	c, err := Parse([]byte("capture: {mode: tproxy}\negress: [{name: us, exit_node: a}]\nrules: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Capture.TProxyPort != DefaultTProxyPort || c.Capture.DNSListen != DefaultDNSListen || c.Capture.Scope != "selective" || c.DNS.Mode != "fakeip" {
		t.Fatalf("defaults: %+v %+v", c.Capture, c.DNS.Mode)
	}
	for _, bad := range []string{
		"capture: {mode: tun}\nrules: []\n",
		"capture: {mode: magic}\nrules: []\n",
		"capture: {mode: tproxy, scope: some}\nrules: []\n",
		"capture: {exclude_cidr: [not-a-cidr]}\nrules: []\n",
		"dns: {mode: dnssec}\nrules: []\n",
		"dns: {fakeip: {inet4: 'fc00::/18'}}\nrules: []\n",
		"dns: {unknown_domain: 'egress:nope'}\nrules: []\n",
		"dns: {unknown_domain: maybe}\nrules: []\n",
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("accepted: %s", bad)
		}
	}
	if _, err := Parse([]byte("egress: [{name: us, exit_node: a}]\ndns: {unknown_domain: 'egress:us'}\nrules: []\n")); err != nil {
		t.Errorf("egress:us rejected: %v", err)
	}
}
