package config

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestReplaceRulesKeepsRestOfFile(t *testing.T) {
	orig, err := os.ReadFile("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rules := []Rule{
		{DomainKeyword: []string{"openai"}, Egress: "jp"},
		{IPCIDR: []string{"fd7a:115c:a1e0::/48"}, Port: []uint16{443}, Egress: "tailnet"},
		{Final: "direct"},
	}
	out, err := ReplaceRules(orig, rules)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(out)
	if err != nil {
		t.Fatalf("rewritten config does not parse: %v\n%s", err, out)
	}
	if !reflect.DeepEqual(c.Rules, rules) {
		t.Fatalf("rules = %+v, want %+v", c.Rules, rules)
	}
	// Everything before the rules section is byte-identical.
	head := string(orig[:strings.Index(string(orig), "\nrules:")])
	if !strings.HasPrefix(string(out), head) {
		t.Fatal("content before rules: changed")
	}
	if !strings.Contains(string(out), "auth_key_env: TS_AUTHKEY          # 不把密钥写进文件") {
		t.Fatal("comment alignment outside rules was not preserved")
	}
}

func TestReplaceRulesMiddleSectionAndComments(t *testing.T) {
	in := `# top comment
egress:
  - {name: us, exit_node: a}
rules:
  - {domain: [old.example], egress: us}   # old comment
  - {final: direct}

# comment about panel
panel:
  listen: 127.0.0.1:7708   # keep me
`
	out, err := ReplaceRules([]byte(in), []Rule{{DomainSuffix: []string{"new.example"}, Egress: "us"}})
	if err != nil {
		t.Fatal(err)
	}
	want := `# top comment
egress:
  - {name: us, exit_node: a}
rules:
  - {domain_suffix: [new.example], egress: us}

# comment about panel
panel:
  listen: 127.0.0.1:7708   # keep me
`
	if string(out) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
}

func TestReplaceRulesAppendsAndEmpty(t *testing.T) {
	out, err := ReplaceRules([]byte("panel: {listen: 127.0.0.1:7708}"), []Rule{{Final: "reject"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "panel: {listen: 127.0.0.1:7708}\nrules:\n  - {final: reject}\n" {
		t.Fatalf("got %q", out)
	}
	out, err = ReplaceRules(nil, nil)
	if err != nil || string(out) != "rules: []\n" {
		t.Fatalf("got %q, %v", out, err)
	}
	out, err = ReplaceRules([]byte("rules: [{final: direct}]\n"), nil)
	if err != nil || string(out) != "rules: []\n" {
		t.Fatalf("got %q, %v", out, err)
	}
}

func TestReplaceRulesMultilineFlow(t *testing.T) {
	in := "rules: [\n  {final: direct},\n]\npanel: {listen: 127.0.0.1:7708}\n"
	out, err := ReplaceRules([]byte(in), []Rule{{Final: "reject"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "rules:\n  - {final: reject}\npanel: {listen: 127.0.0.1:7708}\n" {
		t.Fatalf("got %q", out)
	}
}

func TestReplaceEgress(t *testing.T) {
	in := `tailnet: {control_url: https://controlplane.tailscale.com}   # keep
egress:
  - {name: us, exit_node: a}   # old
rules:
  - {domain: [a.com], egress: us}
`
	eg := []Egress{
		{Name: "us", ExitNode: "ser647557941975"},
		{Name: "cn", ExitNode: "VM-0-5-opencloudos", DoH: "https://223.5.5.5/dns-query"},
		{Name: "auto", Type: "fallback", Members: []string{"us", "cn"}, HealthCheck: &HealthCheck{URL: "https://www.gstatic.com/generate_204", Interval: "60s"}},
	}
	out, err := ReplaceEgress([]byte(in), eg)
	if err != nil {
		t.Fatal(err)
	}
	want := `tailnet: {control_url: https://controlplane.tailscale.com}   # keep
egress:
  - {name: us, exit_node: ser647557941975}
  - {name: cn, exit_node: VM-0-5-opencloudos, doh: 'https://223.5.5.5/dns-query'}
  - {name: auto, type: fallback, members: [us, cn], health_check: {url: 'https://www.gstatic.com/generate_204', interval: 60s}}
rules:
  - {domain: [a.com], egress: us}
`
	if string(out) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
	c, err := Parse(out)
	if err != nil || !reflect.DeepEqual(c.Egress, eg) {
		t.Fatalf("round trip: %v\n%+v", err, c.Egress)
	}
}

func TestEgressNameValidation(t *testing.T) {
	for _, n := range []string{"us", "cn-2", "a1"} {
		if !ValidEgressName(n) {
			t.Errorf("%q should be valid", n)
		}
	}
	for _, n := range []string{"", "US", "-a", "a_b", "中国", "a b", strings.Repeat("a", 41)} {
		if ValidEgressName(n) {
			t.Errorf("%q should be invalid", n)
		}
	}
}
