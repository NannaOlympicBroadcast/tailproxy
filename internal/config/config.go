// Package config loads and validates the tailproxy YAML configuration
// described in docs/DESIGN.md §5.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultPanelListen is the default address of the web panel (DESIGN §4.10).
const DefaultPanelListen = "127.0.0.1:7708"

// Reserved rule targets that are not egress slots.
const (
	TargetDirect  = "direct"
	TargetTailnet = "tailnet"
	TargetReject  = "reject"
)

// IsReservedTarget reports whether name is a built-in rule target.
func IsReservedTarget(name string) bool {
	switch name {
	case TargetDirect, TargetTailnet, TargetReject:
		return true
	}
	return false
}

type Config struct {
	Tailnet        Tailnet  `yaml:"tailnet" json:"tailnet"`
	Egress         []Egress `yaml:"egress" json:"egress"`
	DNS            DNS      `yaml:"dns" json:"dns"`
	Capture        Capture  `yaml:"capture" json:"capture"`
	Panel          Panel    `yaml:"panel" json:"panel"`
	WireguardPorts string   `yaml:"wireguard_ports" json:"wireguard_ports"`
	Rules          []Rule   `yaml:"rules" json:"rules"`
}

type Tailnet struct {
	ControlURL    string   `yaml:"control_url" json:"control_url"`
	AuthKeyEnv    string   `yaml:"auth_key_env" json:"auth_key_env"`
	AdvertiseTags []string `yaml:"advertise_tags" json:"advertise_tags"`
	StateDir      string   `yaml:"state_dir" json:"state_dir"`
}

// Egress is either a slot (one tsnet node pinned to one exit node) or a
// group of slots (Type "fallback" or "latency").
type Egress struct {
	Name        string       `yaml:"name" json:"name"`
	ExitNode    string       `yaml:"exit_node,omitempty" json:"exit_node,omitempty"`
	Type        string       `yaml:"type,omitempty" json:"type,omitempty"`
	Members     []string     `yaml:"members,omitempty" json:"members,omitempty"`
	HealthCheck *HealthCheck `yaml:"health_check,omitempty" json:"health_check,omitempty"`
}

// IsGroup reports whether e is a group of other egress slots.
func (e Egress) IsGroup() bool { return e.Type != "" }

type HealthCheck struct {
	URL      string `yaml:"url" json:"url"`
	Interval string `yaml:"interval" json:"interval"`
}

type DNS struct {
	Mode           string     `yaml:"mode" json:"mode"`
	FakeIP         FakeIP     `yaml:"fakeip" json:"fakeip"`
	PerEgressDoH   string     `yaml:"per_egress_doh" json:"per_egress_doh"`
	DirectUpstream string     `yaml:"direct_upstream" json:"direct_upstream"`
	AntiBypass     AntiBypass `yaml:"anti_bypass" json:"anti_bypass"`
	UnknownDomain  string     `yaml:"unknown_domain" json:"unknown_domain"`
}

type FakeIP struct {
	Inet4 string `yaml:"inet4" json:"inet4"`
	Inet6 string `yaml:"inet6" json:"inet6"`
}

type AntiBypass struct {
	Canary       bool     `yaml:"canary" json:"canary"`
	BlockDoH     bool     `yaml:"block_doh" json:"block_doh"`
	DoHLists     []string `yaml:"doh_lists" json:"doh_lists"`
	DoHAllow     []string `yaml:"doh_allow" json:"doh_allow"`
	BlockDoTDoQ  bool     `yaml:"block_dot_doq" json:"block_dot_doq"`
	StripECH     string   `yaml:"strip_ech" json:"strip_ech"`
	LearnRuleIPs bool     `yaml:"learn_rule_ips" json:"learn_rule_ips"`
}

type Capture struct {
	Mode        string   `yaml:"mode" json:"mode"`
	ExcludeCIDR []string `yaml:"exclude_cidr" json:"exclude_cidr"`
	SocksListen string   `yaml:"socks_listen" json:"socks_listen"`
	TProxyPort  uint16   `yaml:"tproxy_port" json:"tproxy_port"`
	DNSListen   string   `yaml:"dns_listen" json:"dns_listen"`
}

type Panel struct {
	Listen       string `yaml:"listen" json:"listen"`
	Tailnet      bool   `yaml:"tailnet" json:"tailnet"`
	AuthTokenEnv string `yaml:"auth_token_env" json:"auth_token_env"`
}

// Rule is one routing rule. Exactly one of Egress or Final is set.
// Domain conditions and ip_cidr are OR-ed; port, if present, is AND-ed.
type Rule struct {
	Domain        []string `yaml:"domain,omitempty" json:"domain,omitempty"`
	DomainSuffix  []string `yaml:"domain_suffix,omitempty" json:"domain_suffix,omitempty"`
	DomainKeyword []string `yaml:"domain_keyword,omitempty" json:"domain_keyword,omitempty"`
	IPCIDR        []string `yaml:"ip_cidr,omitempty" json:"ip_cidr,omitempty"`
	Port          []uint16 `yaml:"port,omitempty" json:"port,omitempty"`
	Egress        string   `yaml:"egress,omitempty" json:"egress,omitempty"`
	Final         string   `yaml:"final,omitempty" json:"final,omitempty"`
}

// Target returns the rule's destination (egress name or reserved target).
func (r Rule) Target() string {
	if r.Final != "" {
		return r.Final
	}
	return r.Egress
}

// Load reads, parses and validates the configuration file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse decodes YAML (rejecting unknown fields), applies defaults and validates.
func Parse(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Panel.Listen == "" {
		c.Panel.Listen = DefaultPanelListen
	}
}

// Validate checks cross-references between egress entries and rules.
func (c *Config) Validate() error {
	var errs []error
	slots := map[string]bool{}
	names := map[string]bool{}
	for i, e := range c.Egress {
		switch {
		case e.Name == "":
			errs = append(errs, fmt.Errorf("egress[%d]: name is required", i))
			continue
		case IsReservedTarget(e.Name):
			errs = append(errs, fmt.Errorf("egress[%d]: name %q is reserved", i, e.Name))
		case names[e.Name]:
			errs = append(errs, fmt.Errorf("egress[%d]: duplicate name %q", i, e.Name))
		}
		names[e.Name] = true
		switch e.Type {
		case "":
			if e.ExitNode == "" {
				errs = append(errs, fmt.Errorf("egress %q: exit_node is required", e.Name))
			}
			slots[e.Name] = true
		case "fallback", "latency":
			if e.ExitNode != "" {
				errs = append(errs, fmt.Errorf("egress %q: a group cannot set exit_node", e.Name))
			}
			if len(e.Members) == 0 {
				errs = append(errs, fmt.Errorf("egress %q: group needs members", e.Name))
			}
		default:
			errs = append(errs, fmt.Errorf("egress %q: unknown type %q (want fallback or latency)", e.Name, e.Type))
		}
	}
	for _, e := range c.Egress {
		for _, m := range e.Members {
			if !slots[m] {
				errs = append(errs, fmt.Errorf("egress %q: member %q is not a defined slot", e.Name, m))
			}
		}
	}

	for i, r := range c.Rules {
		switch {
		case r.Egress != "" && r.Final != "":
			errs = append(errs, fmt.Errorf("rules[%d]: set either egress or final, not both", i))
			continue
		case r.Egress == "" && r.Final == "":
			errs = append(errs, fmt.Errorf("rules[%d]: missing egress or final", i))
			continue
		}
		if t := r.Target(); !IsReservedTarget(t) && !names[t] {
			errs = append(errs, fmt.Errorf("rules[%d]: unknown target %q", i, t))
		}
		hasCond := len(r.Domain)+len(r.DomainSuffix)+len(r.DomainKeyword)+len(r.IPCIDR)+len(r.Port) > 0
		if r.Final != "" {
			if hasCond {
				errs = append(errs, fmt.Errorf("rules[%d]: final rule cannot have match conditions", i))
			}
			if i != len(c.Rules)-1 {
				errs = append(errs, fmt.Errorf("rules[%d]: final must be the last rule", i))
			}
		} else if !hasCond {
			errs = append(errs, fmt.Errorf("rules[%d]: no match conditions", i))
		}
		for _, p := range r.IPCIDR {
			if _, err := ParsePrefix(p); err != nil {
				errs = append(errs, fmt.Errorf("rules[%d]: %w", i, err))
			}
		}
	}

	if _, _, err := net.SplitHostPort(c.Panel.Listen); err != nil {
		errs = append(errs, fmt.Errorf("panel.listen: %w", err))
	}
	return errors.Join(errs...)
}

// ParsePrefix accepts a CIDR prefix or a bare IP address (treated as /32 or /128).
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid ip_cidr %q: %w", s, err)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid ip_cidr %q: %w", s, err)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}
