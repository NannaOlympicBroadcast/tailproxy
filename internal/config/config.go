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
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

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
	// Hostname of the main node, the one you log in once with. Default
	// "tailproxy". Egress slots are named tailproxy-<egress name>.
	Hostname      string   `yaml:"hostname,omitempty" json:"hostname,omitempty"`
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
	// DoH overrides dns.per_egress_doh for this slot, e.g. a resolver that
	// works well from the exit node's country. The host must be an IP.
	DoH string `yaml:"doh,omitempty" json:"doh,omitempty"`
	// Relay, instead of exit_node, sends this egress's traffic through a
	// `tailproxy relay` at host:port on the tailnet (e.g. 100.98.60.52:1081).
	// Relays need no extra tailnet device on this side.
	Relay string `yaml:"relay,omitempty" json:"relay,omitempty"`
	// RelayTokenEnv names an environment variable holding the relay token;
	// otherwise the token is read from <state-dir>/relay/<name>.token.
	RelayTokenEnv string `yaml:"relay_token_env,omitempty" json:"relay_token_env,omitempty"`
}

// IsRelay reports whether e goes through a tailproxy relay.
func (e Egress) IsRelay() bool { return e.Type == "" && e.Relay != "" }

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

// AntiBypass is DESIGN §4.8. Canary, BlockDoH and BlockDoTDoQ default to
// on when unset (use the *On methods).
type AntiBypass struct {
	Canary       *bool    `yaml:"canary,omitempty" json:"canary,omitempty"`
	BlockDoH     *bool    `yaml:"block_doh,omitempty" json:"block_doh,omitempty"`
	DoHLists     []string `yaml:"doh_lists" json:"doh_lists"`
	DoHAllow     []string `yaml:"doh_allow" json:"doh_allow"`
	BlockDoTDoQ  *bool    `yaml:"block_dot_doq,omitempty" json:"block_dot_doq,omitempty"`
	StripECH     string   `yaml:"strip_ech" json:"strip_ech"`
	LearnRuleIPs *bool    `yaml:"learn_rule_ips,omitempty" json:"learn_rule_ips,omitempty"`
}

func on(b *bool) bool { return b == nil || *b }

// CanaryOn: answer use-application-dns.net with NXDOMAIN (default on).
func (a AntiBypass) CanaryOn() bool { return on(a.Canary) }

// BlockDoHOn: block public DoH endpoints by name and address (default on).
func (a AntiBypass) BlockDoHOn() bool { return on(a.BlockDoH) }

// BlockDoTDoQOn: refuse TCP/UDP 853 (default on).
func (a AntiBypass) BlockDoTDoQOn() bool { return on(a.BlockDoTDoQ) }

// LearnOn: pre-resolve rule host names and learn addresses from DNS
// answers (L4, default on).
func (a AntiBypass) LearnOn() bool { return on(a.LearnRuleIPs) }

// StripECHOn reports whether HTTPS/SVCB answers lose their ech parameter
// (L3): "auto" (default) only in real-IP DNS mode, where the SNI is the
// only way to see the name; "on" / "off" force it.
func (a AntiBypass) StripECHOn(dnsMode string) bool {
	switch a.StripECH {
	case "on", "true":
		return true
	case "off", "false":
		return false
	}
	return dnsMode == "real"
}

// DefaultDoHLists are the public DoH domain / IP lists (DESIGN S38).
var DefaultDoHLists = []string{
	"https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-domains.txt",
	"https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv4.txt",
	"https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv6.txt",
}

// Capture modes.
const (
	CaptureAuto   = "auto"   // currently: SOCKS5 inbound only, no system changes
	CaptureSOCKS  = "socks"  // SOCKS5 inbound only
	CaptureTProxy = "tproxy" // Linux nftables TPROXY + DNS front end
	CaptureTUN    = "tun"    // TUN device + userspace stack (Linux so far)
)

type Capture struct {
	Mode string `yaml:"mode" json:"mode"`
	// Scope for tproxy: "selective" (default: FakeIP pools and routed
	// ip_cidr only; unmatched traffic never enters tailproxy) or "all"
	// (all TCP except excluded and private ranges).
	Scope       string   `yaml:"scope,omitempty" json:"scope,omitempty"`
	ExcludeCIDR []string `yaml:"exclude_cidr" json:"exclude_cidr"`
	SocksListen string   `yaml:"socks_listen" json:"socks_listen"`
	TProxyPort  uint16   `yaml:"tproxy_port" json:"tproxy_port"`
	DNSListen   string   `yaml:"dns_listen" json:"dns_listen"`
	// UDP for tproxy: "block" (default: UDP to FakeIPs is unreachable, so
	// clients fall back to TCP) or "proxy" (UDP is routed like TCP;
	// relay egresses cannot carry it).
	UDP string `yaml:"udp,omitempty" json:"udp,omitempty"`
	// TUN mode: device name and its address; the next address in the
	// subnet answers DNS (default tailproxy0, 172.19.0.1/30 -> 172.19.0.2).
	TUNName    string `yaml:"tun_name,omitempty" json:"tun_name,omitempty"`
	TUNAddress string `yaml:"tun_address,omitempty" json:"tun_address,omitempty"`
	// TUNSystemDNS: "auto" (default) points the system resolver at the
	// stack's DNS address while running and restores it on exit; "off"
	// leaves system DNS alone.
	TUNSystemDNS string `yaml:"tun_system_dns,omitempty" json:"tun_system_dns,omitempty"`
}

// capture.tun_system_dns values.
const (
	SystemDNSAuto = "auto"
	SystemDNSOff  = "off"
)

// UDP modes (capture.udp).
const (
	UDPBlock = "block"
	UDPProxy = "proxy"
)

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
	// OuterSNI matches the outer (public) server name of a TLS ClientHello
	// that uses ECH, by suffix (DESIGN §4.8 L4). Such a name is the
	// provider's, not the site's, so it never matches the domain fields.
	OuterSNI []string `yaml:"outer_sni,omitempty" json:"outer_sni,omitempty"`
	Port     []uint16 `yaml:"port,omitempty" json:"port,omitempty"`
	Egress   string   `yaml:"egress,omitempty" json:"egress,omitempty"`
	Final    string   `yaml:"final,omitempty" json:"final,omitempty"`
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
	if c.Capture.Mode == CaptureTProxy {
		if c.Capture.TProxyPort == 0 {
			c.Capture.TProxyPort = DefaultTProxyPort
		}
		if c.Capture.DNSListen == "" {
			c.Capture.DNSListen = DefaultDNSListen
		}
		if c.Capture.Scope == "" {
			c.Capture.Scope = "selective"
		}
	}
	if c.Capture.Mode == CaptureTUN {
		if c.Capture.TUNName == "" {
			c.Capture.TUNName = DefaultTUNName
		}
		if c.Capture.TUNAddress == "" {
			c.Capture.TUNAddress = DefaultTUNAddress
		}
		if c.Capture.TUNSystemDNS == "" {
			c.Capture.TUNSystemDNS = SystemDNSAuto
		}
		if c.Capture.Scope == "" {
			c.Capture.Scope = "selective"
		}
	}
	if c.DNS.Mode == "" {
		c.DNS.Mode = "fakeip"
	}
}

// Defaults for transparent capture (DESIGN §4.10).
const (
	DefaultTProxyPort = 7893
	DefaultDNSListen  = "127.0.0.1:1053"
	DefaultTUNName    = "tailproxy0"
	DefaultTUNAddress = "172.19.0.1/30"
)

// TUNDNSAddr is the address the TUN stack answers DNS on: the one after
// capture.tun_address.
func (c *Capture) TUNDNSAddr() netip.Addr {
	p, err := netip.ParsePrefix(c.TUNAddress)
	if err != nil {
		return netip.Addr{}
	}
	return p.Addr().Next()
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
		case !validEgressName(e.Name):
			errs = append(errs, fmt.Errorf("egress[%d]: name %q must be 1-40 characters of a-z, 0-9 and '-' (used in the device hostname)", i, e.Name))
		case names[e.Name]:
			errs = append(errs, fmt.Errorf("egress[%d]: duplicate name %q", i, e.Name))
		}
		names[e.Name] = true
		switch e.Type {
		case "":
			switch {
			case e.Relay != "" && e.ExitNode != "":
				errs = append(errs, fmt.Errorf("egress %q: set either exit_node or relay, not both", e.Name))
			case e.Relay != "":
				if err := checkRelayAddr(e.Relay); err != nil {
					errs = append(errs, fmt.Errorf("egress %q: relay: %w", e.Name, err))
				}
				if e.DoH != "" {
					errs = append(errs, fmt.Errorf("egress %q: doh is not used with relay (the relay resolves names itself)", e.Name))
				}
			case e.ExitNode == "":
				errs = append(errs, fmt.Errorf("egress %q: exit_node or relay is required", e.Name))
			}
			if e.RelayTokenEnv != "" && e.Relay == "" {
				errs = append(errs, fmt.Errorf("egress %q: relay_token_env needs relay", e.Name))
			}
			slots[e.Name] = true
		case "fallback", "latency":
			if e.DoH != "" {
				errs = append(errs, fmt.Errorf("egress %q: doh is set per slot, not on a group", e.Name))
			}
			if e.ExitNode != "" || e.Relay != "" {
				errs = append(errs, fmt.Errorf("egress %q: a group cannot set exit_node or relay", e.Name))
			}
			if len(e.Members) == 0 {
				errs = append(errs, fmt.Errorf("egress %q: group needs members", e.Name))
			}
			if hc := e.HealthCheck; hc != nil {
				if d, err := time.ParseDuration(hc.Interval); err != nil || d < 5*time.Second {
					errs = append(errs, fmt.Errorf("egress %q: health_check.interval %q must be a duration of at least 5s", e.Name, hc.Interval))
				}
				if hc.URL == "" {
					errs = append(errs, fmt.Errorf("egress %q: health_check.url is required", e.Name))
				}
			}
		default:
			errs = append(errs, fmt.Errorf("egress %q: unknown type %q (want fallback or latency)", e.Name, e.Type))
		}
	}
	for _, e := range c.Egress {
		for _, m := range e.Members {
			if !slots[m] {
				errs = append(errs, fmt.Errorf("egress %q: member %q is not a defined exit (slot or relay)", e.Name, m))
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
		hasCond := len(r.Domain)+len(r.DomainSuffix)+len(r.DomainKeyword)+len(r.IPCIDR)+len(r.OuterSNI)+len(r.Port) > 0
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
		for _, f := range []struct {
			name string
			vals []string
		}{{"domain", r.Domain}, {"domain_suffix", r.DomainSuffix}, {"domain_keyword", r.DomainKeyword}, {"outer_sni", r.OuterSNI}} {
			for _, v := range f.vals {
				if v = strings.TrimSpace(v); v == "" || v == "." {
					errs = append(errs, fmt.Errorf("rules[%d]: empty value in %s", i, f.name))
				}
			}
		}
		for _, p := range r.IPCIDR {
			if _, err := ParsePrefix(p); err != nil {
				errs = append(errs, fmt.Errorf("rules[%d]: %w", i, err))
			}
		}
	}

	for _, e := range c.Egress {
		if e.DoH != "" {
			if err := checkDoHURL(e.DoH); err != nil {
				errs = append(errs, fmt.Errorf("egress %q: doh: %w", e.Name, err))
			}
		}
	}
	if c.DNS.PerEgressDoH != "" {
		if err := checkDoHURL(c.DNS.PerEgressDoH); err != nil {
			errs = append(errs, fmt.Errorf("dns.per_egress_doh: %w", err))
		}
	}
	if _, _, err := net.SplitHostPort(c.Panel.Listen); err != nil {
		errs = append(errs, fmt.Errorf("panel.listen: %w", err))
	}
	errs = append(errs, c.validateCapture(names)...)
	return errors.Join(errs...)
}

func (c *Config) validateCapture(egressNames map[string]bool) []error {
	var errs []error
	switch c.Capture.Mode {
	case "", CaptureAuto, CaptureSOCKS, CaptureTProxy:
	case CaptureTUN:
		if c.Capture.TUNAddress != "" {
			p, err := netip.ParsePrefix(c.Capture.TUNAddress)
			switch {
			case err != nil:
				errs = append(errs, fmt.Errorf("capture.tun_address: %w", err))
			case !p.Addr().Is4() || p.Bits() > 30:
				errs = append(errs, fmt.Errorf("capture.tun_address %s: want an IPv4 prefix of /30 or larger (the next address answers DNS)", c.Capture.TUNAddress))
			}
		}
		switch c.Capture.TUNSystemDNS {
		case "", SystemDNSAuto, SystemDNSOff:
		default:
			errs = append(errs, fmt.Errorf("capture.tun_system_dns %q: want auto or off", c.Capture.TUNSystemDNS))
		}
	default:
		errs = append(errs, fmt.Errorf("capture.mode %q: want auto, socks, tproxy or tun", c.Capture.Mode))
	}
	switch c.Capture.Scope {
	case "", "selective", "all":
	default:
		errs = append(errs, fmt.Errorf("capture.scope %q: want selective or all", c.Capture.Scope))
	}
	switch c.Capture.UDP {
	case "", UDPBlock, UDPProxy:
	default:
		errs = append(errs, fmt.Errorf("capture.udp %q: want block or proxy", c.Capture.UDP))
	}
	for _, p := range c.Capture.ExcludeCIDR {
		if _, err := ParsePrefix(p); err != nil {
			errs = append(errs, fmt.Errorf("capture.exclude_cidr: %w", err))
		}
	}
	if c.Capture.DNSListen != "" {
		if _, _, err := net.SplitHostPort(c.Capture.DNSListen); err != nil {
			errs = append(errs, fmt.Errorf("capture.dns_listen: %w", err))
		}
	}
	switch c.DNS.Mode {
	case "", "fakeip", "real":
	default:
		errs = append(errs, fmt.Errorf("dns.mode %q: want fakeip or real", c.DNS.Mode))
	}
	for name, s := range map[string]string{"dns.fakeip.inet4": c.DNS.FakeIP.Inet4, "dns.fakeip.inet6": c.DNS.FakeIP.Inet6} {
		if s == "" {
			continue
		}
		p, err := ParsePrefix(s)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		case (name == "dns.fakeip.inet4") != p.Addr().Is4():
			errs = append(errs, fmt.Errorf("%s: %s is the wrong address family", name, s))
		}
	}
	switch c.DNS.AntiBypass.StripECH {
	case "", "auto", "on", "off", "true", "false":
	default:
		errs = append(errs, fmt.Errorf("dns.anti_bypass.strip_ech %q: want auto, on or off", c.DNS.AntiBypass.StripECH))
	}
	switch u := c.DNS.UnknownDomain; {
	case u == "", u == "ip_rules_only", u == "reject":
	case strings.HasPrefix(u, "egress:"):
		if t := strings.TrimPrefix(u, "egress:"); !egressNames[t] && t != TargetTailnet {
			errs = append(errs, fmt.Errorf("dns.unknown_domain: %q is not a defined egress", t))
		}
	default:
		errs = append(errs, fmt.Errorf("dns.unknown_domain %q: want ip_rules_only, reject or egress:<name>", u))
	}
	return errs
}

// validEgressName: lower-case letters, digits and '-', not starting with '-'.
// The name becomes part of a directory and of the hostname tailproxy-<name>.
func validEgressName(n string) bool {
	if len(n) == 0 || len(n) > 40 || n[0] == '-' {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// ValidEgressName reports whether n is usable as an egress name.
func ValidEgressName(n string) bool { return validEgressName(n) }

// checkRelayAddr requires host:port with a numeric port. The host may be a
// Tailscale IP or MagicDNS name, or loopback for a relay on the same machine.
func checkRelayAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q: want host:port, e.g. 100.98.60.52:1081", addr)
	}
	if host == "" {
		return fmt.Errorf("%q: missing host", addr)
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("%q: invalid port", addr)
	}
	return nil
}

// checkDoHURL requires https:// with an IP-literal host, so resolving a name
// through an exit node never needs a lookup outside that exit node.
func checkDoHURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%q must use https://", raw)
	}
	if _, err := netip.ParseAddr(u.Hostname()); err != nil {
		return fmt.Errorf("%q: the host must be an IP address (e.g. https://1.1.1.1/dns-query)", raw)
	}
	return nil
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
