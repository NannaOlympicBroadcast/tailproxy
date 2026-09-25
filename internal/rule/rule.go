// Package rule implements the first-match routing rule engine (DESIGN §4.3).
package rule

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
)

// Query describes a connection to classify. Domain may be empty when it is
// unknown; IP may be the zero Addr.
type Query struct {
	Domain string
	IP     netip.Addr
	Port   uint16
	// OuterSNI is the outer server name of an ECH ClientHello (the
	// provider's public name). Only outer_sni conditions look at it.
	OuterSNI string
}

// Result is the outcome of matching a Query.
type Result struct {
	// RuleIndex is the 0-based index of the matched rule, or -1 when no rule
	// matched and the implicit `final: direct` applied (DESIGN §4.6).
	RuleIndex int    `json:"rule_index"`
	Target    string `json:"target"`
	Implicit  bool   `json:"implicit"`
	Reason    string `json:"reason"`
	// ByOuterSNI is set when an outer_sni condition decided the match.
	ByOuterSNI bool `json:"-"`
}

type compiled struct {
	exact    map[string]bool
	suffixes []string
	keywords []string
	prefixes []netip.Prefix
	outerSNI []string
	ports    map[uint16]bool
	target   string
	final    bool
}

// Engine matches queries against compiled rules. It is immutable and safe
// for concurrent use.
type Engine struct {
	rules []compiled
}

// Compile builds an Engine from validated config rules.
func Compile(rules []config.Rule) (*Engine, error) {
	e := &Engine{rules: make([]compiled, 0, len(rules))}
	for i, r := range rules {
		c := compiled{target: r.Target(), final: r.Final != ""}
		if len(r.Domain) > 0 {
			c.exact = make(map[string]bool, len(r.Domain))
			for _, d := range r.Domain {
				c.exact[NormalizeDomain(d)] = true
			}
		}
		for _, s := range r.DomainSuffix {
			if s = strings.TrimPrefix(NormalizeDomain(s), "."); s != "" {
				c.suffixes = append(c.suffixes, s)
			}
		}
		for _, k := range r.DomainKeyword {
			if k = NormalizeDomain(k); k != "" {
				c.keywords = append(c.keywords, k)
			}
		}
		for _, p := range r.IPCIDR {
			prefix, err := config.ParsePrefix(p)
			if err != nil {
				return nil, fmt.Errorf("rules[%d]: %w", i, err)
			}
			c.prefixes = append(c.prefixes, prefix)
		}
		for _, s := range r.OuterSNI {
			if s = strings.TrimPrefix(NormalizeDomain(s), "."); s != "" {
				c.outerSNI = append(c.outerSNI, s)
			}
		}
		if len(r.Port) > 0 {
			c.ports = make(map[uint16]bool, len(r.Port))
			for _, p := range r.Port {
				c.ports[p] = true
			}
		}
		e.rules = append(e.rules, c)
	}
	return e, nil
}

// Len returns the number of rules.
func (e *Engine) Len() int { return len(e.rules) }

// NormalizeDomain lower-cases d and strips surrounding space and a trailing dot.
func NormalizeDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

// Match returns the first rule matching q, or the implicit direct target.
func (e *Engine) Match(q Query) Result {
	domain := NormalizeDomain(q.Domain)
	outer := NormalizeDomain(q.OuterSNI)
	ip := q.IP.Unmap()
	for i, r := range e.rules {
		if r.final {
			return Result{RuleIndex: i, Target: r.target, Reason: "final"}
		}
		if r.ports != nil && !r.ports[q.Port] {
			continue
		}
		reason, ok := r.matchDest(domain, ip)
		byOuter := false
		if !ok {
			if reason, ok = r.matchOuterSNI(outer); !ok {
				continue
			}
			byOuter = true
		}
		if r.ports != nil {
			reason = strings.TrimPrefix(reason+fmt.Sprintf(" + port %d", q.Port), " + ")
		}
		return Result{RuleIndex: i, Target: r.target, Reason: reason, ByOuterSNI: byOuter}
	}
	return Result{RuleIndex: -1, Target: config.TargetDirect, Implicit: true, Reason: "no rule matched (implicit final: direct)"}
}

func (r *compiled) matchDest(domain string, ip netip.Addr) (string, bool) {
	hasDest := r.exact != nil || len(r.suffixes) > 0 || len(r.keywords) > 0 || len(r.prefixes) > 0 || len(r.outerSNI) > 0
	if !hasDest {
		return "", true // port-only rule
	}
	if domain != "" {
		if r.exact[domain] {
			return fmt.Sprintf("domain %q", domain), true
		}
		for _, s := range r.suffixes {
			if domain == s || strings.HasSuffix(domain, "."+s) {
				return fmt.Sprintf("domain_suffix %q", s), true
			}
		}
		for _, k := range r.keywords {
			if strings.Contains(domain, k) {
				return fmt.Sprintf("domain_keyword %q", k), true
			}
		}
	}
	if ip.IsValid() {
		for _, p := range r.prefixes {
			if p.Contains(ip) {
				return fmt.Sprintf("ip_cidr %s", p), true
			}
		}
	}
	return "", false
}

// matchOuterSNI matches an ECH outer name against outer_sni by suffix.
func (r *compiled) matchOuterSNI(outer string) (string, bool) {
	if outer == "" {
		return "", false
	}
	for _, s := range r.outerSNI {
		if outer == s || strings.HasSuffix(outer, "."+s) {
			return fmt.Sprintf("outer_sni %q", s), true
		}
	}
	return "", false
}

// DomainMayRoute reports whether some connection to domain could match a
// rule whose target is not direct (DESIGN §4.6, selective mode): the DNS
// module hands out a FakeIP only for such names and answers the rest with
// real addresses, so their traffic never enters tailproxy. Rules are
// scanned in order; a domain rule sending every port direct ends the scan.
// IP-only rules are skipped here — they apply to real addresses, which
// capture covers by prefix (see RoutedPrefixes).
func (e *Engine) DomainMayRoute(domain string) bool {
	domain = NormalizeDomain(domain)
	for _, r := range e.rules {
		if r.final {
			return r.target != config.TargetDirect
		}
		hasDomainCond := r.exact != nil || len(r.suffixes) > 0 || len(r.keywords) > 0
		if !hasDomainCond {
			if len(r.prefixes) == 0 && len(r.outerSNI) == 0 && r.target != config.TargetDirect {
				return true // port-only rule: some port goes elsewhere
			}
			continue
		}
		if _, ok := r.matchDest(domain, netip.Addr{}); !ok {
			continue
		}
		if r.target != config.TargetDirect {
			return true
		}
		if r.ports == nil {
			return false
		}
	}
	return false
}

// RoutedPrefixes returns the ip_cidr prefixes of rules whose target is not
// direct: in selective mode, capture takes these plus the FakeIP pools.
func (e *Engine) RoutedPrefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, r := range e.rules {
		if r.target != config.TargetDirect {
			out = append(out, r.prefixes...)
		}
	}
	return out
}

// RoutedHosts returns the host names written in domain and domain_suffix
// conditions of rules whose target is not direct (a suffix contributes the
// name itself, e.g. "openai.com"). They are resolved periodically so their
// addresses map back to a name (DESIGN §4.8 L4); keywords cannot be.
func (e *Engine) RoutedHosts() []string {
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		if h != "" && !seen[h] && strings.Contains(h, ".") {
			seen[h] = true
			out = append(out, h)
		}
	}
	for _, r := range e.rules {
		if r.final || r.target == config.TargetDirect {
			continue
		}
		for h := range r.exact {
			add(h)
		}
		for _, s := range r.suffixes {
			add(s)
		}
	}
	sort.Strings(out)
	return out
}
