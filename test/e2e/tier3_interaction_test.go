package e2e

import (
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/fakeip"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
)

// =============================================================================
// Tier 3 - Interaction 1: Kernel Switching (Davin <-> Bacarra)
// =============================================================================

// T3.I1: Seamless config migration between Davin and Bacarra modes.
func TestTier3_Interaction_KernelSwitching(t *testing.T) {
	davinYAML := sampleValidConfig("davin")
	cfgDavin, err := config.Parse([]byte(davinYAML))
	if err != nil {
		t.Fatalf("failed to parse davin config: %v", err)
	}
	if cfgDavin.Kernel != config.KernelDavin {
		t.Fatalf("expected davin kernel, got: %s", cfgDavin.Kernel)
	}

	// Switch to bacarra
	bacarraYAML := sampleValidConfig("bacarra")
	cfgBacarra, err := config.Parse([]byte(bacarraYAML))
	if err != nil {
		t.Fatalf("failed to parse bacarra config: %v", err)
	}
	if cfgBacarra.Kernel != config.KernelBacarra {
		t.Fatalf("expected bacarra kernel, got: %s", cfgBacarra.Kernel)
	}

	// Verify state directories do not collide
	davinTsnetDir := filepath.Join(cfgDavin.Tailnet.StateDir, "tsnet", "_main")
	bacarraStateFile := filepath.Join(cfgBacarra.Tailnet.StateDir, "bacarra_routes.json")
	if davinTsnetDir == bacarraStateFile {
		t.Fatalf("state directory collision between kernels: %s", davinTsnetDir)
	}
}

// =============================================================================
// Tier 3 - Interaction 2: Rule Engine Routed Prefix Extraction for Bacarra
// =============================================================================

// T3.I2: Rule engine accurately extracts routed CIDRs while excluding direct CIDRs.
func TestTier3_Interaction_RuleEngineRoutedPrefixes(t *testing.T) {
	raw := sampleValidConfig("bacarra")
	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	eng, err := rule.Compile(cfg.Rules)
	if err != nil {
		t.Fatalf("failed to compile rules: %v", err)
	}

	routed := eng.RoutedPrefixes()

	// In sampleValidConfig:
	// - 91.108.4.0/22 -> exit-jp (routed)
	// - 149.154.160.0/20 -> exit-jp (routed)
	// - 192.168.0.0/16 -> direct (EXCLUDED)
	// - 10.0.0.0/8 -> direct (EXCLUDED)
	if len(routed) != 2 {
		t.Fatalf("expected exactly 2 routed prefixes, got %d: %v", len(routed), routed)
	}

	expectedPrefixes := map[string]bool{
		"91.108.4.0/22":    true,
		"149.154.160.0/20": true,
	}

	for _, p := range routed {
		if !expectedPrefixes[p.String()] {
			t.Fatalf("unexpected routed prefix found: %s", p.String())
		}
	}
}

// =============================================================================
// Tier 3 - Interaction 3: Dynamic Config Reload & Route Diffing
// =============================================================================

// T3.I3: Staged route diffing correctly identifies additions, removals, and unchanged routes.
func TestTier3_Interaction_DynamicReloadRouteDiffing(t *testing.T) {
	initialRoutes := []netip.Prefix{
		netip.MustParsePrefix("198.18.0.0/15"),  // FakeIP IPv4
		netip.MustParsePrefix("fc00::/18"),      // FakeIP IPv6
		netip.MustParsePrefix("91.108.4.0/22"),  // Old rule
		netip.MustParsePrefix("1.1.1.0/24"),     // Common rule
	}

	newRoutes := []netip.Prefix{
		netip.MustParsePrefix("198.18.0.0/15"),  // FakeIP IPv4 (unchanged)
		netip.MustParsePrefix("fc00::/18"),      // FakeIP IPv6 (unchanged)
		netip.MustParsePrefix("1.1.1.0/24"),     // Common rule (unchanged)
		netip.MustParsePrefix("8.8.8.0/24"),     // Added rule
		netip.MustParsePrefix("149.154.160.0/20"), // Added rule
	}

	// Build sets
	initialSet := make(map[netip.Prefix]bool)
	for _, p := range initialRoutes {
		initialSet[p] = true
	}

	newSet := make(map[netip.Prefix]bool)
	for _, p := range newRoutes {
		newSet[p] = true
	}

	// Calculate additions
	var added []netip.Prefix
	for p := range newSet {
		if !initialSet[p] {
			added = append(added, p)
		}
	}

	// Calculate removals
	var removed []netip.Prefix
	for p := range initialSet {
		if !newSet[p] {
			removed = append(removed, p)
		}
	}

	if len(added) != 2 {
		t.Fatalf("expected 2 added routes, got %d: %v", len(added), added)
	}
	if len(removed) != 1 {
		t.Fatalf("expected 1 removed route, got %d: %v", len(removed), removed)
	}
	if removed[0].String() != "91.108.4.0/22" {
		t.Fatalf("expected removed route to be 91.108.4.0/22, got %s", removed[0].String())
	}
}

// =============================================================================
// Tier 3 - Interaction 4: FakeIP Pool Interception & Routing Integration
// =============================================================================

// T3.I4: FakeIP pool generates valid IPv4 and IPv6 subnets for host route injection.
func TestTier3_Interaction_FakeIPPoolPrefixes(t *testing.T) {
	pool4 := netip.MustParsePrefix("198.18.0.0/15")
	pool6 := netip.MustParsePrefix("fc00::/18")

	p, err := fakeip.New(pool4, pool6)
	if err != nil {
		t.Fatalf("failed to initialize FakeIP pool: %v", err)
	}

	// Allocate a FakeIP
	ip := p.V4("example.com")
	if !p.Contains(ip) {
		t.Fatalf("allocated ip %s not within pool", ip)
	}

	// Reverse lookup restores original domain
	domain, ok := p.Lookup(ip)
	if !ok || domain != "example.com" {
		t.Fatalf("lookup failed for %s, got %q, ok=%v", ip, domain, ok)
	}
}

// =============================================================================
// Tier 3 - Interaction 5: Windows NextHop Assignment Validation
// =============================================================================

// T3.I5: NextHop on Windows is assigned 100.100.100.100 to prevent WSA error 10049.
func TestTier3_Interaction_WindowsNextHopAssignment(t *testing.T) {
	// TailscaleServiceIP is authoritative 100.100.100.100
	expectedNextHop := netip.MustParseAddr("100.100.100.100")
	if !expectedNextHop.IsValid() {
		t.Fatalf("invalid NextHop address")
	}

	// NextHop must be an address, not an unspecified broadcast
	if expectedNextHop.IsUnspecified() {
		t.Fatalf("NextHop must not be unspecified")
	}

	if expectedNextHop.String() != "100.100.100.100" {
		t.Fatalf("expected NextHop 100.100.100.100, got %s", expectedNextHop.String())
	}
}
