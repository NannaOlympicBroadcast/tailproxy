package bacarra

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/kernel"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
)

type memoryDriver struct {
	mu      sync.Mutex
	routes  map[netip.Prefix]bool
	added   []netip.Prefix
	deleted []netip.Prefix
}

func newMemoryDriver() *memoryDriver {
	return &memoryDriver{
		routes: make(map[netip.Prefix]bool),
	}
}

func (m *memoryDriver) AddRoute(p netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes[p] = true
	m.added = append(m.added, p)
	return nil
}

func (m *memoryDriver) DeleteRoute(p netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.routes, p)
	m.deleted = append(m.deleted, p)
	return nil
}

func TestBacarraEngine_Lifecycle(t *testing.T) {
	stateDir := t.TempDir()
	adapter := &AdapterInfo{
		Name:  "tailscale0",
		Index: 42,
		IPs:   []netip.Addr{netip.MustParseAddr("100.64.0.5")},
	}
	driver := newMemoryDriver()
	rm, err := NewRouteManagerWithDriver(adapter, stateDir, nil, driver)
	if err != nil {
		t.Fatalf("NewRouteManagerWithDriver error: %v", err)
	}

	cfg := &config.Config{
		Kernel: "bacarra",
		DNS: config.DNS{
			Mode: "fakeip",
			FakeIP: config.FakeIP{
				Inet4: "198.18.0.0/15",
				Inet6: "fc00::/18",
			},
		},
	}

	eng, err := NewEngineWithManager(cfg, stateDir, nil, adapter, rm)
	if err != nil {
		t.Fatalf("NewEngineWithManager error: %v", err)
	}

	var _ kernel.Engine = eng

	if eng.Type() != kernel.ModeBacarra {
		t.Errorf("eng.Type() = %q, want %q", eng.Type(), kernel.ModeBacarra)
	}
	if eng.Adapter() != adapter {
		t.Errorf("eng.Adapter() mismatch")
	}
	if eng.RouteManager() != rm {
		t.Errorf("eng.RouteManager() mismatch")
	}
	if eng.Pool() == nil {
		t.Error("eng.Pool() is nil when DNS mode is fakeip")
	}

	// Set dynamic rules
	testPrefix := netip.MustParsePrefix("203.0.113.0/24")
	rulesEngine, err := rule.Compile([]config.Rule{
		{IPCIDR: []string{"203.0.113.0/24"}, Egress: "vpn-node"},
		{Final: "direct"},
	})
	if err != nil {
		t.Fatalf("rule.Compile error: %v", err)
	}
	eng.SetRules(func() *rule.Engine { return rulesEngine })

	// Start engine
	ctx := context.Background()
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("eng.Start error: %v", err)
	}

	// Verify routes were applied (FakeIP pools + testPrefix)
	applied := rm.AppliedRoutes()
	if len(applied) < 3 {
		t.Fatalf("expected at least 3 routes (2 fakeip + 1 rule cidr), got %d: %v", len(applied), applied)
	}

	foundCIDR := false
	for _, p := range applied {
		if p == testPrefix {
			foundCIDR = true
			break
		}
	}
	if !foundCIDR {
		t.Errorf("applied routes %v does not contain %s", applied, testPrefix)
	}

	// Verify status
	statusRaw := eng.Status()
	statusMap, ok := statusRaw.(map[string]any)
	if !ok {
		t.Fatalf("eng.Status() returned %T, want map[string]any", statusRaw)
	}
	if statusMap["mode"] != "bacarra" || statusMap["adapter_name"] != "tailscale0" {
		t.Errorf("unexpected status map: %+v", statusMap)
	}

	// Verify components
	comps := eng.Components()
	if len(comps) != 3 {
		t.Fatalf("expected 3 components, got %d", len(comps))
	}
	expectedNames := []string{"kernel", "tailscale_adapter", "route_manager"}
	for i, name := range expectedNames {
		if comps[i].Name != name {
			t.Errorf("comps[%d].Name = %q, want %q", i, comps[i].Name, name)
		}
		if comps[i].State != "running" && comps[i].State != "active" {
			t.Errorf("comps[%d].State = %q, want running or active", i, comps[i].State)
		}
	}

	// Verify Reload with removed CIDR
	newRules, err := rule.Compile([]config.Rule{
		{Final: "direct"},
	})
	if err != nil {
		t.Fatalf("rule.Compile error: %v", err)
	}
	if err := eng.Reload(cfg, newRules); err != nil {
		t.Fatalf("eng.Reload error: %v", err)
	}

	// After reload, rule prefix should be gone, leaving only FakeIP prefixes
	appliedAfter := rm.AppliedRoutes()
	for _, p := range appliedAfter {
		if p == testPrefix {
			t.Errorf("testPrefix %s should have been removed after reload", testPrefix)
		}
	}

	// Verify Close
	if err := eng.Close(); err != nil {
		t.Fatalf("eng.Close error: %v", err)
	}

	// Applied routes in RouteManager should now be 0
	if len(rm.AppliedRoutes()) != 0 {
		t.Errorf("routes after Close: %v, want empty", rm.AppliedRoutes())
	}

	// FakeIP file should exist
	fakeIPPath := filepath.Join(stateDir, "fakeip.json")
	if _, err := os.Stat(fakeIPPath); err != nil {
		t.Errorf("fakeip.json not saved after Close: %v", err)
	}

	// Verify Teardown
	if err := eng.Teardown(); err != nil {
		t.Fatalf("eng.Teardown error: %v", err)
	}
}

func TestBacarraFactoryRegistered(t *testing.T) {
	modes := kernel.RegisteredModes()
	found := false
	for _, m := range modes {
		if m == kernel.ModeBacarra {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("kernel.ModeBacarra not found in RegisteredModes(): %v", modes)
	}
}
