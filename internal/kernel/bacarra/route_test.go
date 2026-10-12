package bacarra_test

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/kernel/bacarra"
)

type mockRouteDriver struct {
	mu      sync.Mutex
	added   map[netip.Prefix]int
	deleted map[netip.Prefix]int
	failAdd map[netip.Prefix]error
	failDel map[netip.Prefix]error
}

func newMockRouteDriver() *mockRouteDriver {
	return &mockRouteDriver{
		added:   make(map[netip.Prefix]int),
		deleted: make(map[netip.Prefix]int),
		failAdd: make(map[netip.Prefix]error),
		failDel: make(map[netip.Prefix]error),
	}
}

func (m *mockRouteDriver) AddRoute(p netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err, ok := m.failAdd[p]; ok {
		return err
	}
	m.added[p]++
	return nil
}

func (m *mockRouteDriver) DeleteRoute(p netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err, ok := m.failDel[p]; ok {
		return err
	}
	m.deleted[p]++
	return nil
}

func TestNextHopForPrefix(t *testing.T) {
	v4Prefixes := []string{
		"198.18.0.0/15",
		"91.108.4.0/22",
		"1.1.1.1/32",
		"0.0.0.0/0",
	}

	for _, pStr := range v4Prefixes {
		p := netip.MustParsePrefix(pStr)
		nh := bacarra.NextHopForPrefix(p)

		if !nh.IsValid() {
			t.Fatalf("expected valid NextHop for %s", pStr)
		}
		if nh.IsUnspecified() {
			t.Fatalf("NextHop must not be unspecified (0.0.0.0) for %s to prevent WSA 10049", pStr)
		}
		if nh.String() != "100.100.100.100" {
			t.Errorf("NextHop for IPv4 %s: got %s, want 100.100.100.100", pStr, nh.String())
		}
	}

	v6Prefix := netip.MustParsePrefix("fc00::/18")
	nh6 := bacarra.NextHopForPrefix(v6Prefix)
	if !nh6.IsValid() {
		t.Fatalf("expected valid NextHop for IPv6 %s", v6Prefix)
	}
	if nh6.IsUnspecified() {
		t.Fatalf("NextHop must not be unspecified (::) for %s", v6Prefix)
	}
}

func TestRouteManager_DiffingAndLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	driver := newMockRouteDriver()

	adapter := &bacarra.AdapterInfo{
		Name:  "tailscale0",
		Index: 1,
		IPs:   []netip.Addr{netip.MustParseAddr("100.64.0.1")},
	}

	rm, err := bacarra.NewRouteManagerWithDriver(adapter, tmpDir, nil, driver)
	if err != nil {
		t.Fatalf("NewRouteManagerWithDriver failed: %v", err)
	}

	// Step 1: Initial apply of 3 routes
	initialRoutes := []netip.Prefix{
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("91.108.4.0/22"),
		netip.MustParsePrefix("1.1.1.0/24"),
	}

	if err := rm.Apply(initialRoutes); err != nil {
		t.Fatalf("initial Apply failed: %v", err)
	}

	if len(driver.added) != 3 {
		t.Errorf("expected 3 routes added, got %d", len(driver.added))
	}
	if len(driver.deleted) != 0 {
		t.Errorf("expected 0 routes deleted, got %d", len(driver.deleted))
	}

	// Verify state file was created
	state, err := bacarra.ReadRouteState(tmpDir)
	if err != nil {
		t.Fatalf("read route state failed: %v", err)
	}
	if len(state.Routes) != 3 {
		t.Errorf("expected 3 routes in state, got %d", len(state.Routes))
	}

	applied := rm.AppliedRoutes()
	if len(applied) != 3 {
		t.Errorf("expected 3 applied routes, got %d", len(applied))
	}

	// Step 2: Idempotency check: re-apply exact same set
	if err := rm.Apply(initialRoutes); err != nil {
		t.Fatalf("idempotent Apply failed: %v", err)
	}

	// No new calls to AddRoute or DeleteRoute should occur
	for p, count := range driver.added {
		if count != 1 {
			t.Errorf("route %s added %d times (expected 1)", p, count)
		}
	}
	if len(driver.deleted) != 0 {
		t.Errorf("expected 0 routes deleted on identical re-apply, got %d", len(driver.deleted))
	}

	// Step 3: Incremental modification
	// Remove 91.108.4.0/22, keep 198.18.0.0/15 and 1.1.1.0/24, add 8.8.8.0/24
	updatedRoutes := []netip.Prefix{
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("1.1.1.0/24"),
		netip.MustParsePrefix("8.8.8.0/24"),
	}

	if err := rm.Apply(updatedRoutes); err != nil {
		t.Fatalf("incremental Apply failed: %v", err)
	}

	// 8.8.8.0/24 should be added
	pAdded := netip.MustParsePrefix("8.8.8.0/24")
	if driver.added[pAdded] != 1 {
		t.Errorf("expected %s to be added", pAdded)
	}

	// 91.108.4.0/22 should be deleted
	pRemoved := netip.MustParsePrefix("91.108.4.0/22")
	if driver.deleted[pRemoved] != 1 {
		t.Errorf("expected %s to be deleted", pRemoved)
	}

	// State file should now have 3 routes: 198.18.0.0/15, 1.1.1.0/24, 8.8.8.0/24
	state, err = bacarra.ReadRouteState(tmpDir)
	if err != nil {
		t.Fatalf("read updated route state failed: %v", err)
	}
	if len(state.Routes) != 3 {
		t.Errorf("expected 3 routes in updated state, got %d", len(state.Routes))
	}

	// Step 4: Close teardown
	if err := rm.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if len(rm.AppliedRoutes()) != 0 {
		t.Errorf("expected 0 applied routes after Close, got %d", len(rm.AppliedRoutes()))
	}

	// Remaining 3 routes should have been deleted by Close
	for _, p := range updatedRoutes {
		if driver.deleted[p] != 1 {
			t.Errorf("expected %s to be deleted upon Close", p)
		}
	}

	// State file must be purged after Close
	if _, err := bacarra.ReadRouteState(tmpDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected state file to be removed after Close, got: %v", err)
	}
}

func TestRouteManager_ErrorHandling(t *testing.T) {
	tmpDir := t.TempDir()
	driver := newMockRouteDriver()

	failPrefix := netip.MustParsePrefix("192.168.100.0/24")
	driver.failAdd[failPrefix] = errors.New("simulated route injection failure")

	adapter := &bacarra.AdapterInfo{
		Name:  "tailscale0",
		Index: 1,
		IPs:   []netip.Addr{netip.MustParseAddr("100.64.0.1")},
	}

	rm, err := bacarra.NewRouteManagerWithDriver(adapter, tmpDir, nil, driver)
	if err != nil {
		t.Fatalf("NewRouteManagerWithDriver failed: %v", err)
	}

	routes := []netip.Prefix{
		netip.MustParsePrefix("198.18.0.0/15"),
		failPrefix,
	}

	err = rm.Apply(routes)
	if err == nil {
		t.Fatal("expected Apply to return error when driver fails, got nil")
	}

	// The failing prefix must not be marked applied
	applied := rm.AppliedRoutes()
	if len(applied) != 1 || applied[0].String() != "198.18.0.0/15" {
		t.Errorf("expected only successful prefix in applied routes, got: %v", applied)
	}
}

func TestRouteManager_TeardownStale_ValidState(t *testing.T) {
	tmpDir := t.TempDir()

	state := &bacarra.RouteState{
		Kernel:       "bacarra",
		AdapterName:  "tailscale0",
		AdapterIndex: 1,
		UpdatedAt:    "2026-10-12T00:00:00Z",
		Routes: []string{
			"198.18.0.0/15",
			"91.108.4.0/22",
		},
	}

	if err := bacarra.SaveRouteState(tmpDir, state); err != nil {
		t.Fatalf("save state: %v", err)
	}

	// Run TeardownStale
	_ = bacarra.TeardownStale(tmpDir)

	// State file must be cleaned up
	if _, err := os.Stat(bacarra.StateFilePath(tmpDir)); !os.IsNotExist(err) {
		t.Errorf("expected state file to be purged, got: %v", err)
	}
}

func TestRouteManager_TeardownStale_CorruptState(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := bacarra.StateFilePath(tmpDir)

	if err := os.WriteFile(filePath, []byte(`{"kernel": "bacarra", "routes": [ incomplete`), 0600); err != nil {
		t.Fatalf("write corrupt state: %v", err)
	}

	err := bacarra.TeardownStale(tmpDir)
	if err == nil {
		t.Fatal("expected error from TeardownStale on corrupt state, got nil")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("expected 'corrupt' in error, got: %v", err)
	}

	// Corrupt file must be purged
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Errorf("expected corrupt state file to be purged, but it still exists")
	}
}

func TestRouteManager_TeardownStale_EmptyState(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := bacarra.StateFilePath(tmpDir)

	if err := os.WriteFile(filePath, []byte(""), 0600); err != nil {
		t.Fatalf("write empty state: %v", err)
	}

	err := bacarra.TeardownStale(tmpDir)
	if err == nil {
		t.Fatal("expected error from TeardownStale on empty state, got nil")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("expected 'corrupt' in error, got: %v", err)
	}

	// Empty file must be purged
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Errorf("expected empty state file to be purged, but it still exists")
	}
}

func TestRouteManager_TeardownStale_NonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistentDir := filepath.Join(tmpDir, "does_not_exist")

	if err := bacarra.TeardownStale(nonExistentDir); err != nil {
		t.Errorf("expected nil error for non-existent state dir, got: %v", err)
	}
}

func TestRouteManager_NilAdapterValidation(t *testing.T) {
	_, err := bacarra.NewRouteManager(nil, "", nil)
	if err == nil {
		t.Fatal("expected error creating RouteManager with nil adapter, got nil")
	}

	_, err = bacarra.NewRouteManagerWithDriver(nil, "", nil, newMockRouteDriver())
	if err == nil {
		t.Fatal("expected error creating RouteManagerWithDriver with nil adapter, got nil")
	}
}
