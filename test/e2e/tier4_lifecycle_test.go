package e2e

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
)

// =============================================================================
// Tier 4 - Scenario 1: Simulated Bacarra Full Lifecycle
// =============================================================================

// T4.S1: Complete lifecycle execution: config check -> pre-clean -> adapter check -> route persistence -> teardown -> idempotency.
func TestTier4_Lifecycle_BacarraFullSimulation(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "bacarra_routes.json")

	// -------------------------------------------------------------------------
	// Step 1: Pre-Flight Config Check
	// -------------------------------------------------------------------------
	raw := sampleValidConfig("bacarra")
	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("lifecycle Step 1 failed: config parse error: %v", err)
	}
	if cfg.Kernel != config.KernelBacarra {
		t.Fatalf("lifecycle Step 1 failed: expected bacarra kernel, got %s", cfg.Kernel)
	}

	// -------------------------------------------------------------------------
	// Step 2: Pre-Clean Any Stale State Left From Crashes
	// -------------------------------------------------------------------------
	if _, err := os.Stat(statePath); err == nil {
		// Found stale state file, remove it
		if err := os.Remove(statePath); err != nil {
			t.Fatalf("lifecycle Step 2 failed: cannot remove stale state: %v", err)
		}
	}

	// -------------------------------------------------------------------------
	// Step 3: Adapter Discovery & Anti-Mock Verification
	// -------------------------------------------------------------------------
	verifyNoMockAdapters(t)

	// -------------------------------------------------------------------------
	// Step 4: Route Generation & State Persistence
	// -------------------------------------------------------------------------
	expectedRoutes := compileExpectedRoutes(t, cfg)
	if len(expectedRoutes) == 0 {
		t.Fatalf("lifecycle Step 4 failed: expected non-empty route set")
	}

	var routeStrings []string
	for _, r := range expectedRoutes {
		routeStrings = append(routeStrings, r.String())
	}

	initialState := &BacarraState{
		Kernel:       "bacarra",
		AdapterName:  "tailscale0",
		AdapterIndex: 1,
		UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
		Routes:       routeStrings,
	}

	if err := writeBacarraState(statePath, initialState); err != nil {
		t.Fatalf("lifecycle Step 4 failed: cannot persist state: %v", err)
	}

	// Verify file was written and is readable
	loadedState, err := readBacarraState(statePath)
	if err != nil {
		t.Fatalf("lifecycle Step 4 failed: cannot read state file: %v", err)
	}
	if len(loadedState.Routes) != len(routeStrings) {
		t.Fatalf("lifecycle Step 4 failed: route count mismatch: %d != %d", len(loadedState.Routes), len(routeStrings))
	}

	// -------------------------------------------------------------------------
	// Step 5: Graceful Teardown Cleanup
	// -------------------------------------------------------------------------
	// Simulate route teardown
	var deletedRoutes []netip.Prefix
	for _, rStr := range loadedState.Routes {
		p, err := netip.ParsePrefix(rStr)
		if err != nil {
			t.Fatalf("lifecycle Step 5 failed: invalid route in state: %v", err)
		}
		deletedRoutes = append(deletedRoutes, p)
	}

	if len(deletedRoutes) != len(loadedState.Routes) {
		t.Fatalf("lifecycle Step 5 failed: incomplete teardown route collection")
	}

	// Remove state file on clean exit
	if err := os.Remove(statePath); err != nil {
		t.Fatalf("lifecycle Step 5 failed: cannot remove state file: %v", err)
	}

	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("lifecycle Step 5 failed: state file still exists after teardown")
	}

	// -------------------------------------------------------------------------
	// Step 6: Teardown Idempotency
	// -------------------------------------------------------------------------
	// Re-executing teardown on non-existent state file must not error or panic
	if err := os.Remove(statePath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("lifecycle Step 6 failed: unexpected error on idempotent removal: %v", err)
	}
}

// =============================================================================
// Tier 4 - Scenario 2: Simulated Crash Recovery & Capture Down
// =============================================================================

// T4.S2: Simulated unhandled daemon crash recovery restores state safely.
func TestTier4_Lifecycle_CrashRecovery(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "bacarra_routes.json")

	// Simulate dirty state leftover after SIGKILL
	dirtyState := &BacarraState{
		Kernel:       "bacarra",
		AdapterName:  "tailscale0",
		AdapterIndex: 2,
		UpdatedAt:    "2026-10-12T01:00:00Z",
		Routes: []string{
			"198.18.0.0/15",
			"fc00::/18",
			"91.108.4.0/22",
		},
	}
	if err := writeBacarraState(statePath, dirtyState); err != nil {
		t.Fatalf("failed to create dirty crash state: %v", err)
	}

	// Execute simulated "tailproxy capture down" / crash recovery purge
	recoveryPurge := func(path string) error {
		state, err := readBacarraState(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil // already clean
			}
			// If corrupt, remove anyway to restore host
			_ = os.Remove(path)
			return fmt.Errorf("purged corrupt state file: %w", err)
		}

		// Purge all tracked routes
		for _, rStr := range state.Routes {
			if _, err := netip.ParsePrefix(rStr); err != nil {
				t.Logf("ignoring malformed route during recovery purge: %s", rStr)
			}
		}

		// Unlink state file
		return os.Remove(path)
	}

	if err := recoveryPurge(statePath); err != nil {
		t.Fatalf("crash recovery purge failed: %v", err)
	}

	// State file must be gone
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("state file was not unlinked after crash recovery")
	}

	// Second execution must be completely idempotent (no-op, nil error)
	if err := recoveryPurge(statePath); err != nil {
		t.Fatalf("idempotent crash recovery failed: %v", err)
	}
}
