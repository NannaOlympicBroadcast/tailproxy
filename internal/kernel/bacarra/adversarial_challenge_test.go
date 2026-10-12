package bacarra_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/kernel/bacarra"
	"tailscale.com/net/tsaddr"
)

// =============================================================================
// 1. Stress Tests: State Persistence (Atomic Writes, Corrupt/Truncated/Binary/Perms)
// =============================================================================

// TestAdversarial_State_ConcurrentAtomicWrites stresses SaveRouteState with multiple
// concurrent goroutines and concurrent readers.
// Empirical finding: on Windows, uncoordinated concurrent calls to SaveRouteState
// can experience timestamp collisions (time.Now().UnixNano() granularity) and
// ERROR_ACCESS_DENIED due to transient Windows file locks.
// This test asserts:
// 1. Concurrent readers never observe a corrupted or half-written state file (atomicity invariant).
// 2. Successful writes always produce valid, uncorrupted JSON.
// 3. No temporary files (.bacarra_routes.*.tmp) are orphaned.
func TestAdversarial_State_ConcurrentAtomicWrites(t *testing.T) {
	tmpDir := t.TempDir()
	const workers = 10
	const iterations = 10

	var stopReaders = make(chan struct{})
	var readerWg sync.WaitGroup

	// Spawn concurrent readers constantly reading state
	for r := 0; r < 5; r++ {
		readerWg.Add(1)
		go func() {
			defer readerWg.Done()
			for {
				select {
				case <-stopReaders:
					return
				default:
					st, err := bacarra.ReadRouteState(tmpDir)
					if err == nil {
						// State MUST be valid if read succeeded
						if st.Kernel != "bacarra" {
							t.Errorf("reader observed invalid kernel %q", st.Kernel)
						}
					}
					time.Sleep(500 * time.Microsecond)
				}
			}
		}()
	}

	var wg sync.WaitGroup
	wg.Add(workers)

	var contentionCount int
	var countMu sync.Mutex

	for i := 0; i < workers; i++ {
		workerID := i
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				state := &bacarra.RouteState{
					Kernel:       "bacarra",
					AdapterName:  fmt.Sprintf("tailscale-%d", workerID),
					AdapterIndex: workerID,
					UpdatedAt:    time.Now().UTC().Format(time.RFC3339Nano),
					Routes: []string{
						fmt.Sprintf("198.18.%d.0/24", workerID%250),
						"fc00::/18",
					},
				}
				if err := bacarra.SaveRouteState(tmpDir, state); err != nil {
					countMu.Lock()
					contentionCount++
					countMu.Unlock()
				}
				time.Sleep(2 * time.Millisecond)
			}
		}()
	}

	wg.Wait()
	close(stopReaders)
	readerWg.Wait()

	if contentionCount > 0 {
		t.Logf("Empirical finding (Windows filesystem): %d uncoordinated concurrent writes encountered rename contention", contentionCount)
	}

	// Verify that the final state file is completely valid JSON and readable
	finalState, err := bacarra.ReadRouteState(tmpDir)
	if err != nil {
		t.Fatalf("final ReadRouteState failed after concurrent writes: %v", err)
	}
	if finalState.Kernel != "bacarra" {
		t.Errorf("expected final kernel 'bacarra', got %q", finalState.Kernel)
	}
	if len(finalState.Routes) != 2 {
		t.Errorf("expected 2 routes, got %d", len(finalState.Routes))
	}

	// Verify no temporary files (.bacarra_routes.*.tmp) are orphaned in the directory
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("failed to read dir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".bacarra_routes.") && strings.HasSuffix(entry.Name(), ".tmp") {
			t.Errorf("orphaned temporary file detected: %s", entry.Name())
		}
	}
}

// TestAdversarial_RouteManager_ConcurrentApply_SerializedSafety verifies that when
// writes are coordinated through RouteManager.Apply (the production code path),
// the internal mutex completely prevents Windows Access is denied collisions.
func TestAdversarial_RouteManager_ConcurrentApply_SerializedSafety(t *testing.T) {
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

	const workers = 20
	const iterations = 10
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		workerID := i
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				prefixes := []netip.Prefix{
					netip.MustParsePrefix(fmt.Sprintf("198.18.%d.0/24", workerID%250)),
					netip.MustParsePrefix("fc00::/18"),
				}
				if err := rm.Apply(prefixes); err != nil {
					t.Errorf("worker %d iteration %d rm.Apply failed: %v", workerID, j, err)
				}
			}
		}()
	}

	wg.Wait()

	// State file must be intact and valid
	state, err := bacarra.ReadRouteState(tmpDir)
	if err != nil {
		t.Fatalf("ReadRouteState failed after concurrent rm.Apply: %v", err)
	}
	if state.Kernel != "bacarra" {
		t.Errorf("expected kernel 'bacarra', got %s", state.Kernel)
	}

	if err := rm.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

// TestAdversarial_State_TruncatedFiles stresses ReadRouteState with arbitrary file truncations.
func TestAdversarial_State_TruncatedFiles(t *testing.T) {
	validJSON := `{
  "kernel": "bacarra",
  "adapter_name": "tailscale0",
  "adapter_index": 1,
  "updated_at": "2026-10-12T00:00:00Z",
  "routes": [
    "198.18.0.0/15",
    "91.108.4.0/22"
  ]
}`

	// Truncate at every single byte length from 1 to len(validJSON)-1
	for length := 1; length < len(validJSON); length++ {
		truncated := validJSON[:length]
		tmpDir := t.TempDir()
		statePath := bacarra.StateFilePath(tmpDir)

		if err := os.WriteFile(statePath, []byte(truncated), 0600); err != nil {
			t.Fatalf("write truncated file at length %d: %v", length, err)
		}

		_, err := bacarra.ReadRouteState(tmpDir)
		if err == nil {
			t.Errorf("expected error for truncated JSON at length %d, got nil", length)
		}
		if !strings.Contains(err.Error(), "corrupt state file") {
			t.Errorf("expected error to mention 'corrupt state file' at length %d, got: %v", length, err)
		}
	}
}

// TestAdversarial_State_BinaryGarbage tests arbitrary binary entropy and null-bytes.
func TestAdversarial_State_BinaryGarbage(t *testing.T) {
	garbagePayloads := map[string][]byte{
		"all_null_bytes":          make([]byte, 256),
		"random_binary_1k":        make([]byte, 1024),
		"utf16_bom_with_garbage":  append([]byte{0xFF, 0xFE}, []byte("garbage binary data\x00\x01\x02")...),
		"utf8_bom_with_bad_json":  append([]byte{0xEF, 0xBB, 0xBF}, []byte("{\"kernel\": bad")...),
		"null_byte_prefixed_json": append([]byte{0x00}, []byte(`{"kernel":"bacarra"}`)...),
	}

	// Fill random_binary_1k with random bytes
	if _, err := rand.Read(garbagePayloads["random_binary_1k"]); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	for name, payload := range garbagePayloads {
		t.Run(name, func(t *testing.T) {
			tmpDir := t.TempDir()
			statePath := bacarra.StateFilePath(tmpDir)

			if err := os.WriteFile(statePath, payload, 0600); err != nil {
				t.Fatalf("write garbage: %v", err)
			}

			_, err := bacarra.ReadRouteState(tmpDir)
			if err == nil {
				t.Fatalf("expected error reading binary garbage, got nil")
			}
			if !strings.Contains(err.Error(), "corrupt state file") {
				t.Errorf("expected 'corrupt state file' in error, got: %v", err)
			}
		})
	}
}

// TestAdversarial_State_CorruptJSONStructures tests structurally invalid or mismatched JSON schemas.
func TestAdversarial_State_CorruptJSONStructures(t *testing.T) {
	badJSONs := map[string]string{
		"routes_is_integer":       `{"kernel": "bacarra", "routes": 12345}`,
		"routes_is_string":        `{"kernel": "bacarra", "routes": "198.18.0.0/15"}`,
		"routes_is_object":        `{"kernel": "bacarra", "routes": {"subnet": "198.18.0.0/15"}}`,
		"adapter_index_is_string": `{"kernel": "bacarra", "adapter_index": "not-a-number", "routes": []}`,
		"trailing_comma_syntax":   `{"kernel": "bacarra", "routes": ["198.18.0.0/15",]}`,
		"unclosed_array":          `{"kernel": "bacarra", "routes": ["198.18.0.0/15"`,
		"nested_array_in_routes":  `{"kernel": "bacarra", "routes": [["198.18.0.0/15"]]}`,
	}

	for name, content := range badJSONs {
		t.Run(name, func(t *testing.T) {
			tmpDir := t.TempDir()
			statePath := bacarra.StateFilePath(tmpDir)

			if err := os.WriteFile(statePath, []byte(content), 0600); err != nil {
				t.Fatalf("write bad JSON: %v", err)
			}

			_, err := bacarra.ReadRouteState(tmpDir)
			if err == nil {
				t.Fatalf("expected error parsing malformed JSON schema %q, got nil", name)
			}
			if !strings.Contains(err.Error(), "corrupt state file") {
				t.Errorf("expected 'corrupt state file' in error, got: %v", err)
			}
		})
	}
}

// TestAdversarial_State_WrongKernelStrings tests various invalid kernel values.
func TestAdversarial_State_WrongKernelStrings(t *testing.T) {
	testCases := []string{
		"davin",
		"DAVIN",
		"BACARRA",
		"bacarra ",
		" bacarra",
		"bacarra\x00",
		"wireguard",
		"tun",
		"",
		"null",
	}

	for _, kVal := range testCases {
		t.Run("kernel_"+kVal, func(t *testing.T) {
			tmpDir := t.TempDir()
			statePath := bacarra.StateFilePath(tmpDir)

			jsonContent := fmt.Sprintf(`{"kernel": %q, "adapter_name": "tailscale0", "routes": []}`, kVal)
			if err := os.WriteFile(statePath, []byte(jsonContent), 0600); err != nil {
				t.Fatalf("write state: %v", err)
			}

			_, err := bacarra.ReadRouteState(tmpDir)
			if err == nil {
				t.Fatalf("expected error for invalid kernel string %q, got nil", kVal)
			}
			if !strings.Contains(err.Error(), "corrupt state file") {
				t.Errorf("expected 'corrupt state file' in error, got: %v", err)
			}
		})
	}
}

// TestAdversarial_State_ReadOnlyHandling tests behavior when state file has read-only permissions.
func TestAdversarial_State_ReadOnlyHandling(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := bacarra.StateFilePath(tmpDir)

	initialState := &bacarra.RouteState{
		Kernel:       "bacarra",
		AdapterName:  "tailscale0",
		AdapterIndex: 1,
		UpdatedAt:    "2026-10-12T00:00:00Z",
		Routes:       []string{"198.18.0.0/15"},
	}

	if err := bacarra.SaveRouteState(tmpDir, initialState); err != nil {
		t.Fatalf("initial save failed: %v", err)
	}

	// Make state file read-only
	if err := os.Chmod(statePath, 0400); err != nil {
		t.Skipf("cannot set read-only attribute: %v", err)
	}

	// Read should still succeed even if file is read-only
	readState, err := bacarra.ReadRouteState(tmpDir)
	if err != nil {
		t.Errorf("ReadRouteState failed on read-only file: %v", err)
	}
	if readState == nil || readState.Kernel != "bacarra" {
		t.Errorf("unexpected read state on read-only file: %v", readState)
	}

	// Restore write permissions so cleanup doesn't fail
	_ = os.Chmod(statePath, 0600)
}

// =============================================================================
// 2. Stress Tests: TeardownStale Behavior
// =============================================================================

// TestAdversarial_TeardownStale_MissingCorruptEmptyObsolete systematically verifies
// all lifecycle conditions of TeardownStale.
func TestAdversarial_TeardownStale_MissingCorruptEmptyObsolete(t *testing.T) {
	// Case 1: Missing state file -> returns nil (no-op)
	t.Run("missing_file", func(t *testing.T) {
		tmpDir := t.TempDir()
		if err := bacarra.TeardownStale(tmpDir); err != nil {
			t.Errorf("expected nil for missing state file, got: %v", err)
		}
	})

	// Case 2: Empty directory path -> returns nil
	t.Run("empty_dir_path", func(t *testing.T) {
		if err := bacarra.TeardownStale(""); err != nil {
			t.Errorf("expected nil for empty state dir path, got: %v", err)
		}
	})

	// Case 3: Empty file (0-byte) -> returns corrupt error AND purges the file
	t.Run("empty_file_purged", func(t *testing.T) {
		tmpDir := t.TempDir()
		statePath := bacarra.StateFilePath(tmpDir)
		if err := os.WriteFile(statePath, []byte(""), 0600); err != nil {
			t.Fatalf("write empty file: %v", err)
		}

		err := bacarra.TeardownStale(tmpDir)
		if err == nil {
			t.Fatal("expected error on empty state file, got nil")
		}
		if !strings.Contains(err.Error(), "corrupt") {
			t.Errorf("expected 'corrupt' in error, got: %v", err)
		}

		// State file must be purged from disk
		if _, err := os.Stat(statePath); !os.IsNotExist(err) {
			t.Errorf("expected empty state file to be purged, but it still exists: %v", err)
		}

		// Second invocation should now find no file and return nil (self-healing)
		if err := bacarra.TeardownStale(tmpDir); err != nil {
			t.Errorf("second invocation of TeardownStale should return nil, got: %v", err)
		}
	})

	// Case 4: Binary corrupt file -> returns corrupt error AND purges the file
	t.Run("corrupt_file_purged", func(t *testing.T) {
		tmpDir := t.TempDir()
		statePath := bacarra.StateFilePath(tmpDir)
		if err := os.WriteFile(statePath, []byte{0x00, 0xFF, 0xFE, 0x01}, 0600); err != nil {
			t.Fatalf("write corrupt file: %v", err)
		}

		err := bacarra.TeardownStale(tmpDir)
		if err == nil {
			t.Fatal("expected error on corrupt state file, got nil")
		}
		if !strings.Contains(err.Error(), "corrupt") {
			t.Errorf("expected 'corrupt' in error, got: %v", err)
		}

		// State file must be purged
		if _, err := os.Stat(statePath); !os.IsNotExist(err) {
			t.Errorf("expected corrupt state file to be purged, but it still exists: %v", err)
		}

		// Second invocation returns nil
		if err := bacarra.TeardownStale(tmpDir); err != nil {
			t.Errorf("second invocation of TeardownStale should return nil, got: %v", err)
		}
	})

	// Case 5: State with obsolete / invalid route strings
	t.Run("invalid_route_strings_in_state", func(t *testing.T) {
		tmpDir := t.TempDir()
		statePath := bacarra.StateFilePath(tmpDir)

		stateContent := `{
  "kernel": "bacarra",
  "adapter_name": "tailscale0",
  "adapter_index": 999999,
  "updated_at": "2026-10-12T00:00:00Z",
  "routes": [
    "not-a-valid-cidr",
    "999.999.999.999/32",
    "::invalid::prefix/128",
    "",
    "198.18.0.0/15"
  ]
}`
		if err := os.WriteFile(statePath, []byte(stateContent), 0600); err != nil {
			t.Fatalf("write state: %v", err)
		}

		// TeardownStale should parse, skip invalid prefix strings, and remove state file
		_ = bacarra.TeardownStale(tmpDir)

		// State file must be purged
		if _, err := os.Stat(statePath); !os.IsNotExist(err) {
			t.Errorf("state file was not purged after TeardownStale")
		}

		// Second call must succeed with nil
		if err := bacarra.TeardownStale(tmpDir); err != nil {
			t.Errorf("idempotent TeardownStale failed: %v", err)
		}
	})

	// Case 6: Non-existent adapter index and name in state file
	t.Run("non_existent_adapter_in_state", func(t *testing.T) {
		tmpDir := t.TempDir()
		statePath := bacarra.StateFilePath(tmpDir)

		state := &bacarra.RouteState{
			Kernel:       "bacarra",
			AdapterName:  "non_existent_ghost_adapter_12345",
			AdapterIndex: 99999,
			UpdatedAt:    "2026-10-12T00:00:00Z",
			Routes: []string{
				"198.18.0.0/15",
			},
		}

		if err := bacarra.SaveRouteState(tmpDir, state); err != nil {
			t.Fatalf("save state: %v", err)
		}

		// TeardownStale should clean up the state file even if adapter cannot be resolved
		_ = bacarra.TeardownStale(tmpDir)

		if _, err := os.Stat(statePath); !os.IsNotExist(err) {
			t.Errorf("expected state file to be purged even when adapter is gone")
		}
	})
}

// =============================================================================
// 3. Stress Tests: NextHop Determination Logic (IPv4 & IPv6 Subnets)
// =============================================================================

// TestAdversarial_NextHopDetermination tests NextHop resolution across diverse IPv4 & IPv6 subnets.
func TestAdversarial_NextHopDetermination(t *testing.T) {
	v4Cases := []struct {
		prefix string
		desc   string
	}{
		{"0.0.0.0/0", "default route"},
		{"198.18.0.0/15", "FakeIP IPv4 pool"},
		{"91.108.4.0/22", "Telegram CIDR"},
		{"149.154.160.0/20", "Telegram CIDR 2"},
		{"1.1.1.1/32", "host route /32"},
		{"10.0.0.0/8", "RFC1918 Class A"},
		{"172.16.0.0/12", "RFC1918 Class B"},
		{"192.168.0.0/16", "RFC1918 Class C"},
		{"100.64.0.0/10", "CGNAT block"},
		{"224.0.0.0/4", "Multicast block"},
		{"255.255.255.255/32", "Broadcast host"},
	}

	expectedV4NextHop := tsaddr.TailscaleServiceIP() // 100.100.100.100

	for _, tc := range v4Cases {
		p, err := netip.ParsePrefix(tc.prefix)
		if err != nil {
			t.Fatalf("parse prefix %s: %v", tc.prefix, err)
		}

		nh := bacarra.NextHopForPrefix(p)
		if !nh.IsValid() {
			t.Errorf("[%s] NextHop for %s is not valid", tc.desc, tc.prefix)
		}
		if nh.IsUnspecified() {
			t.Errorf("[%s] NextHop for %s is unspecified (0.0.0.0) - violates WSA 10049 prevention", tc.desc, tc.prefix)
		}
		if !nh.Is4() {
			t.Errorf("[%s] NextHop for IPv4 %s must be IPv4", tc.desc, tc.prefix)
		}
		if nh != expectedV4NextHop {
			t.Errorf("[%s] NextHop for %s: got %s, want %s", tc.desc, tc.prefix, nh, expectedV4NextHop)
		}
		if !bacarra.IsTailscaleIP(nh) {
			t.Errorf("[%s] NextHop %s must be within official Tailscale IP range", tc.desc, nh)
		}
	}

	v6Cases := []struct {
		prefix string
		desc   string
	}{
		{"::/0", "IPv6 default route"},
		{"fc00::/18", "FakeIP IPv6 pool"},
		{"fd7a:115c:a1e0::/48", "Tailscale ULA range"},
		{"2001:db8::/32", "Documentation prefix"},
		{"2606:4700::/32", "Cloudflare IPv6"},
		{"::1/128", "IPv6 loopback"},
		{"fe80::/10", "Link local prefix"},
	}

	expectedV6NextHop := tsaddr.TailscaleServiceIPv6()

	for _, tc := range v6Cases {
		p, err := netip.ParsePrefix(tc.prefix)
		if err != nil {
			t.Fatalf("parse prefix %s: %v", tc.prefix, err)
		}

		nh := bacarra.NextHopForPrefix(p)
		if !nh.IsValid() {
			t.Errorf("[%s] NextHop for %s is not valid", tc.desc, tc.prefix)
		}
		if nh.IsUnspecified() {
			t.Errorf("[%s] NextHop for %s is unspecified (::)", tc.desc, tc.prefix)
		}
		if !nh.Is6() {
			t.Errorf("[%s] NextHop for IPv6 %s must be IPv6", tc.desc, tc.prefix)
		}
		if nh != expectedV6NextHop {
			t.Errorf("[%s] NextHop for %s: got %s, want %s", tc.desc, tc.prefix, nh, expectedV6NextHop)
		}
		if !bacarra.IsTailscaleIP(nh) {
			t.Errorf("[%s] NextHop %s must be within official Tailscale IP range", tc.desc, nh)
		}
	}
}

// TestAdversarial_NextHopDetermination_ZeroValuePrefix tests that even an invalid
// or zero-value prefix does not panic.
func TestAdversarial_NextHopDetermination_ZeroValuePrefix(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NextHopForPrefix panicked on zero prefix: %v", r)
		}
	}()

	var zeroPrefix netip.Prefix
	nh := bacarra.NextHopForPrefix(zeroPrefix)
	if !nh.IsValid() {
		t.Errorf("expected valid fallback NextHop, got: %v", nh)
	}
}

// =============================================================================
// 4. Stress Tests: RouteManager Idempotency, Repeated Apply & Teardown
// =============================================================================

func TestAdversarial_RouteManager_RapidRepeatedApplies(t *testing.T) {
	tmpDir := t.TempDir()
	driver := newMockRouteDriver()

	adapter := &bacarra.AdapterInfo{
		Name:  "tailscale0",
		Index: 10,
		IPs:   []netip.Addr{netip.MustParseAddr("100.64.0.10")},
	}

	rm, err := bacarra.NewRouteManagerWithDriver(adapter, tmpDir, nil, driver)
	if err != nil {
		t.Fatalf("NewRouteManagerWithDriver failed: %v", err)
	}

	// Repeatedly apply alternating sets of routes 50 times
	setA := []netip.Prefix{
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("91.108.4.0/22"),
		netip.MustParsePrefix("fc00::/18"),
	}

	setB := []netip.Prefix{
		netip.MustParsePrefix("198.18.0.0/15"), // overlapping
		netip.MustParsePrefix("1.1.1.0/24"),    // new
	}

	for i := 0; i < 50; i++ {
		targetSet := setA
		if i%2 == 1 {
			targetSet = setB
		}
		if err := rm.Apply(targetSet); err != nil {
			t.Fatalf("iteration %d Apply failed: %v", i, err)
		}

		applied := rm.AppliedRoutes()
		if len(applied) != len(targetSet) {
			t.Fatalf("iteration %d: applied count mismatch: got %d, want %d", i, len(applied), len(targetSet))
		}
	}

	// Finally close
	if err := rm.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if len(rm.AppliedRoutes()) != 0 {
		t.Errorf("routes still applied after Close: %v", rm.AppliedRoutes())
	}

	// State file must be gone
	if _, err := bacarra.ReadRouteState(tmpDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected state file to be gone after Close, got: %v", err)
	}
}
