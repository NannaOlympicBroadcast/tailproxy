package kernel_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/kernel"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/kernel/bacarra"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/kernel/davin"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/panel"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
)

// =============================================================================
// Mock / In-Memory Driver for Bacarra Testing
// =============================================================================

type testMemoryRouteDriver struct {
	mu      sync.Mutex
	routes  map[netip.Prefix]bool
	added   []netip.Prefix
	deleted []netip.Prefix
}

func newTestMemoryRouteDriver() *testMemoryRouteDriver {
	return &testMemoryRouteDriver{
		routes: make(map[netip.Prefix]bool),
	}
}

func (m *testMemoryRouteDriver) AddRoute(p netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes[p] = true
	m.added = append(m.added, p)
	return nil
}

func (m *testMemoryRouteDriver) DeleteRoute(p netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.routes, p)
	m.deleted = append(m.deleted, p)
	return nil
}

// =============================================================================
// Objective 1: Invalid/Unregistered Kernel Modes in kernel.New()
// =============================================================================

func TestAdversarial_KernelNew_NilAndInvalidModes(t *testing.T) {
	// Case 1: Nil Config
	if _, err := kernel.New(nil, t.TempDir(), nil); err == nil {
		t.Fatal("kernel.New(nil) expected error, got nil")
	} else if !strings.Contains(err.Error(), "nil configuration") {
		t.Errorf("kernel.New(nil) error %q does not mention 'nil configuration'", err.Error())
	}

	// Case 2: Empty Kernel Mode string in Config (should default to Davin)
	emptyCfg := &config.Config{Kernel: ""}
	eng, err := kernel.New(emptyCfg, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("kernel.New with empty kernel mode failed: %v", err)
	}
	if eng.Type() != kernel.ModeDavin {
		t.Fatalf("kernel.New with empty kernel mode returned %q, want %q", eng.Type(), kernel.ModeDavin)
	}
	_ = eng.Close()

	// Case 3: Explicit Davin mode
	davinCfg := &config.Config{Kernel: "davin"}
	engDavin, err := kernel.New(davinCfg, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("kernel.New(davin) failed: %v", err)
	}
	if engDavin.Type() != kernel.ModeDavin {
		t.Fatalf("kernel.New(davin) returned %q, want %q", engDavin.Type(), kernel.ModeDavin)
	}
	_ = engDavin.Close()

	// Case 4: Unregistered / unsupported modes matrix
	unregisteredModes := []string{
		"unknown",
		"wireguard",
		"openvpn",
		"davin2",
		"bacarra2",
		"custom",
		"proxy",
		"default",
	}
	for _, m := range unregisteredModes {
		t.Run("unregistered_"+m, func(t *testing.T) {
			cfg := &config.Config{Kernel: m}
			_, err := kernel.New(cfg, t.TempDir(), nil)
			if err == nil {
				t.Fatalf("kernel.New(%q) expected error, got nil", m)
			}
			if !strings.Contains(err.Error(), "unsupported or unregistered") {
				t.Errorf("kernel.New(%q) error %q does not contain 'unsupported or unregistered'", m, err)
			}
		})
	}

	// Case 5: Case Sensitivity Strictness
	casingTests := []string{
		"Davin",
		"DAVIN",
		"DaViN",
		"Bacarra",
		"BACARRA",
		"BaCarRa",
	}
	for _, c := range casingTests {
		t.Run("casing_"+c, func(t *testing.T) {
			cfg := &config.Config{Kernel: c}
			_, err := kernel.New(cfg, t.TempDir(), nil)
			if err == nil {
				t.Fatalf("kernel.New(%q) expected casing error, got nil", c)
			}
			if !strings.Contains(err.Error(), "unsupported or unregistered") {
				t.Errorf("kernel.New(%q) error %q does not contain 'unsupported or unregistered'", c, err)
			}
		})
	}

	// Case 6: Whitespace, tabs, newlines, control characters, null bytes
	adversarialStrings := []string{
		" davin",
		"davin ",
		" davin ",
		"\tdavin",
		"davin\n",
		"bacarra\r\n",
		"bacarra\x00",
		"davin\x00suffix",
		"   ",
		"davin;rm -rf /",
		"../davin",
	}
	for _, s := range adversarialStrings {
		t.Run(fmt.Sprintf("adversarial_%q", s), func(t *testing.T) {
			cfg := &config.Config{Kernel: s}
			_, err := kernel.New(cfg, t.TempDir(), nil)
			if err == nil {
				t.Fatalf("kernel.New(%q) expected error, got nil", s)
			}
			if !strings.Contains(err.Error(), "unsupported or unregistered") {
				t.Errorf("kernel.New(%q) error %q does not contain 'unsupported or unregistered'", s, err)
			}
		})
	}
}

// TestAdversarial_KernelRegistry_ConcurrentStress tests thread-safety of kernel driver registration
// and factory dispatch under high concurrent access.
func TestAdversarial_KernelRegistry_ConcurrentStress(t *testing.T) {
	const workers = 30
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		workerID := w
		go func() {
			defer wg.Done()
			customMode := kernel.Mode(fmt.Sprintf("stress-driver-%d", workerID))

			for i := 0; i < iterations; i++ {
				// Register driver
				kernel.Register(customMode, func(cfg *config.Config, stateDir string, logf func(string, ...any)) (kernel.Engine, error) {
					return &mockEngineStub{mode: customMode}, nil
				})

				// Read registered modes
				modes := kernel.RegisteredModes()
				if len(modes) < 2 {
					t.Errorf("RegisteredModes() returned fewer than 2 modes: %v", modes)
				}

				// Instantiate via kernel.New
				cfg := &config.Config{Kernel: string(customMode)}
				eng, err := kernel.New(cfg, "", nil)
				if err != nil {
					t.Errorf("kernel.New(%q) failed: %v", customMode, err)
				} else if eng.Type() != customMode {
					t.Errorf("eng.Type() = %q, want %q", eng.Type(), customMode)
				}
			}
		}()
	}

	wg.Wait()
}

type mockEngineStub struct {
	mode kernel.Mode
}

func (m *mockEngineStub) Type() kernel.Mode                                      { return m.mode }
func (m *mockEngineStub) Start(ctx context.Context) error                        { return nil }
func (m *mockEngineStub) Close() error                                           { return nil }
func (m *mockEngineStub) Reload(cfg *config.Config, rules *rule.Engine) error    { return nil }
func (m *mockEngineStub) Status() any                                            { return map[string]string{"mode": string(m.mode)} }
func (m *mockEngineStub) Components() []panel.Component                        { return nil }
func (m *mockEngineStub) Teardown() error                                        { return nil }

// =============================================================================
// Objective 2: Crash Recovery in TeardownStale Under Edge Cases
// =============================================================================

func TestAdversarial_TeardownStale_EdgeCases(t *testing.T) {
	// Case 2.1: Empty state directory string -> must return nil without error or panic
	t.Run("empty_dir_path", func(t *testing.T) {
		if err := bacarra.TeardownStale(""); err != nil {
			t.Fatalf("TeardownStale(\"\") returned error: %v", err)
		}
	})

	// Case 2.2: Non-existent directory path -> must return nil
	t.Run("non_existent_directory", func(t *testing.T) {
		nonExistent := filepath.Join(t.TempDir(), "deep", "nested", "path", "does_not_exist")
		if err := bacarra.TeardownStale(nonExistent); err != nil {
			t.Fatalf("TeardownStale(nonExistent) returned error: %v", err)
		}
	})

	// Case 2.3: Existing directory with missing state file -> must return nil
	t.Run("missing_state_file", func(t *testing.T) {
		tmpDir := t.TempDir()
		if err := bacarra.TeardownStale(tmpDir); err != nil {
			t.Fatalf("TeardownStale with missing file returned error: %v", err)
		}
	})

	// Case 2.4: 0-byte state file -> must report corrupt error AND purge file from disk
	t.Run("zero_byte_corrupt_file", func(t *testing.T) {
		tmpDir := t.TempDir()
		filePath := bacarra.StateFilePath(tmpDir)
		if err := os.WriteFile(filePath, []byte(""), 0600); err != nil {
			t.Fatalf("write 0-byte file: %v", err)
		}

		err := bacarra.TeardownStale(tmpDir)
		if err == nil {
			t.Fatal("expected error on 0-byte state file, got nil")
		}
		if !strings.Contains(err.Error(), "corrupt") {
			t.Errorf("error %q does not contain 'corrupt'", err.Error())
		}

		// File must be purged
		if _, err := os.Stat(filePath); !os.IsNotExist(err) {
			t.Fatalf("0-byte file was not purged: %v", err)
		}

		// Second call must return nil (self-healing idempotency)
		if err := bacarra.TeardownStale(tmpDir); err != nil {
			t.Fatalf("second TeardownStale call failed: %v", err)
		}
	})

	// Case 2.5: Syntactically corrupt JSON -> must report corrupt error AND purge file
	t.Run("malformed_json_syntax", func(t *testing.T) {
		tmpDir := t.TempDir()
		filePath := bacarra.StateFilePath(tmpDir)
		if err := os.WriteFile(filePath, []byte(`{"kernel": "bacarra", "routes": [ incomplete JSON ...`), 0600); err != nil {
			t.Fatalf("write malformed JSON: %v", err)
		}

		err := bacarra.TeardownStale(tmpDir)
		if err == nil {
			t.Fatal("expected error on malformed JSON, got nil")
		}
		if !strings.Contains(err.Error(), "corrupt") {
			t.Errorf("error %q does not contain 'corrupt'", err.Error())
		}

		// File must be purged
		if _, err := os.Stat(filePath); !os.IsNotExist(err) {
			t.Fatalf("malformed JSON file was not purged: %v", err)
		}

		// Second call must return nil
		if err := bacarra.TeardownStale(tmpDir); err != nil {
			t.Fatalf("second TeardownStale call failed: %v", err)
		}
	})

	// Case 2.6: Binary garbage payload -> must report corrupt error AND purge file
	t.Run("binary_garbage_payload", func(t *testing.T) {
		tmpDir := t.TempDir()
		filePath := bacarra.StateFilePath(tmpDir)
		garbage := []byte{0x00, 0xFF, 0xFE, 0x80, 0xDE, 0xAD, 0xBE, 0xEF}
		if err := os.WriteFile(filePath, garbage, 0600); err != nil {
			t.Fatalf("write binary garbage: %v", err)
		}

		err := bacarra.TeardownStale(tmpDir)
		if err == nil {
			t.Fatal("expected error on binary garbage, got nil")
		}
		if !strings.Contains(err.Error(), "corrupt") {
			t.Errorf("error %q does not contain 'corrupt'", err.Error())
		}

		if _, err := os.Stat(filePath); !os.IsNotExist(err) {
			t.Fatalf("binary garbage file was not purged: %v", err)
		}
	})

	// Case 2.7: JSON with unexpected kernel string (e.g. "davin")
	t.Run("unexpected_kernel_in_state", func(t *testing.T) {
		tmpDir := t.TempDir()
		filePath := bacarra.StateFilePath(tmpDir)
		if err := os.WriteFile(filePath, []byte(`{"kernel": "davin", "routes": []}`), 0600); err != nil {
			t.Fatalf("write state: %v", err)
		}

		err := bacarra.TeardownStale(tmpDir)
		if err == nil {
			t.Fatal("expected error on unexpected kernel in state file, got nil")
		}
		if !strings.Contains(err.Error(), "corrupt") {
			t.Errorf("error %q does not contain 'corrupt'", err.Error())
		}

		if _, err := os.Stat(filePath); !os.IsNotExist(err) {
			t.Fatalf("file with invalid kernel was not purged: %v", err)
		}
	})

	// Case 2.8: Valid JSON with empty routes slice []
	t.Run("empty_route_slice", func(t *testing.T) {
		tmpDir := t.TempDir()
		state := &bacarra.RouteState{
			Kernel:       "bacarra",
			AdapterName:  "tailscale0",
			AdapterIndex: 1,
			UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
			Routes:       []string{},
		}
		if err := bacarra.SaveRouteState(tmpDir, state); err != nil {
			t.Fatalf("SaveRouteState failed: %v", err)
		}

		// Must succeed with nil error and delete state file
		if err := bacarra.TeardownStale(tmpDir); err != nil {
			t.Fatalf("TeardownStale with empty routes failed: %v", err)
		}

		if _, err := os.Stat(bacarra.StateFilePath(tmpDir)); !os.IsNotExist(err) {
			t.Fatalf("state file was not purged after empty route teardown: %v", err)
		}
	})

	// Case 2.9: Valid JSON with null routes
	t.Run("null_route_slice", func(t *testing.T) {
		tmpDir := t.TempDir()
		filePath := bacarra.StateFilePath(tmpDir)
		if err := os.WriteFile(filePath, []byte(`{"kernel": "bacarra", "adapter_name": "tailscale0", "adapter_index": 1, "routes": null}`), 0600); err != nil {
			t.Fatalf("write null routes: %v", err)
		}

		if err := bacarra.TeardownStale(tmpDir); err != nil {
			t.Fatalf("TeardownStale with null routes failed: %v", err)
		}

		if _, err := os.Stat(filePath); !os.IsNotExist(err) {
			t.Fatalf("state file was not purged: %v", err)
		}
	})

	// Case 2.10: Malformed prefix strings in route list
	t.Run("malformed_prefix_strings_tolerated", func(t *testing.T) {
		tmpDir := t.TempDir()
		state := &bacarra.RouteState{
			Kernel:       "bacarra",
			AdapterName:  "tailscale0",
			AdapterIndex: 1,
			UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
			Routes: []string{
				"not-a-cidr",
				"999.999.999.999/99",
				"",
				"198.18.0.0/15",
			},
		}
		if err := bacarra.SaveRouteState(tmpDir, state); err != nil {
			t.Fatalf("SaveRouteState failed: %v", err)
		}

		// TeardownStale must not panic, should skip malformed prefixes, and clean up state file
		_ = bacarra.TeardownStale(tmpDir)

		if _, err := os.Stat(bacarra.StateFilePath(tmpDir)); !os.IsNotExist(err) {
			t.Fatalf("state file was not purged: %v", err)
		}
	})

	// Case 2.11: Non-existent adapter in state file
	t.Run("non_existent_adapter_in_state", func(t *testing.T) {
		tmpDir := t.TempDir()
		state := &bacarra.RouteState{
			Kernel:       "bacarra",
			AdapterName:  "ghost_adapter_9999",
			AdapterIndex: 999999,
			UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
			Routes: []string{
				"198.18.0.0/15",
			},
		}
		if err := bacarra.SaveRouteState(tmpDir, state); err != nil {
			t.Fatalf("SaveRouteState failed: %v", err)
		}

		// Must safely purge state file without panicking
		_ = bacarra.TeardownStale(tmpDir)

		if _, err := os.Stat(bacarra.StateFilePath(tmpDir)); !os.IsNotExist(err) {
			t.Fatalf("state file was not purged when adapter does not exist: %v", err)
		}
	})
}

// TestAdversarial_TeardownStale_ConcurrentInvocations tests that concurrent calls to
// TeardownStale on the same state directory execute cleanly without panics or races.
func TestAdversarial_TeardownStale_ConcurrentInvocations(t *testing.T) {
	tmpDir := t.TempDir()
	state := &bacarra.RouteState{
		Kernel:       "bacarra",
		AdapterName:  "tailscale0",
		AdapterIndex: 1,
		UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
		Routes: []string{
			"198.18.0.0/15",
			"fc00::/18",
		},
	}
	if err := bacarra.SaveRouteState(tmpDir, state); err != nil {
		t.Fatalf("SaveRouteState failed: %v", err)
	}

	const workers = 25
	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			_ = bacarra.TeardownStale(tmpDir)
		}()
	}

	wg.Wait()

	// State file must be unlinked
	if _, err := os.Stat(bacarra.StateFilePath(tmpDir)); !os.IsNotExist(err) {
		t.Fatalf("state file was not unlinked after concurrent TeardownStale")
	}

	// An immediate follow-up call must return nil
	if err := bacarra.TeardownStale(tmpDir); err != nil {
		t.Fatalf("follow-up TeardownStale call returned error: %v", err)
	}
}

// =============================================================================
// Objective 3: Idempotency of Engine.Close() and Engine.Teardown()
// =============================================================================

// TestAdversarial_DavinEngine_CloseAndTeardown_Idempotency verifies Davin mode under
// double-call, unstarted close, and concurrent invocation.
func TestAdversarial_DavinEngine_CloseAndTeardown_Idempotency(t *testing.T) {
	t.Run("unstarted_engine_close_idempotency", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := &config.Config{Kernel: "davin"}
		eng, err := davin.New(cfg, tmpDir, nil)
		if err != nil {
			t.Fatalf("davin.New failed: %v", err)
		}

		// Close without Start -> must succeed
		if err := eng.Close(); err != nil {
			t.Fatalf("first Close failed on unstarted engine: %v", err)
		}

		// Double Close -> must be idempotent
		if err := eng.Close(); err != nil {
			t.Fatalf("second Close failed on unstarted engine: %v", err)
		}

		// Teardown -> noop, must succeed
		if err := eng.Teardown(); err != nil {
			t.Fatalf("first Teardown failed: %v", err)
		}
		if err := eng.Teardown(); err != nil {
			t.Fatalf("second Teardown failed: %v", err)
		}
	})

	t.Run("started_engine_close_double_call", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := &config.Config{
			Kernel: "davin",
			Egress: []config.Egress{
				{Name: "slot-1"},
			},
		}
		eng, err := davin.New(cfg, tmpDir, nil)
		if err != nil {
			t.Fatalf("davin.New failed: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := eng.Start(ctx); err != nil {
			t.Fatalf("eng.Start failed: %v", err)
		}

		time.Sleep(10 * time.Millisecond)

		// First Close
		if err := eng.Close(); err != nil {
			t.Fatalf("first Close failed: %v", err)
		}

		// Second Close must not panic and must return nil
		if err := eng.Close(); err != nil {
			t.Fatalf("second Close failed: %v", err)
		}

		// Teardown after Close
		if err := eng.Teardown(); err != nil {
			t.Fatalf("Teardown failed: %v", err)
		}
	})

	t.Run("concurrent_close_stress", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := &config.Config{
			Kernel: "davin",
			Egress: []config.Egress{
				{Name: "slot-concurrent"},
			},
		}
		eng, err := davin.New(cfg, tmpDir, nil)
		if err != nil {
			t.Fatalf("davin.New failed: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := eng.Start(ctx); err != nil {
			t.Fatalf("eng.Start failed: %v", err)
		}

		time.Sleep(10 * time.Millisecond)

		const workers = 25
		var wg sync.WaitGroup
		wg.Add(workers)

		errCh := make(chan error, workers)

		for w := 0; w < workers; w++ {
			go func() {
				defer wg.Done()
				if err := eng.Close(); err != nil {
					errCh <- err
				}
			}()
		}

		wg.Wait()
		close(errCh)

		for err := range errCh {
			t.Errorf("concurrent Close returned error: %v", err)
		}
	})

	t.Run("concurrent_mixed_close_teardown_status", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := &config.Config{Kernel: "davin"}
		eng, err := davin.New(cfg, tmpDir, nil)
		if err != nil {
			t.Fatalf("davin.New failed: %v", err)
		}

		const workers = 20
		var wg sync.WaitGroup
		wg.Add(workers)

		for w := 0; w < workers; w++ {
			idx := w
			go func() {
				defer wg.Done()
				switch idx % 4 {
				case 0:
					_ = eng.Close()
				case 1:
					_ = eng.Teardown()
				case 2:
					_ = eng.Status()
				case 3:
					_ = eng.Components()
				}
			}()
		}

		wg.Wait()

		// Final Close and Teardown
		if err := eng.Close(); err != nil {
			t.Fatalf("final Close failed: %v", err)
		}
		if err := eng.Teardown(); err != nil {
			t.Fatalf("final Teardown failed: %v", err)
		}
	})
}

// TestAdversarial_BacarraEngine_CloseAndTeardown_Idempotency verifies Bacarra mode under
// double-call, unstarted close, and concurrent invocation.
func TestAdversarial_BacarraEngine_CloseAndTeardown_Idempotency(t *testing.T) {
	t.Run("unstarted_engine_close_and_teardown", func(t *testing.T) {
		tmpDir := t.TempDir()
		adapter := &bacarra.AdapterInfo{
			Name:  "tailscale0",
			Index: 1,
			IPs:   []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		}
		driver := newTestMemoryRouteDriver()
		rm, err := bacarra.NewRouteManagerWithDriver(adapter, tmpDir, nil, driver)
		if err != nil {
			t.Fatalf("NewRouteManagerWithDriver failed: %v", err)
		}

		cfg := &config.Config{
			Kernel: "bacarra",
			DNS: config.DNS{
				Mode: "fakeip",
			},
		}

		eng, err := bacarra.NewEngineWithManager(cfg, tmpDir, nil, adapter, rm)
		if err != nil {
			t.Fatalf("NewEngineWithManager failed: %v", err)
		}

		// Close without start
		if err := eng.Close(); err != nil {
			t.Fatalf("first Close failed: %v", err)
		}

		// Second Close must return nil immediately
		if err := eng.Close(); err != nil {
			t.Fatalf("second Close failed: %v", err)
		}

		// Teardown on clean state
		if err := eng.Teardown(); err != nil {
			t.Fatalf("first Teardown failed: %v", err)
		}
		if err := eng.Teardown(); err != nil {
			t.Fatalf("second Teardown failed: %v", err)
		}
	})

	t.Run("started_engine_double_close_and_teardown", func(t *testing.T) {
		tmpDir := t.TempDir()
		adapter := &bacarra.AdapterInfo{
			Name:  "tailscale0",
			Index: 1,
			IPs:   []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		}
		driver := newTestMemoryRouteDriver()
		rm, err := bacarra.NewRouteManagerWithDriver(adapter, tmpDir, nil, driver)
		if err != nil {
			t.Fatalf("NewRouteManagerWithDriver failed: %v", err)
		}

		cfg := &config.Config{
			Kernel: "bacarra",
			DNS: config.DNS{
				Mode: "fakeip",
			},
		}

		eng, err := bacarra.NewEngineWithManager(cfg, tmpDir, nil, adapter, rm)
		if err != nil {
			t.Fatalf("NewEngineWithManager failed: %v", err)
		}

		if err := eng.Start(context.Background()); err != nil {
			t.Fatalf("eng.Start failed: %v", err)
		}

		// Verify state file was created
		if _, err := bacarra.ReadRouteState(tmpDir); err != nil {
			t.Fatalf("ReadRouteState failed after Start: %v", err)
		}

		// First Close
		if err := eng.Close(); err != nil {
			t.Fatalf("first Close failed: %v", err)
		}

		// State file should be purged
		if _, err := bacarra.ReadRouteState(tmpDir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("state file was not purged after Close: %v", err)
		}

		// Second Close must return nil
		if err := eng.Close(); err != nil {
			t.Fatalf("second Close failed: %v", err)
		}

		// Teardown after Close
		if err := eng.Teardown(); err != nil {
			t.Fatalf("Teardown failed: %v", err)
		}
	})

	t.Run("concurrent_close_stress", func(t *testing.T) {
		tmpDir := t.TempDir()
		adapter := &bacarra.AdapterInfo{
			Name:  "tailscale0",
			Index: 1,
			IPs:   []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		}
		driver := newTestMemoryRouteDriver()
		rm, err := bacarra.NewRouteManagerWithDriver(adapter, tmpDir, nil, driver)
		if err != nil {
			t.Fatalf("NewRouteManagerWithDriver failed: %v", err)
		}

		cfg := &config.Config{
			Kernel: "bacarra",
			DNS: config.DNS{
				Mode: "fakeip",
			},
		}

		eng, err := bacarra.NewEngineWithManager(cfg, tmpDir, nil, adapter, rm)
		if err != nil {
			t.Fatalf("NewEngineWithManager failed: %v", err)
		}

		if err := eng.Start(context.Background()); err != nil {
			t.Fatalf("eng.Start failed: %v", err)
		}

		const workers = 30
		var wg sync.WaitGroup
		wg.Add(workers)

		errCh := make(chan error, workers)

		for w := 0; w < workers; w++ {
			go func() {
				defer wg.Done()
				if err := eng.Close(); err != nil {
					errCh <- err
				}
			}()
		}

		wg.Wait()
		close(errCh)

		for err := range errCh {
			t.Errorf("concurrent Close returned error: %v", err)
		}

		if len(rm.AppliedRoutes()) != 0 {
			t.Errorf("AppliedRoutes after concurrent Close: %v", rm.AppliedRoutes())
		}
	})

	t.Run("concurrent_mixed_close_teardown_status", func(t *testing.T) {
		tmpDir := t.TempDir()
		adapter := &bacarra.AdapterInfo{
			Name:  "tailscale0",
			Index: 1,
			IPs:   []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		}
		driver := newTestMemoryRouteDriver()
		rm, err := bacarra.NewRouteManagerWithDriver(adapter, tmpDir, nil, driver)
		if err != nil {
			t.Fatalf("NewRouteManagerWithDriver failed: %v", err)
		}

		cfg := &config.Config{
			Kernel: "bacarra",
			DNS: config.DNS{
				Mode: "fakeip",
			},
		}

		eng, err := bacarra.NewEngineWithManager(cfg, tmpDir, nil, adapter, rm)
		if err != nil {
			t.Fatalf("NewEngineWithManager failed: %v", err)
		}

		if err := eng.Start(context.Background()); err != nil {
			t.Fatalf("eng.Start failed: %v", err)
		}

		const workers = 40
		var wg sync.WaitGroup
		wg.Add(workers)

		for w := 0; w < workers; w++ {
			idx := w
			go func() {
				defer wg.Done()
				switch idx % 4 {
				case 0:
					_ = eng.Close()
				case 1:
					_ = eng.Teardown()
				case 2:
					_ = eng.Status()
				case 3:
					_ = eng.Components()
				}
			}()
		}

		wg.Wait()

		// Final checks
		if err := eng.Close(); err != nil {
			t.Fatalf("final Close failed: %v", err)
		}
		if err := eng.Teardown(); err != nil {
			t.Fatalf("final Teardown failed: %v", err)
		}
		if len(rm.AppliedRoutes()) != 0 {
			t.Errorf("AppliedRoutes after final Close: %v", rm.AppliedRoutes())
		}
	})
}
