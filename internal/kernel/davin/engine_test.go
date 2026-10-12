package davin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/kernel"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
)

func TestDavinEngine(t *testing.T) {
	stateDir := t.TempDir()
	cfg := &config.Config{
		Kernel: "davin",
		Egress: []config.Egress{
			{Name: "direct-slot"},
		},
	}

	// Verify factory registration via kernel.New
	engGeneric, err := kernel.New(cfg, stateDir, nil)
	if err != nil {
		t.Fatalf("kernel.New(davin) error: %v", err)
	}

	eng, ok := engGeneric.(*Engine)
	if !ok {
		t.Fatalf("kernel.New returned type %T, want *Engine", engGeneric)
	}

	if eng.Type() != kernel.ModeDavin {
		t.Errorf("eng.Type() = %q, want %q", eng.Type(), kernel.ModeDavin)
	}

	if eng.Manager() == nil {
		t.Error("eng.Manager() is nil")
	}
	if eng.Router() == nil {
		t.Error("eng.Router() is nil")
	}
	if eng.Tracker() == nil {
		t.Error("eng.Tracker() is nil")
	}

	comps := eng.Components()
	if len(comps) < 2 {
		t.Fatalf("expected at least 2 components, got %d", len(comps))
	}
	if comps[0].Name != "kernel" || comps[0].State != "running" {
		t.Errorf("first component = %+v, want kernel running", comps[0])
	}
	if comps[1].Name != "egress_manager" {
		t.Errorf("second component = %+v, want egress_manager", comps[1])
	}

	if status := eng.Status(); status == nil {
		t.Error("eng.Status() is nil")
	}

	// Test Reload
	rulesEngine, err := rule.Compile([]config.Rule{
		{Final: "direct"},
	})
	if err != nil {
		t.Fatalf("rule.Compile error: %v", err)
	}
	if err := eng.Reload(cfg, rulesEngine); err != nil {
		t.Fatalf("eng.Reload error: %v", err)
	}
	if eng.Router().Rules == nil || eng.Router().Rules() != rulesEngine {
		t.Error("eng.Router().Rules was not updated by Reload")
	}

	if err := eng.Teardown(); err != nil {
		t.Errorf("eng.Teardown() error: %v", err)
	}

	// Lifecycle test
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := eng.Start(ctx); err != nil {
		t.Fatalf("eng.Start error: %v", err)
	}

	// Wait brief moment for start
	time.Sleep(20 * time.Millisecond)

	if err := eng.Close(); err != nil {
		t.Fatalf("eng.Close error: %v", err)
	}
}

func TestDavinNew_InvalidConfig(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "nonexistent", "subdir")
	_ = os.MkdirAll(t.TempDir(), 0o700)
	// Invalid egress configuration (e.g. invalid name or setup)
	cfg := &config.Config{
		Kernel: "davin",
	}
	eng, err := New(cfg, stateDir, nil)
	if err != nil {
		t.Fatalf("New with empty egress shouldn't fail, got %v", err)
	}
	_ = eng.Close()
}
