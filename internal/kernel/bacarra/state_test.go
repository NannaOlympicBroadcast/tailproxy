package bacarra_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/kernel/bacarra"
)

func TestState_SaveAndRead(t *testing.T) {
	tmpDir := t.TempDir()

	original := &bacarra.RouteState{
		Kernel:       "bacarra",
		AdapterName:  "tailscale0",
		AdapterIndex: 42,
		UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
		Routes: []string{
			"198.18.0.0/15",
			"91.108.4.0/22",
			"fc00::/18",
		},
	}

	if err := bacarra.SaveRouteState(tmpDir, original); err != nil {
		t.Fatalf("SaveRouteState failed: %v", err)
	}

	loaded, err := bacarra.ReadRouteState(tmpDir)
	if err != nil {
		t.Fatalf("ReadRouteState failed: %v", err)
	}

	if loaded.Kernel != original.Kernel {
		t.Errorf("Kernel mismatch: got %q, want %q", loaded.Kernel, original.Kernel)
	}
	if loaded.AdapterName != original.AdapterName {
		t.Errorf("AdapterName mismatch: got %q, want %q", loaded.AdapterName, original.AdapterName)
	}
	if loaded.AdapterIndex != original.AdapterIndex {
		t.Errorf("AdapterIndex mismatch: got %d, want %d", loaded.AdapterIndex, original.AdapterIndex)
	}
	if len(loaded.Routes) != len(original.Routes) {
		t.Fatalf("Routes count mismatch: got %d, want %d", len(loaded.Routes), len(original.Routes))
	}
	for i, r := range loaded.Routes {
		if r != original.Routes[i] {
			t.Errorf("Route[%d] mismatch: got %q, want %q", i, r, original.Routes[i])
		}
	}
}

func TestState_SaveNilState(t *testing.T) {
	tmpDir := t.TempDir()
	if err := bacarra.SaveRouteState(tmpDir, nil); err == nil {
		t.Fatal("expected error saving nil state, got nil")
	}
}

func TestState_ReadNonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := bacarra.ReadRouteState(tmpDir)
	if err == nil {
		t.Fatal("expected error reading non-existent state file, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist, got: %v", err)
	}
}

func TestState_CorruptJSON(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := bacarra.StateFilePath(tmpDir)

	if err := os.WriteFile(filePath, []byte(`{"kernel": "bacarra", "routes": [ incomplete...`), 0600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	_, err := bacarra.ReadRouteState(tmpDir)
	if err == nil {
		t.Fatal("expected error reading malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("expected 'corrupt' in error message, got: %v", err)
	}
}

func TestState_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := bacarra.StateFilePath(tmpDir)

	if err := os.WriteFile(filePath, []byte(""), 0600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}

	_, err := bacarra.ReadRouteState(tmpDir)
	if err == nil {
		t.Fatal("expected error reading empty state file, got nil")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("expected 'corrupt' in error message, got: %v", err)
	}
}

func TestState_WrongKernel(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := bacarra.StateFilePath(tmpDir)

	badJSON := `{"kernel": "davin", "adapter_name": "tailscale0", "routes": []}`
	if err := os.WriteFile(filePath, []byte(badJSON), 0600); err != nil {
		t.Fatalf("write bad kernel JSON: %v", err)
	}

	_, err := bacarra.ReadRouteState(tmpDir)
	if err == nil {
		t.Fatal("expected error for mismatched kernel mode, got nil")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("expected 'corrupt' in error message, got: %v", err)
	}
}

func TestState_Remove(t *testing.T) {
	tmpDir := t.TempDir()

	state := &bacarra.RouteState{
		Kernel:      "bacarra",
		AdapterName: "tailscale0",
		Routes:      []string{"198.18.0.0/15"},
	}
	if err := bacarra.SaveRouteState(tmpDir, state); err != nil {
		t.Fatalf("save state: %v", err)
	}

	// Remove existing state file
	if err := bacarra.RemoveRouteState(tmpDir); err != nil {
		t.Fatalf("RemoveRouteState failed: %v", err)
	}

	targetPath := bacarra.StateFilePath(tmpDir)
	if _, err := os.Stat(targetPath); !os.IsNotExist(err) {
		t.Errorf("expected state file to be deleted, but stat returned: %v", err)
	}

	// Idempotent removal: removing already non-existent file should succeed without error
	if err := bacarra.RemoveRouteState(tmpDir); err != nil {
		t.Errorf("RemoveRouteState second call failed: %v", err)
	}
}

func TestState_StateFilePath(t *testing.T) {
	dir := "test_state_dir"
	expected := filepath.Join(dir, "bacarra_routes.json")
	if got := bacarra.StateFilePath(dir); got != expected {
		t.Errorf("StateFilePath: got %q, want %q", got, expected)
	}
}
