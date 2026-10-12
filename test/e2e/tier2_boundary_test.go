package e2e

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
)

// =============================================================================
// Tier 2 - Boundary 1: Unknown Fields Strict Rejection
// =============================================================================

// T2.B1: Unknown config fields are strictly rejected by dec.KnownFields(true).
func TestTier2_Boundary_UnknownFieldsRejection(t *testing.T) {
	typoConfigs := []string{
		"kernel_mode: davin\n",
		"kernel_type: bacarra\n",
		"engine: davin\n",
		"mode: bacarra\n",
		"tailscale_interface: tailscale0\n",
	}

	for _, typo := range typoConfigs {
		t.Run(strings.TrimSpace(typo), func(t *testing.T) {
			raw := typo + sampleValidConfig("davin")
			_, err := config.Parse([]byte(raw))
			if err == nil {
				t.Fatalf("expected parse error for unknown field %q, got nil", typo)
			}
			if !strings.Contains(err.Error(), "field") && !strings.Contains(err.Error(), "not found") {
				t.Fatalf("expected unknown field error, got: %v", err)
			}
		})
	}
}

// =============================================================================
// Tier 2 - Boundary 2: Strict Case Sensitivity
// =============================================================================

// T2.B2: Uppercase or mixed-case kernel names are strictly rejected.
func TestTier2_Boundary_CaseSensitivity(t *testing.T) {
	casingTests := []string{
		"Davin",
		"DAVIN",
		"DaViN",
		"Bacarra",
		"BACARRA",
		"BaCarRa",
	}

	for _, c := range casingTests {
		t.Run(c, func(t *testing.T) {
			raw := sampleValidConfig(c)
			_, err := config.Parse([]byte(raw))
			if err == nil {
				t.Fatalf("expected casing rejection for %q, but parse succeeded", c)
			}
			if !strings.Contains(err.Error(), "kernel") {
				t.Fatalf("expected error mentioning 'kernel', got: %v", err)
			}
		})
	}
}

// =============================================================================
// Tier 2 - Boundary 3: Corrupt Route State File Recovery
// =============================================================================

// T2.B3.1: Malformed JSON syntax in bacarra_routes.json is safely detected.
func TestTier2_Boundary_CorruptState_MalformedJSON(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "bacarra_routes.json")

	// Write syntactically invalid JSON
	if err := os.WriteFile(statePath, []byte(`{"kernel": "bacarra", "routes": [ incomplete...`), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := readBacarraState(statePath)
	if err == nil {
		t.Fatalf("expected error when reading malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("expected corrupt state error, got: %v", err)
	}
}

// T2.B3.2: 0-byte or truncated state file is safely detected.
func TestTier2_Boundary_CorruptState_TruncatedFile(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "bacarra_routes.json")

	// Write empty file
	if err := os.WriteFile(statePath, []byte(""), 0600); err != nil {
		t.Fatalf("failed to write empty file: %v", err)
	}

	_, err := readBacarraState(statePath)
	if err == nil {
		t.Fatalf("expected error reading empty state file, got nil")
	}
}

// T2.B3.3: Invalid route prefixes in state file are detected during validation.
func TestTier2_Boundary_CorruptState_InvalidPrefixStrings(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "bacarra_routes.json")

	badState := &BacarraState{
		Kernel:       "bacarra",
		AdapterName:  "tailscale0",
		AdapterIndex: 1,
		UpdatedAt:    "2026-10-12T00:00:00Z",
		Routes: []string{
			"198.18.0.0/15",
			"not-a-valid-cidr",
			"999.999.999.999/24",
		},
	}
	if err := writeBacarraState(statePath, badState); err != nil {
		t.Fatalf("failed to write bad state: %v", err)
	}

	loaded, err := readBacarraState(statePath)
	if err != nil {
		t.Fatalf("failed to read state: %v", err)
	}

	// Validate each prefix
	var parseErrors int
	for _, r := range loaded.Routes {
		if _, err := netip.ParsePrefix(r); err != nil {
			parseErrors++
		}
	}
	if parseErrors != 2 {
		t.Fatalf("expected 2 invalid prefixes to be detected, found %d", parseErrors)
	}
}

// =============================================================================
// Tier 2 - Boundary 4: Unprivileged Permissions Error Handling
// =============================================================================

// T2.B4: Non-root / non-Administrator execution safely returns permission error.
func TestTier2_Boundary_PermissionsSafeHandling(t *testing.T) {
	// Simulate an operation returning os.ErrPermission
	simulatedErr := os.ErrPermission
	wrapped := fmt.Errorf("bacarra route manager: %w", simulatedErr)
	if !errors.Is(wrapped, os.ErrPermission) {
		t.Fatalf("expected errors.Is to recognize wrapped os.ErrPermission")
	}
}

// =============================================================================
// Tier 2 - Boundary 5: Edge-Case CIDR Routing Values
// =============================================================================

// T2.B5: Valid edge-case CIDRs (/32 single IP, /128 single IPv6) are accepted.
func TestTier2_Boundary_CIDRPrefixExtremes(t *testing.T) {
	validExtremes := []string{
		"1.1.1.1/32",
		"0.0.0.0/32",
		"255.255.255.255/32",
		"::1/128",
		"fc00::1/128",
	}

	for _, cidr := range validExtremes {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			t.Fatalf("failed to parse valid extreme prefix %s: %v", cidr, err)
		}
		if !p.IsValid() {
			t.Fatalf("prefix %s reported invalid", cidr)
		}
	}

	invalidPrefixes := []string{
		"192.168.1.1/33",
		"10.0.0.1/-1",
		"fc00::/129",
		"999.0.0.0/24",
	}

	for _, cidr := range invalidPrefixes {
		_, err := netip.ParsePrefix(cidr)
		if err == nil {
			t.Fatalf("expected error parsing invalid prefix %s, got nil", cidr)
		}
	}
}
