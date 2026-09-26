//go:build linux

package browserpolicy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestApplyRevertLinux(t *testing.T) {
	root = t.TempDir()
	defer func() { root = "/" }()
	state := filepath.Join(t.TempDir(), "state.json")
	ff := filepath.Join(root, "etc/firefox/policies/policies.json")
	os.MkdirAll(filepath.Dir(ff), 0o755)
	os.WriteFile(ff, []byte(`{"policies":{"DisableTelemetry":true,"DNSOverHTTPS":{"Enabled":true}}}`), 0o644)

	plan, err := Plan(Options{All: true, DisableECH: true})
	if err != nil || len(plan) != 5 {
		t.Fatalf("plan: %v %v", plan, err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/opt")); err == nil {
		t.Fatal("Plan wrote something")
	}
	if _, err := Apply(Options{All: true, DisableECH: true}, state); err != nil {
		t.Fatal(err)
	}
	chrome := readJSON(t, filepath.Join(root, "etc/opt/chrome/policies/managed/tailproxy.json"))
	if chrome["DnsOverHttpsMode"] != "off" || chrome["EncryptedClientHelloEnabled"] != false {
		t.Fatalf("chrome policy %v", chrome)
	}
	edge := readJSON(t, filepath.Join(root, "etc/opt/edge/policies/managed/tailproxy.json"))
	if edge["DnsOverHttpsMode"] != "off" || edge["EncryptedClientHelloEnabled"] != nil {
		t.Fatalf("edge policy %v", edge)
	}
	for _, d := range []string{"etc/chromium", "etc/chromium-browser"} {
		if _, err := os.Stat(filepath.Join(root, d, "policies/managed/tailproxy.json")); err != nil {
			t.Fatal(err)
		}
	}
	pol := readJSON(t, ff)["policies"].(map[string]any)
	if pol["DisableTelemetry"] != true {
		t.Fatal("other Firefox policy lost")
	}
	if d := pol["DNSOverHTTPS"].(map[string]any); d["Enabled"] != false || d["Locked"] != true {
		t.Fatalf("firefox DNSOverHTTPS %v", d)
	}
	if _, err := Apply(Options{All: true}, state); !errors.Is(err, ErrApplied) {
		t.Fatalf("second apply: %v", err)
	}

	if _, err := Revert(state); err != nil {
		t.Fatal(err)
	}
	pol = readJSON(t, ff)["policies"].(map[string]any)
	if d := pol["DNSOverHTTPS"].(map[string]any); d["Enabled"] != true || d["Locked"] != nil || pol["DisableTelemetry"] != true {
		t.Fatalf("firefox after revert %v", pol)
	}
	// Owned files and the directories created for them are gone; /etc
	// itself (it existed... in the temp root it was created with firefox's
	// directory) stays.
	for _, d := range []string{"etc/opt", "etc/chromium", "etc/chromium-browser"} {
		if _, err := os.Stat(filepath.Join(root, d)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left after revert", d)
		}
	}
	if _, err := Revert(state); !errors.Is(err, ErrNotApplied) {
		t.Fatalf("second revert: %v", err)
	}
}

// A failure part way undoes what was written, and a Firefox file tailproxy
// created is removed on revert.
func TestApplyRollbackLinux(t *testing.T) {
	root = t.TempDir()
	defer func() { root = "/" }()
	state := filepath.Join(t.TempDir(), "state.json")
	// Edge's file is in the way (targets run Chrome, Chromium, Edge, Firefox).
	blocker := filepath.Join(root, "etc/opt/edge/policies/managed/tailproxy.json")
	os.MkdirAll(filepath.Dir(blocker), 0o755)
	os.WriteFile(blocker, []byte("{}"), 0o644)
	if _, err := Apply(Options{All: true}, state); err == nil {
		t.Fatal("apply over an existing file succeeded")
	}
	for _, p := range []string{"etc/opt/chrome", "etc/chromium", "etc/chromium-browser", "etc/firefox"} {
		if _, err := os.Stat(filepath.Join(root, p)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left after a failed apply", p)
		}
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("state saved for a failed apply")
	}
	os.Remove(blocker)
	if _, err := Apply(Options{All: true}, state); err != nil {
		t.Fatal(err)
	}
	if _, err := Revert(state); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/firefox")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("created Firefox policies left after revert")
	}
}

// Without --all-browsers only installed browsers are written.
func TestDetectLinux(t *testing.T) {
	root = t.TempDir()
	defer func() { root = "/" }()
	t.Setenv("PATH", t.TempDir())
	os.MkdirAll(filepath.Join(root, "opt/google/chrome"), 0o755)
	plan, err := Plan(Options{})
	if err != nil || len(plan) != 1 || plan[0].Browser != "Chrome" {
		t.Fatalf("plan with only Chrome installed: %v %v", plan, err)
	}
}
