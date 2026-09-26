//go:build darwin

package browserpolicy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Real `defaults` on plists in a temporary directory (no root needed).
func TestApplyRevertDarwin(t *testing.T) {
	prefsDir, appsDir = t.TempDir(), t.TempDir()
	defer func() { prefsDir, appsDir = "/Library/Preferences", "/Applications" }()
	state := filepath.Join(t.TempDir(), "state.json")
	chrome := filepath.Join(prefsDir, "com.google.Chrome")
	if _, err := defaults("write", chrome, "DnsOverHttpsMode", "-string", "secure"); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(appsDir, "Firefox.app/Contents/Resources"), 0o755)
	os.MkdirAll(filepath.Join(appsDir, "Google Chrome.app"), 0o755)

	changes, err := Apply(Options{DisableECH: true}, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("applied: %+v", changes)
	if v, err := defaults("read", chrome, "DnsOverHttpsMode"); err != nil || v != "off" {
		t.Fatalf("DnsOverHttpsMode = %q %v", v, err)
	}
	if v, err := defaults("read", chrome, "EncryptedClientHelloEnabled"); err != nil || v != "0" {
		t.Fatalf("EncryptedClientHelloEnabled = %q %v", v, err)
	}
	if _, err := defaults("read", filepath.Join(prefsDir, "com.microsoft.Edge"), "DnsOverHttpsMode"); err == nil {
		t.Fatal("Edge written though not installed")
	}
	ff := filepath.Join(appsDir, "Firefox.app/Contents/Resources/distribution/policies.json")
	if _, err := os.Stat(ff); err != nil {
		t.Fatal(err)
	}

	if _, err := Revert(state); err != nil {
		t.Fatal(err)
	}
	if v, err := defaults("read", chrome, "DnsOverHttpsMode"); err != nil || v != "secure" {
		t.Fatalf("DnsOverHttpsMode after revert = %q %v", v, err)
	}
	if _, err := defaults("read", chrome, "EncryptedClientHelloEnabled"); err == nil {
		t.Fatal("EncryptedClientHelloEnabled left after revert")
	}
	if _, err := os.Stat(filepath.Dir(ff)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Firefox distribution directory left after revert")
	}
}
