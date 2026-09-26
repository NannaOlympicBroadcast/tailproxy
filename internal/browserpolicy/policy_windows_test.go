//go:build windows

package browserpolicy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// The real registry, under an HKCU scratch key instead of HKLM.
func TestApplyRevertWindows(t *testing.T) {
	base := fmt.Sprintf(`Software\tailproxy-test-%d`, os.Getpid())
	regRoot, regBase = registry.CURRENT_USER, base+`\Policies`
	defer func() {
		regRoot, regBase = registry.LOCAL_MACHINE, `SOFTWARE\Policies`
		for _, k := range []string{`\Policies\Microsoft\Edge`, `\Policies\Microsoft`, `\Policies`} {
			registry.DeleteKey(registry.CURRENT_USER, base+k)
		}
		registry.DeleteKey(registry.CURRENT_USER, base)
	}()
	state := filepath.Join(t.TempDir(), "state.json")
	// An existing Edge value is put back on revert.
	k, _, err := createKey(regBase + `\Microsoft\Edge`)
	if err != nil {
		t.Fatal(err)
	}
	k.SetStringValue("DnsOverHttpsMode", "automatic")
	k.Close()

	if _, err := Apply(Options{DisableECH: true}, state); err != nil {
		t.Fatal(err)
	}
	get := func(path, name string) (string, error) {
		k, err := registry.OpenKey(regRoot, regBase+`\`+path, registry.QUERY_VALUE)
		if err != nil {
			return "", err
		}
		defer k.Close()
		if s, _, err := k.GetStringValue(name); err == nil {
			return s, nil
		}
		d, _, err := k.GetIntegerValue(name)
		return fmt.Sprint(d), err
	}
	for _, c := range []struct{ path, name, want string }{
		{`Google\Chrome`, "DnsOverHttpsMode", "off"},
		{`Google\Chrome`, "EncryptedClientHelloEnabled", "0"},
		{`Microsoft\Edge`, "DnsOverHttpsMode", "off"},
		{`Mozilla\Firefox\DNSOverHTTPS`, "Enabled", "0"},
		{`Mozilla\Firefox\DNSOverHTTPS`, "Locked", "1"},
	} {
		if got, err := get(c.path, c.name); err != nil || got != c.want {
			t.Errorf("%s\\%s = %q %v, want %q", c.path, c.name, got, err, c.want)
		}
	}

	if _, err := Revert(state); err != nil {
		t.Fatal(err)
	}
	if got, err := get(`Microsoft\Edge`, "DnsOverHttpsMode"); err != nil || got != "automatic" {
		t.Fatalf("Edge after revert = %q %v", got, err)
	}
	for _, p := range []string{`Google`, `Mozilla`} {
		if _, err := registry.OpenKey(regRoot, regBase+`\`+p, registry.QUERY_VALUE); !errors.Is(err, registry.ErrNotExist) {
			t.Errorf("key %s left after revert: %v", p, err)
		}
	}
}
