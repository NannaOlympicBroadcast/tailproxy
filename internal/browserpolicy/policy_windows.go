//go:build windows

package browserpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Windows locations: machine policies under HKLM\SOFTWARE\Policies:
//   - Chrome: Google\Chrome (support.google.com/chrome/a/answer/9131254).
//   - Edge: Microsoft\Edge, DnsOverHttpsMode REG_SZ (learn.microsoft.com
//     deployedge DnsOverHttpsMode).
//   - Firefox: Mozilla\Firefox\DNSOverHTTPS, Enabled / Locked DWORD
//     (mozilla.github.io/policy-templates, Windows GPO).
//
// Policies for a browser that is not installed are harmless, so all three
// are written. Tests use another base key.
var (
	regRoot = registry.LOCAL_MACHINE
	regBase = `SOFTWARE\Policies`
)

func targets(o Options) ([]target, error) {
	var ts []target
	pol := chromePolicy(o, true)
	ts = append(ts, regTarget("Chrome", `Google\Chrome`, "DnsOverHttpsMode", pol["DnsOverHttpsMode"]))
	if v, ok := pol["EncryptedClientHelloEnabled"]; ok {
		ts = append(ts, regTarget("Chrome", `Google\Chrome`, "EncryptedClientHelloEnabled", v))
	}
	ts = append(ts,
		regTarget("Edge", `Microsoft\Edge`, "DnsOverHttpsMode", "off"),
		regTarget("Firefox", `Mozilla\Firefox\DNSOverHTTPS`, "Enabled", false),
		regTarget("Firefox", `Mozilla\Firefox\DNSOverHTTPS`, "Locked", true))
	return ts, nil
}

func regWhere(sub string) string {
	root := "HKLM"
	if regRoot == registry.CURRENT_USER {
		root = "HKCU"
	}
	return root + `\` + regBase + `\` + sub
}

// createKey opens path, creating missing keys, and returns the ones it
// created (deepest first).
func createKey(path string) (registry.Key, []string, error) {
	parts := strings.Split(path, `\`)
	var created []string
	for i := range parts {
		p := strings.Join(parts[:i+1], `\`)
		k, existed, err := registry.CreateKey(regRoot, p, registry.ALL_ACCESS)
		if err != nil {
			return 0, nil, err
		}
		if !existed {
			created = append([]string{p}, created...)
		}
		if i < len(parts)-1 {
			k.Close()
		} else {
			return k, created, nil
		}
	}
	return 0, nil, errors.New("empty key path")
}

func regTarget(browser, sub, name string, v any) target {
	path := regBase + `\` + sub
	return target{
		change: Change{Browser: browser, Where: regWhere(sub), What: fmt.Sprintf("%s = %v", name, v)},
		apply: func() ([]undo, error) {
			k, created, err := createKey(path)
			if err != nil {
				return nil, err
			}
			defer k.Close()
			u := undo{Kind: "reg", Path: path, Key: name, Dirs: created}
			if s, _, err := k.GetStringValue(name); err == nil {
				u.Existed, u.PrevType = true, "string"
				u.Prev, _ = json.Marshal(s)
			} else if d, _, err := k.GetIntegerValue(name); err == nil {
				u.Existed, u.PrevType = true, "dword"
				u.Prev, _ = json.Marshal(d)
			}
			switch v := v.(type) {
			case bool:
				d := uint32(0)
				if v {
					d = 1
				}
				err = k.SetDWordValue(name, d)
			default:
				err = k.SetStringValue(name, fmt.Sprint(v))
			}
			if err != nil {
				return nil, err
			}
			return []undo{u}, nil
		},
	}
}

func revertOne(u undo) error {
	if u.Kind != "reg" {
		return revertFile(u)
	}
	k, err := registry.OpenKey(regRoot, u.Path, registry.ALL_ACCESS)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	switch {
	case !u.Existed:
		err = k.DeleteValue(u.Key)
		if errors.Is(err, registry.ErrNotExist) {
			err = nil
		}
	case u.PrevType == "string":
		var s string
		json.Unmarshal(u.Prev, &s)
		err = k.SetStringValue(u.Key, s)
	default:
		var d uint64
		json.Unmarshal(u.Prev, &d)
		err = k.SetDWordValue(u.Key, uint32(d))
	}
	k.Close()
	for _, p := range u.Dirs { // deepest first; fails (harmlessly) if not empty
		registry.DeleteKey(regRoot, p)
	}
	return err
}

// DefaultStatePath is where Apply records its changes.
func DefaultStatePath() string {
	dir := os.Getenv("ProgramData")
	if dir == "" {
		dir = `C:\ProgramData`
	}
	return filepath.Join(dir, "tailproxy", "browser-policy.json")
}
