//go:build darwin

package browserpolicy

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// macOS locations (tests point these at a temporary directory):
//   - Chrome / Edge read preferences of com.google.Chrome /
//     com.microsoft.Edge; values written with `defaults` outside a
//     configuration profile apply at the recommended level, not
//     mandatory (chromium.org Mac Quick Start). Mandatory policies need a
//     configuration profile (MDM), which this does not install.
//   - Firefox: Firefox.app/Contents/Resources/distribution/policies.json
//     (mozilla.github.io/policy-templates).
var (
	prefsDir = "/Library/Preferences"
	appsDir  = "/Applications"
)

func app(name string) bool {
	_, err := os.Stat(filepath.Join(appsDir, name))
	return err == nil
}

func targets(o Options) ([]target, error) {
	var ts []target
	add := func(browser, domain string, ech bool) {
		pol := chromePolicy(o, ech)
		for _, k := range []string{"DnsOverHttpsMode", "EncryptedClientHelloEnabled"} {
			if v, ok := pol[k]; ok {
				ts = append(ts, defaultsTarget(browser, filepath.Join(prefsDir, domain), k, v))
			}
		}
	}
	if o.All || app("Google Chrome.app") {
		add("Chrome", "com.google.Chrome", true)
	}
	if o.All || app("Microsoft Edge.app") {
		add("Edge", "com.microsoft.Edge", false)
	}
	if o.All || app("Firefox.app") {
		ts = append(ts, firefoxFile(filepath.Join(appsDir, "Firefox.app/Contents/Resources/distribution/policies.json")))
	}
	return ts, nil
}

func defaults(args ...string) (string, error) {
	out, err := exec.Command("/usr/bin/defaults", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("defaults %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// defaultsArgs turns a value into `defaults write` type flags.
func defaultsArgs(v any) []string {
	switch v := v.(type) {
	case bool:
		return []string{"-bool", fmt.Sprint(v)}
	case int:
		return []string{"-int", fmt.Sprint(v)}
	default:
		return []string{"-string", fmt.Sprint(v)}
	}
}

func defaultsTarget(browser, domain, key string, v any) target {
	return target{
		change: Change{Browser: browser, Where: domain + ".plist", What: fmt.Sprintf("%s = %v（推荐级别）", key, v)},
		apply: func() ([]undo, error) {
			u := undo{Kind: "defaults", Path: domain, Key: key}
			if prev, err := defaults("read", domain, key); err == nil {
				typ, err := defaults("read-type", domain, key)
				if err != nil {
					return nil, err
				}
				u.Existed, u.PrevType = true, strings.TrimPrefix(typ, "Type is ")
				u.Prev, _ = json.Marshal(prev)
			}
			if _, err := defaults(append([]string{"write", domain, key}, defaultsArgs(v)...)...); err != nil {
				return nil, err
			}
			return []undo{u}, nil
		},
	}
}

func revertOne(u undo) error {
	if u.Kind != "defaults" {
		return revertFile(u)
	}
	if !u.Existed {
		_, err := defaults("delete", u.Path, u.Key)
		return err
	}
	var prev string
	json.Unmarshal(u.Prev, &prev)
	var flag string
	switch u.PrevType {
	case "string":
		flag = "-string"
	case "boolean":
		flag, prev = "-bool", map[string]string{"1": "true", "0": "false"}[prev]
	case "integer":
		flag = "-int"
	default:
		return fmt.Errorf("cannot restore a %s value; set %s by hand", u.PrevType, u.Key)
	}
	_, err := defaults("write", u.Path, u.Key, flag, prev)
	return err
}

// DefaultStatePath is where Apply records its changes.
func DefaultStatePath() string { return "/var/db/tailproxy/browser-policy.json" }
