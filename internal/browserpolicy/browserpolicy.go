// Package browserpolicy writes and removes the browser policies of DESIGN
// §4.8 L5: DNS over HTTPS off in Chrome, Chromium, Edge and Firefox (and,
// optionally, Encrypted ClientHello off in Chrome), so browsers use the
// system resolver (tailproxy) instead of their own DoH. It only runs when
// the user asks (`tailproxy doctor --apply-browser-policy`), and every
// change is journaled so Revert puts back exactly what was there.
//
// Policy names and values:
//   - Chrome / Chromium / Edge DnsOverHttpsMode = "off" (string-enum;
//     Chromium policy_definitions/Miscellaneous/DnsOverHttpsMode.yaml; Edge:
//     learn.microsoft.com/deployedge/microsoft-edge-browser-policies/dnsoverhttpsmode).
//   - Chrome EncryptedClientHelloEnabled = false (boolean; Chromium
//     policy_definitions/Miscellaneous/EncryptedClientHelloEnabled.yaml).
//   - Firefox DNSOverHTTPS {Enabled: false, Locked: true}
//     (mozilla.github.io/policy-templates, DNSOverHTTPS).
package browserpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Options select what is written.
type Options struct {
	// DisableECH also sets Chrome's EncryptedClientHelloEnabled to false.
	DisableECH bool
	// All writes policies for every supported browser, installed or not.
	All bool
}

// Change is one policy write, for printing before and after.
type Change struct {
	Browser string `json:"browser"`
	Where   string `json:"where"`
	What    string `json:"what"`
}

// undo is one journaled change; Revert replays the journal backwards.
type undo struct {
	Kind string `json:"kind"` // file, jsonkey, reg, defaults
	Path string `json:"path"`
	Key  string `json:"key,omitempty"`
	// Existed is whether the file / value existed before; Prev its value
	// (JSON for jsonkey, the registry or defaults value as text), PrevType
	// its type (registry: string/dword; defaults: string/boolean/integer).
	Existed  bool            `json:"existed"`
	Prev     json.RawMessage `json:"prev,omitempty"`
	PrevType string          `json:"prev_type,omitempty"`
	// Dirs this change created, removed on revert when empty.
	Dirs []string `json:"dirs,omitempty"`
}

type state struct {
	Changes []Change `json:"changes"`
	Undo    []undo   `json:"undo"`
}

// ErrApplied is returned by Apply when policies are already applied.
var ErrApplied = errors.New("browser policies are already applied (revert them first)")

// ErrNotApplied is returned by Revert when there is nothing to revert.
var ErrNotApplied = errors.New("no browser policies applied by tailproxy")

// Plan lists what Apply would write.
func Plan(o Options) ([]Change, error) {
	ts, err := targets(o)
	if err != nil {
		return nil, err
	}
	var out []Change
	for _, t := range ts {
		out = append(out, t.change)
	}
	return out, nil
}

// Apply writes the policies and records how to undo them in statePath.
// On a partial failure what was written is undone again.
func Apply(o Options, statePath string) ([]Change, error) {
	if _, err := os.Stat(statePath); err == nil {
		return nil, ErrApplied
	}
	ts, err := targets(o)
	if err != nil {
		return nil, err
	}
	if len(ts) == 0 {
		return nil, errors.New("no supported browser found (use --all-browsers to write the policies anyway)")
	}
	var st state
	for _, t := range ts {
		u, err := t.apply()
		if err != nil {
			rollback(st.Undo)
			return nil, fmt.Errorf("%s: %s: %w", t.change.Browser, t.change.Where, err)
		}
		st.Changes = append(st.Changes, t.change)
		st.Undo = append(st.Undo, u...)
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err == nil {
		err = os.WriteFile(statePath, b, 0o600)
	}
	if err != nil {
		rollback(st.Undo)
		return nil, fmt.Errorf("save %s: %w", statePath, err)
	}
	return st.Changes, nil
}

// Revert undoes what Apply recorded in statePath.
func Revert(statePath string) ([]Change, error) {
	b, err := os.ReadFile(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotApplied
	} else if err != nil {
		return nil, err
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("%s: %w", statePath, err)
	}
	if err := rollback(st.Undo); err != nil {
		return nil, err
	}
	return st.Changes, os.Remove(statePath)
}

func rollback(us []undo) error {
	var errs []error
	for i := len(us) - 1; i >= 0; i-- {
		if err := revertOne(us[i]); err != nil {
			errs = append(errs, fmt.Errorf("%s %s %s: %w", us[i].Kind, us[i].Path, us[i].Key, err))
		}
	}
	return errors.Join(errs...)
}

// target is one policy location.
type target struct {
	change Change
	apply  func() ([]undo, error)
}

// mkdirs creates dir and returns the directories it created.
func mkdirs(dir string) ([]string, error) {
	var created []string
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(d); err == nil {
			break
		}
		created = append(created, d)
		if filepath.Dir(d) == d {
			break
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return created, nil
}

func removeDirs(dirs []string) {
	for _, d := range dirs { // deepest first
		os.Remove(d) // only if empty
	}
}

// ownedFile writes a JSON policy file tailproxy owns (Chromium-based
// browsers on Linux read every *.json in their managed directory).
func ownedFile(browser, path string, policy map[string]any) target {
	b, _ := json.Marshal(policy)
	return target{
		change: Change{Browser: browser, Where: path, What: string(b)},
		apply: func() ([]undo, error) {
			if _, err := os.Stat(path); err == nil {
				return nil, fmt.Errorf("%s already exists", path)
			}
			dirs, err := mkdirs(filepath.Dir(path))
			if err != nil {
				return nil, err
			}
			if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
				removeDirs(dirs)
				return nil, err
			}
			return []undo{{Kind: "file", Path: path, Dirs: dirs}}, nil
		},
	}
}

// firefoxFile sets policies.DNSOverHTTPS in a Firefox policies.json,
// keeping the file's other policies.
func firefoxFile(path string) target {
	val := map[string]any{"Enabled": false, "Locked": true}
	vb, _ := json.Marshal(val)
	return target{
		change: Change{Browser: "Firefox", Where: path, What: `policies.DNSOverHTTPS = ` + string(vb)},
		apply: func() ([]undo, error) {
			u := undo{Kind: "jsonkey", Path: path, Key: "DNSOverHTTPS"}
			doc := map[string]any{}
			b, err := os.ReadFile(path)
			switch {
			case err == nil:
				u.Existed = true
				if err := json.Unmarshal(b, &doc); err != nil {
					return nil, fmt.Errorf("existing file is not JSON: %w", err)
				}
			case errors.Is(err, os.ErrNotExist):
				if u.Dirs, err = mkdirs(filepath.Dir(path)); err != nil {
					return nil, err
				}
			default:
				return nil, err
			}
			pol, _ := doc["policies"].(map[string]any)
			if pol == nil {
				pol = map[string]any{}
			}
			if prev, ok := pol["DNSOverHTTPS"]; ok {
				u.Prev, _ = json.Marshal(prev)
			}
			pol["DNSOverHTTPS"] = val
			doc["policies"] = pol
			out, _ := json.MarshalIndent(doc, "", "  ")
			if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
				removeDirs(u.Dirs)
				return nil, err
			}
			return []undo{u}, nil
		},
	}
}

func revertFile(u undo) error {
	switch u.Kind {
	case "file":
		if err := os.Remove(u.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		removeDirs(u.Dirs)
		return nil
	case "jsonkey":
		b, err := os.ReadFile(u.Path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		doc := map[string]any{}
		if err := json.Unmarshal(b, &doc); err != nil {
			return err
		}
		pol, _ := doc["policies"].(map[string]any)
		if pol == nil {
			pol = map[string]any{}
		}
		if len(u.Prev) > 0 {
			var prev any
			json.Unmarshal(u.Prev, &prev)
			pol[u.Key] = prev
		} else {
			delete(pol, u.Key)
		}
		if !u.Existed && len(pol) == 0 && len(doc) == 1 {
			if err := os.Remove(u.Path); err != nil {
				return err
			}
			removeDirs(u.Dirs)
			return nil
		}
		doc["policies"] = pol
		out, _ := json.MarshalIndent(doc, "", "  ")
		return os.WriteFile(u.Path, append(out, '\n'), 0o644)
	}
	return fmt.Errorf("unknown change kind %q", u.Kind)
}

// chromePolicy is the policy set for Chromium-based browsers.
func chromePolicy(o Options, ech bool) map[string]any {
	p := map[string]any{"DnsOverHttpsMode": "off"}
	if o.DisableECH && ech {
		p["EncryptedClientHelloEnabled"] = false
	}
	return p
}
