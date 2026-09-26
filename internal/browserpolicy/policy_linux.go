//go:build linux

package browserpolicy

import (
	"os"
	"os/exec"
	"path/filepath"
)

// root prefixes every path (tests use a temporary directory).
var root = "/"

// Linux locations:
//   - Chrome: /etc/opt/chrome/policies/managed/*.json (chromium.org
//     Linux Quick Start).
//   - Chromium: /etc/chromium/policies/managed; Ubuntu's package reads
//     /etc/chromium-browser/policies instead (same page).
//   - Edge: /etc/opt/edge/policies/managed (Microsoft Q&A answer; the
//     directory Edge on Linux reads, per edge://policy).
//   - Firefox: /etc/firefox/policies/policies.json, system-wide
//     (mozilla.github.io/policy-templates).
const ownedName = "tailproxy.json"

func installed(bins []string, paths []string) bool {
	for _, b := range bins {
		if _, err := exec.LookPath(b); err == nil {
			return true
		}
	}
	for _, p := range paths {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			return true
		}
	}
	return false
}

func targets(o Options) ([]target, error) {
	var ts []target
	p := func(s string) string { return filepath.Join(root, s) }
	if o.All || installed([]string{"google-chrome", "google-chrome-stable", "google-chrome-beta"}, []string{"opt/google/chrome"}) {
		ts = append(ts, ownedFile("Chrome", p("etc/opt/chrome/policies/managed/"+ownedName), chromePolicy(o, true)))
	}
	if o.All || installed([]string{"chromium", "chromium-browser"}, nil) {
		ts = append(ts,
			ownedFile("Chromium", p("etc/chromium/policies/managed/"+ownedName), chromePolicy(o, true)),
			ownedFile("Chromium", p("etc/chromium-browser/policies/managed/"+ownedName), chromePolicy(o, true)))
	}
	if o.All || installed([]string{"microsoft-edge", "microsoft-edge-stable"}, []string{"opt/microsoft/msedge"}) {
		ts = append(ts, ownedFile("Edge", p("etc/opt/edge/policies/managed/"+ownedName), chromePolicy(o, false)))
	}
	if o.All || installed([]string{"firefox", "firefox-esr"}, []string{"usr/lib/firefox", "usr/lib/firefox-esr", "opt/firefox"}) {
		ts = append(ts, firefoxFile(p("etc/firefox/policies/policies.json")))
	}
	return ts, nil
}

func revertOne(u undo) error { return revertFile(u) }

// DefaultStatePath is where Apply records its changes.
func DefaultStatePath() string { return "/var/lib/tailproxy/browser-policy.json" }
