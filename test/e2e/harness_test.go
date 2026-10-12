package e2e

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
	"tailscale.com/net/tsaddr"
)

// BacarraState represents the schema of <stateDir>/bacarra_routes.json.
type BacarraState struct {
	Kernel       string   `json:"kernel"`
	AdapterName  string   `json:"adapter_name"`
	AdapterIndex int      `json:"adapter_index"`
	UpdatedAt    string   `json:"updated_at"`
	Routes       []string `json:"routes"`
}

// sampleValidConfig generates a complete, valid tailproxy YAML configuration string.
func sampleValidConfig(kernel string) string {
	kernelLine := ""
	if kernel != "" {
		kernelLine = fmt.Sprintf("kernel: %s\n", kernel)
	}
	return kernelLine + `
tailnet:
  hostname: testproxy
  control_url: https://controlplane.tailscale.com
  auth_key_env: TS_AUTHKEY
  state_dir: ./test_state

egress:
  - name: exit-jp
    exit_node: tokyo-node

dns:
  mode: fakeip
  fakeip:
    inet4: 198.18.0.0/15
    inet6: fc00::/18
  per_egress_doh: https://1.1.1.1/dns-query
  direct_upstream: system

capture:
  mode: tun
  scope: all
  tun_name: tailproxy0

panel:
  listen: 127.0.0.1:7708

rules:
  - domain_suffix: [".google.com", ".github.com"]
    egress: exit-jp
  - ip_cidr: ["91.108.4.0/22", "149.154.160.0/20"]
    egress: exit-jp
  - ip_cidr: ["192.168.0.0/16", "10.0.0.0/8"]
    egress: direct
  - domain_keyword: ["malware", "adservice"]
    egress: reject
  - final: direct
`
}

// createTempConfig creates a temporary file containing the given YAML content
// and registers its removal with t.Cleanup.
func createTempConfig(t *testing.T, content string) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	return path
}

// writeBacarraState persists a BacarraState struct as JSON.
func writeBacarraState(path string, state *BacarraState) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// readBacarraState reads and parses <stateDir>/bacarra_routes.json.
func readBacarraState(path string) (*BacarraState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state BacarraState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("corrupt state file: %w", err)
	}
	return &state, nil
}

// runGoCLI executes a command using `go run` from the project root.
func runGoCLI(t *testing.T, pkg string, args ...string) (string, error) {
	t.Helper()
	cmdArgs := append([]string{"run", pkg}, args...)
	cmd := exec.Command("go", cmdArgs...)
	cmd.Dir = filepath.Clean(filepath.Join(".", "..", ".."))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// verifyNoMockAdapters inspects host interfaces and asserts that no fake or
// hallucinated adapter is returned.
func verifyNoMockAdapters(t *testing.T) {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("failed to enumerate network interfaces: %v", err)
	}

	for _, iface := range ifaces {
		name := strings.ToLower(iface.Name)
		if strings.Contains(name, "mock") || strings.Contains(name, "dummy_tailscale") {
			t.Fatalf("fail-fast violation: detected unauthorized mock interface: %s", iface.Name)
		}
	}
}

// isTailscaleIP checks if an address belongs to RFC 6598 CGNAT or Tailscale IPv6 ULA.
func isTailscaleIP(ip netip.Addr) bool {
	return tsaddr.CGNATRange().Contains(ip) || tsaddr.TailscaleULARange().Contains(ip)
}

// compileExpectedRoutes compiles the expected list of route prefixes for Bacarra mode.
func compileExpectedRoutes(t *testing.T, cfg *config.Config) []netip.Prefix {
	t.Helper()
	eng, err := rule.Compile(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	rulePrefixes := eng.RoutedPrefixes()

	pool4, err := netip.ParsePrefix(cfg.DNS.FakeIP.Inet4)
	if err != nil {
		t.Fatalf("parse fakeip pool: %v", err)
	}

	pool6, err := netip.ParsePrefix(cfg.DNS.FakeIP.Inet6)
	if err != nil {
		t.Fatalf("parse fakeip pool6: %v", err)
	}

	var allRoutes []netip.Prefix
	allRoutes = append(allRoutes, pool4, pool6)
	allRoutes = append(allRoutes, rulePrefixes...)
	return allRoutes
}
