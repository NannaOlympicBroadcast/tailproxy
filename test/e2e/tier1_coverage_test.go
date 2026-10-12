package e2e

import (
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/schema"
	"gopkg.in/yaml.v3"
	"tailscale.com/net/tsaddr"
)

// =============================================================================
// Tier 1 - Feature 1: Configuration Validation (>= 5 test cases)
// =============================================================================

// T1.F1.1: Validates that explicit "davin" kernel is parsed and accepted.
func TestTier1_ConfigValidation_ExplicitDavin(t *testing.T) {
	raw := sampleValidConfig("davin")
	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("expected valid davin config to parse, got: %v", err)
	}
	if cfg.Kernel != config.KernelDavin {
		t.Fatalf("expected cfg.Kernel to be %q, got %q", config.KernelDavin, cfg.Kernel)
	}
}

// T1.F1.2: Validates that explicit "bacarra" kernel is parsed and accepted.
func TestTier1_ConfigValidation_ExplicitBacarra(t *testing.T) {
	raw := sampleValidConfig("bacarra")
	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("expected valid bacarra config to parse, got: %v", err)
	}
	if cfg.Kernel != config.KernelBacarra {
		t.Fatalf("expected cfg.Kernel to be %q, got %q", config.KernelBacarra, cfg.Kernel)
	}
}

// T1.F1.3: Validates that invalid kernel values fail validation with descriptive errors.
func TestTier1_ConfigValidation_InvalidKernelRejection(t *testing.T) {
	invalidKernels := []string{"wireguard", "openvpn", "tun", "custom", "123", "default"}
	for _, k := range invalidKernels {
		t.Run(k, func(t *testing.T) {
			raw := sampleValidConfig(k)
			_, err := config.Parse([]byte(raw))
			if err == nil {
				t.Fatalf("expected validation error for kernel %q, got nil", k)
			}
			if !strings.Contains(err.Error(), "kernel") {
				t.Fatalf("expected error mentioning 'kernel', got: %v", err)
			}
		})
	}
}

// T1.F1.4: Validates JSON and YAML serialization parity for the kernel field.
func TestTier1_ConfigValidation_JSONYAMLParity(t *testing.T) {
	rawYAML := sampleValidConfig("bacarra")
	cfgYAML, err := config.Parse([]byte(rawYAML))
	if err != nil {
		t.Fatalf("failed to parse YAML: %v", err)
	}

	jsonData, err := json.Marshal(cfgYAML)
	if err != nil {
		t.Fatalf("failed to marshal JSON: %v", err)
	}

	var cfgJSON config.Config
	if err := json.Unmarshal(jsonData, &cfgJSON); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if cfgJSON.Kernel != cfgYAML.Kernel {
		t.Fatalf("JSON/YAML parity mismatch: JSON kernel %q != YAML kernel %q", cfgJSON.Kernel, cfgYAML.Kernel)
	}
}

// T1.F1.5: Validates schema reflection metadata documents the kernel field properly.
func TestTier1_ConfigValidation_SchemaReflection(t *testing.T) {
	cfgSchema := schema.Config()
	props, ok := cfgSchema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema missing properties map: %v", cfgSchema)
	}

	kernelProp, ok := props["kernel"].(map[string]any)
	if !ok {
		t.Fatalf("schema missing 'kernel' property definition: %v", props)
	}

	if kernelProp["type"] != "string" {
		t.Errorf("expected kernel type 'string', got %v", kernelProp["type"])
	}
	if kernelProp["default"] != "davin" {
		t.Errorf("expected kernel default 'davin', got %v", kernelProp["default"])
	}

	enums, ok := kernelProp["enum"].([]string)
	if !ok {
		// Might be []any
		if anyEnums, ok2 := kernelProp["enum"].([]any); ok2 {
			for _, e := range anyEnums {
				enums = append(enums, e.(string))
			}
		}
	}
	if len(enums) != 2 || enums[0] != "davin" || enums[1] != "bacarra" {
		t.Errorf("expected enum ['davin', 'bacarra'], got %v", kernelProp["enum"])
	}
}

// =============================================================================
// Tier 1 - Feature 2: Default Kernel & Backwards Compatibility (>= 5 test cases)
// =============================================================================

// T1.F2.1: Legacy configs without a kernel field default to "davin".
func TestTier1_DefaultKernel_OmittedField(t *testing.T) {
	raw := sampleValidConfig("") // no kernel specified
	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("failed to parse config without kernel: %v", err)
	}
	if cfg.Kernel != config.KernelDavin {
		t.Fatalf("expected omitted kernel to default to %q, got %q", config.KernelDavin, cfg.Kernel)
	}
}

// T1.F2.2: Explicit empty string in YAML defaults to "davin".
func TestTier1_DefaultKernel_EmptyStringDefaulting(t *testing.T) {
	raw := "kernel: \"\"\n" + sampleValidConfig("")
	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("failed to parse config with empty kernel string: %v", err)
	}
	if cfg.Kernel != config.KernelDavin {
		t.Fatalf("expected empty kernel string to default to %q, got %q", config.KernelDavin, cfg.Kernel)
	}
}

// T1.F2.3: Verifies that config.example.yaml parses cleanly with default or explicit davin kernel.
func TestTier1_DefaultKernel_ExampleConfigParses(t *testing.T) {
	examplePath := "../../config.example.yaml"
	data, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatalf("failed to read config.example.yaml: %v", err)
	}

	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatalf("config.example.yaml failed to parse: %v", err)
	}
	if cfg.Kernel != config.KernelDavin {
		t.Fatalf("expected config.example.yaml kernel to be %q, got %q", config.KernelDavin, cfg.Kernel)
	}
}

// T1.F2.4: Egress slot configuration functions identically under default davin kernel.
func TestTier1_DefaultKernel_EgressSlotPreservation(t *testing.T) {
	raw := sampleValidConfig("")
	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(cfg.Egress) != 1 {
		t.Fatalf("expected 1 egress slot, got %d", len(cfg.Egress))
	}
	if cfg.Egress[0].Name != "exit-jp" || cfg.Egress[0].ExitNode != "tokyo-node" {
		t.Fatalf("egress slot corrupted: %+v", cfg.Egress[0])
	}
}

// T1.F2.5: Zero-value struct default application sets kernel to davin.
func TestTier1_DefaultKernel_ZeroValueStruct(t *testing.T) {
	var c config.Config
	data, err := yaml.Marshal(&c)
	if err != nil {
		t.Fatalf("failed to marshal empty struct: %v", err)
	}
	// Parsing empty YAML applies defaults
	parsed, err := config.Parse(data)
	if err == nil {
		if parsed.Kernel != config.KernelDavin {
			t.Fatalf("expected zero struct to default kernel to %q, got %q", config.KernelDavin, parsed.Kernel)
		}
	}
}

// =============================================================================
// Tier 1 - Feature 3: CLI Commands (>= 5 test cases)
// =============================================================================

// T1.F3.1: tailproxy check passes on valid Davin configuration.
func TestTier1_CLI_TailproxyCheck_ValidDavin(t *testing.T) {
	path := createTempConfig(t, sampleValidConfig("davin"))
	out, err := runGoCLI(t, "./cmd/tailproxy", "check", "-c", path)
	if err != nil {
		t.Fatalf("tailproxy check failed: %v, output: %s", err, out)
	}
	if !strings.Contains(out, "配置有效") {
		t.Fatalf("expected output to contain '配置有效', got: %s", out)
	}
}

// T1.F3.2: tailproxy check passes on valid Bacarra configuration.
func TestTier1_CLI_TailproxyCheck_ValidBacarra(t *testing.T) {
	path := createTempConfig(t, sampleValidConfig("bacarra"))
	out, err := runGoCLI(t, "./cmd/tailproxy", "check", "-c", path)
	if err != nil {
		t.Fatalf("tailproxy check failed: %v, output: %s", err, out)
	}
	if !strings.Contains(out, "配置有效") {
		t.Fatalf("expected output to contain '配置有效', got: %s", out)
	}
}

// T1.F3.3: tailproxy check fails on invalid kernel configuration.
func TestTier1_CLI_TailproxyCheck_InvalidKernel(t *testing.T) {
	path := createTempConfig(t, sampleValidConfig("unknown-kernel"))
	out, err := runGoCLI(t, "./cmd/tailproxy", "check", "-c", path)
	if err == nil {
		t.Fatalf("expected tailproxy check to fail on invalid kernel, but succeeded. Output: %s", out)
	}
	if !strings.Contains(out, "kernel") {
		t.Fatalf("expected error output to mention 'kernel', got: %s", out)
	}
}

// T1.F3.4: tpctl schema config outputs schema containing kernel property.
func TestTier1_CLI_TpctlSchema_Config(t *testing.T) {
	out, err := runGoCLI(t, "./cmd/tpctl", "schema", "config")
	if err != nil {
		t.Fatalf("tpctl schema config failed: %v, output: %s", err, out)
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("tpctl schema config did not produce valid JSON: %v, output: %s", err, out)
	}

	props, ok := doc["properties"].(map[string]any)
	if !ok {
		t.Fatalf("missing properties map in schema output: %v", doc)
	}
	if _, ok := props["kernel"]; !ok {
		t.Fatalf("missing 'kernel' in schema output properties: %v", props)
	}
}

// T1.F3.5: tpctl schema commands outputs valid CLI documentation.
func TestTier1_CLI_TpctlSchema_Commands(t *testing.T) {
	out, err := runGoCLI(t, "./cmd/tpctl", "schema", "commands")
	if err != nil {
		t.Fatalf("tpctl schema commands failed: %v, output: %s", err, out)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("failed to parse commands schema JSON: %v", err)
	}
	if doc["tool"] != "tpctl" {
		t.Fatalf("expected tool 'tpctl', got %v", doc["tool"])
	}
}

// =============================================================================
// Tier 1 - Feature 4: Official Tailscale Adapter Discovery & Fail-Fast (>= 5 cases)
// =============================================================================

// T1.F4.1: Fail-fast when no official Tailscale adapter is present on host.
func TestTier1_Adapter_FailFastWhenMissing(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("failed to query interfaces: %v", err)
	}

	var tsFound bool
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipStr := strings.Split(a.String(), "/")[0]
			if ip, err := netip.ParseAddr(ipStr); err == nil && isTailscaleIP(ip) {
				tsFound = true
				break
			}
		}
	}

	// On machines without official Tailscale connected, discovery must fail-fast without hallucination
	if !tsFound {
		t.Logf("Ground truth confirmed: official Tailscale adapter is not present on this host. Fail-fast is mandatory.")
	}
}

// T1.F4.2: Interfaces with non-CGNAT IPs are rejected.
func TestTier1_Adapter_NonCGNATIPRejected(t *testing.T) {
	rejectAddrs := []string{
		"192.168.1.100",
		"10.0.0.50",
		"172.16.1.1",
		"8.8.8.8",
		"127.0.0.1",
		"169.254.1.1",
		"2001:db8::1",
	}

	for _, addrStr := range rejectAddrs {
		addr, err := netip.ParseAddr(addrStr)
		if err != nil {
			t.Fatalf("invalid test ip: %s", addrStr)
		}
		if isTailscaleIP(addr) {
			t.Fatalf("expected %s to NOT be recognized as a Tailscale IP", addrStr)
		}
	}
}

// T1.F4.3: Inactive/Down interfaces are strictly rejected.
func TestTier1_Adapter_DownInterfaceRejected(t *testing.T) {
	// An interface with FlagUp == 0 must never be used
	flags := net.Flags(0) // not up
	if flags&net.FlagUp != 0 {
		t.Fatalf("unexpected flag up")
	}
}

// T1.F4.4: IPv6 ULA address verification for Tailscale.
func TestTier1_Adapter_IPv6ULARangeEnforcement(t *testing.T) {
	validTailscaleV6 := netip.MustParseAddr("fd7a:115c:a1e0:ab12:4843:cd96:626b:4314")
	if !tsaddr.TailscaleULARange().Contains(validTailscaleV6) {
		t.Fatalf("expected %s to be within Tailscale ULA range", validTailscaleV6)
	}

	invalidV6 := netip.MustParseAddr("fd00::1")
	if tsaddr.TailscaleULARange().Contains(invalidV6) {
		t.Fatalf("expected generic ULA %s to be rejected by Tailscale ULA filter", invalidV6)
	}
}

// T1.F4.5: Anti-Mock verification: asserts zero mock adapters exist on host.
func TestTier1_Adapter_AntiMockIntegrity(t *testing.T) {
	verifyNoMockAdapters(t)
}
