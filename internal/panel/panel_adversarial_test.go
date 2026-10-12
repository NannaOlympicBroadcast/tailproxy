package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
)

// mockKernelRuntime implements Runtime and KernelReporter for adversarial tests.
type mockKernelRuntime struct {
	components   []Component
	kernelStatus any
	applied      []*config.Config
}

func (m *mockKernelRuntime) Components() []Component {
	return m.components
}

func (m *mockKernelRuntime) KernelStatus() any {
	return m.kernelStatus
}

func (m *mockKernelRuntime) Egress() any {
	return []any{}
}

func (m *mockKernelRuntime) Connections() any {
	return map[string]any{"active": []any{}, "total": 0, "failed": 0}
}

func (m *mockKernelRuntime) Tailnet(ctx context.Context) (any, any, error) {
	return nil, nil, nil
}

func (m *mockKernelRuntime) ApplyEgress(cfg *config.Config) error {
	m.applied = append(m.applied, cfg)
	return nil
}

func (m *mockKernelRuntime) SetAuthKey(key string) error {
	return nil
}

func (m *mockKernelRuntime) ClearAuthKey() error {
	return nil
}

func (m *mockKernelRuntime) SetRelayToken(name, token string) error {
	return nil
}

// -----------------------------------------------------------------------------
// Objective 1: /api/v1/status with Davin, Bacarra, and nil/uninitialized fallback
// -----------------------------------------------------------------------------

func TestAdversarial_Status_NilRuntime_DavinFallback(t *testing.T) {
	cfgContent := `
kernel: davin
egress:
  - {name: us, exit_node: us-vps}
rules:
  - {domain_keyword: [openai], egress: us}
`
	s, _ := newTestServer(t, cfgContent)
	h := authed(s)

	rec := do(t, h, "GET", "/api/v1/status", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse status JSON: %v", err)
	}

	if resp["kernel"] != "davin" {
		t.Fatalf("expected kernel 'davin', got %v", resp["kernel"])
	}

	if _, ok := resp["kernel_status"]; ok {
		t.Fatalf("kernel_status must not be present when runtime is nil, got %v", resp["kernel_status"])
	}

	comps, ok := resp["components"].([]any)
	if !ok {
		t.Fatalf("components not an array: %v", resp["components"])
	}

	foundEgressMgr := false
	foundCapture := false
	for _, c := range comps {
		cmap := c.(map[string]any)
		name := cmap["name"].(string)
		state := cmap["state"].(string)
		if name == "egress_manager" {
			foundEgressMgr = true
			if state != "not_running" {
				t.Errorf("egress_manager state = %s, want not_running", state)
			}
		}
		if name == "capture" {
			foundCapture = true
			if state != "not_running" {
				t.Errorf("capture state = %s, want not_running", state)
			}
		}
	}
	if !foundEgressMgr {
		t.Errorf("missing fallback egress_manager component in davin nil runtime")
	}
	if !foundCapture {
		t.Errorf("missing fallback capture component in davin nil runtime")
	}
}

func TestAdversarial_Status_NilRuntime_BacarraFallback(t *testing.T) {
	cfgContent := `
kernel: bacarra
egress:
  - {name: us, exit_node: us-vps}
rules:
  - {domain_keyword: [openai], egress: us}
`
	s, _ := newTestServer(t, cfgContent)
	h := authed(s)

	rec := do(t, h, "GET", "/api/v1/status", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse status JSON: %v", err)
	}

	if resp["kernel"] != "bacarra" {
		t.Fatalf("expected kernel 'bacarra', got %v", resp["kernel"])
	}

	if _, ok := resp["kernel_status"]; ok {
		t.Fatalf("kernel_status must not be present when runtime is nil, got %v", resp["kernel_status"])
	}

	comps, ok := resp["components"].([]any)
	if !ok {
		t.Fatalf("components not an array: %v", resp["components"])
	}

	compMap := make(map[string]map[string]any)
	for _, c := range comps {
		cmap := c.(map[string]any)
		compMap[cmap["name"].(string)] = cmap
	}

	expectedBacarraComps := []string{"kernel", "tailscale_adapter", "route_manager"}
	for _, name := range expectedBacarraComps {
		c, exists := compMap[name]
		if !exists {
			t.Fatalf("expected bacarra fallback component %q to be present", name)
		}
		if c["state"] != "not_running" {
			t.Errorf("expected component %q state 'not_running', got %v", name, c["state"])
		}
	}

	// Davin-specific fallback components must NOT be present in Bacarra mode
	if _, exists := compMap["egress_manager"]; exists {
		t.Errorf("egress_manager must NOT be present in Bacarra fallback components")
	}
	if _, exists := compMap["capture"]; exists {
		t.Errorf("capture must NOT be present in Bacarra fallback components")
	}
}

func TestAdversarial_Status_WithDavinRuntime(t *testing.T) {
	cfgContent := `
kernel: davin
egress:
  - {name: us, exit_node: us-vps}
rules:
  - {domain_keyword: [openai], egress: us}
`
	s, _ := newTestServer(t, cfgContent)
	rt := &mockKernelRuntime{
		components: []Component{
			{Name: "kernel", State: "running", Detail: "davin (嵌入式 tsnet 多节点透明代理)"},
			{Name: "egress_manager", State: "running", Detail: "1 个出口"},
		},
		kernelStatus: map[string]any{
			"mode":  "davin",
			"slots": []string{"us"},
		},
	}
	s.SetRuntime(rt)
	h := authed(s)

	rec := do(t, h, "GET", "/api/v1/status", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse status JSON: %v", err)
	}

	if resp["kernel"] != "davin" {
		t.Fatalf("expected kernel 'davin', got %v", resp["kernel"])
	}

	ks, ok := resp["kernel_status"].(map[string]any)
	if !ok {
		t.Fatalf("expected kernel_status object, got %v", resp["kernel_status"])
	}
	if ks["mode"] != "davin" {
		t.Errorf("expected kernel_status.mode 'davin', got %v", ks["mode"])
	}

	comps := resp["components"].([]any)
	compNames := make(map[string]string)
	for _, c := range comps {
		cmap := c.(map[string]any)
		compNames[cmap["name"].(string)] = cmap["state"].(string)
	}

	if compNames["kernel"] != "running" {
		t.Errorf("expected kernel state 'running', got %v", compNames["kernel"])
	}
	if compNames["egress_manager"] != "running" {
		t.Errorf("expected egress_manager state 'running', got %v", compNames["egress_manager"])
	}
}

func TestAdversarial_Status_WithBacarraRuntime(t *testing.T) {
	cfgContent := `
kernel: bacarra
egress:
  - {name: us, exit_node: us-vps}
rules:
  - {domain_keyword: [openai], egress: us}
`
	s, _ := newTestServer(t, cfgContent)
	rt := &mockKernelRuntime{
		components: []Component{
			{Name: "kernel", State: "running", Detail: "bacarra (宿主官方 Tailscale 路由劫持)"},
			{Name: "tailscale_adapter", State: "active", Detail: "Tailscale (索引 14)"},
			{Name: "route_manager", State: "active", Detail: "已注入 3 条路由规则"},
		},
		kernelStatus: map[string]any{
			"mode":          "bacarra",
			"adapter_name":  "Tailscale",
			"adapter_index": 14,
			"adapter_ips":   []string{"100.64.0.1"},
			"routes":        []string{"198.18.0.0/15", "fc00::/18"},
			"routes_count":  2,
		},
	}
	s.SetRuntime(rt)
	h := authed(s)

	rec := do(t, h, "GET", "/api/v1/status", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse status JSON: %v", err)
	}

	if resp["kernel"] != "bacarra" {
		t.Fatalf("expected kernel 'bacarra', got %v", resp["kernel"])
	}

	ks, ok := resp["kernel_status"].(map[string]any)
	if !ok {
		t.Fatalf("expected kernel_status object, got %v", resp["kernel_status"])
	}
	if ks["adapter_name"] != "Tailscale" {
		t.Errorf("expected adapter_name 'Tailscale', got %v", ks["adapter_name"])
	}
	if ks["routes_count"].(float64) != 2 {
		t.Errorf("expected routes_count 2, got %v", ks["routes_count"])
	}

	comps := resp["components"].([]any)
	compNames := make(map[string]string)
	for _, c := range comps {
		cmap := c.(map[string]any)
		compNames[cmap["name"].(string)] = cmap["state"].(string)
	}

	if compNames["tailscale_adapter"] != "active" {
		t.Errorf("expected tailscale_adapter state 'active', got %v", compNames["tailscale_adapter"])
	}
	if compNames["route_manager"] != "active" {
		t.Errorf("expected route_manager state 'active', got %v", compNames["route_manager"])
	}
}

func TestAdversarial_Status_KernelReporterReturnsNil_NoCrash(t *testing.T) {
	cfgContent := `
kernel: bacarra
egress:
  - {name: us, exit_node: us-vps}
rules:
  - {final: direct}
`
	s, _ := newTestServer(t, cfgContent)
	rt := &mockKernelRuntime{
		components:   []Component{{Name: "panel", State: "running"}},
		kernelStatus: nil, // Nil status must not cause crash or invalid json
	}
	s.SetRuntime(rt)
	h := authed(s)

	rec := do(t, h, "GET", "/api/v1/status", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse status JSON: %v", err)
	}

	if _, ok := resp["kernel_status"]; ok {
		t.Errorf("kernel_status should be omitted when nil, got: %v", resp["kernel_status"])
	}
}

// -----------------------------------------------------------------------------
// Objective 3: handleReload when kernel mode is altered
// -----------------------------------------------------------------------------

func TestAdversarial_Reload_KernelModeAlteration_DavinToBacarra(t *testing.T) {
	davinYAML := `
kernel: davin
egress:
  - {name: us, exit_node: us-vps}
rules:
  - {domain_keyword: [openai], egress: us}
`
	s, path := newTestServer(t, davinYAML)
	rt := &mockKernelRuntime{}
	s.SetRuntime(rt)
	h := authed(s)

	// Alter kernel to bacarra on disk
	bacarraYAML := `
kernel: bacarra
egress:
  - {name: us, exit_node: us-vps}
rules:
  - {domain_keyword: [openai], egress: us}
`
	if err := os.WriteFile(path, []byte(bacarraYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := do(t, h, "POST", "/api/v1/config/reload", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse reload JSON: %v", err)
	}

	if resp["ok"] != true {
		t.Fatalf("expected ok: true, got %v", resp["ok"])
	}

	warning, ok := resp["warning"].(string)
	if !ok || warning == "" {
		t.Fatalf("expected warning about restart requirement, got none: %v", resp)
	}

	if !strings.Contains(warning, "kernel") {
		t.Errorf("warning must explicitly mention 'kernel', got: %s", warning)
	}
	if !strings.Contains(warning, "重启") {
		t.Errorf("warning must state that restart is required ('重启'), got: %s", warning)
	}

	// Verify live state integrity: reload succeeded, not marked as failed
	if s.reloadsFailed.Load() != 0 {
		t.Errorf("reloadsFailed = %d, want 0", s.reloadsFailed.Load())
	}
	if s.reloadsOK.Load() != 1 {
		t.Errorf("reloadsOK = %d, want 1", s.reloadsOK.Load())
	}

	// Check updated config snapshot reflects new file without crashing
	cfg, _, _ := s.snapshot()
	if cfg.Kernel != "bacarra" {
		t.Errorf("snapshot kernel = %s, want bacarra", cfg.Kernel)
	}
}

func TestAdversarial_Reload_KernelModeAlteration_BacarraToDavin(t *testing.T) {
	bacarraYAML := `
kernel: bacarra
egress:
  - {name: us, exit_node: us-vps}
rules:
  - {domain_keyword: [openai], egress: us}
`
	s, path := newTestServer(t, bacarraYAML)
	h := authed(s)

	davinYAML := `
kernel: davin
egress:
  - {name: us, exit_node: us-vps}
rules:
  - {domain_keyword: [openai], egress: us}
`
	if err := os.WriteFile(path, []byte(davinYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := do(t, h, "POST", "/api/v1/config/reload", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)

	warning, ok := resp["warning"].(string)
	if !ok || !strings.Contains(warning, "kernel") || !strings.Contains(warning, "重启") {
		t.Fatalf("expected restart warning for kernel change, got: %v", resp)
	}
}

func TestAdversarial_Reload_NoKernelChange_NoKernelRestartWarning(t *testing.T) {
	initialYAML := `
kernel: davin
egress:
  - {name: us, exit_node: us-vps}
rules:
  - {domain_keyword: [openai], egress: us}
`
	s, path := newTestServer(t, initialYAML)
	h := authed(s)

	updatedYAML := `
kernel: davin
egress:
  - {name: us, exit_node: us-vps}
rules:
  - {domain_keyword: [openai], egress: us}
  - {domain_keyword: [anthropic], egress: us}
`
	if err := os.WriteFile(path, []byte(updatedYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := do(t, h, "POST", "/api/v1/config/reload", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if w, ok := resp["warning"].(string); ok && strings.Contains(w, "kernel") {
		t.Fatalf("must NOT issue kernel restart warning when kernel did not change, got: %s", w)
	}
}

func TestAdversarial_Reload_InvalidKernel_RejectsAndPreservesLiveState(t *testing.T) {
	validYAML := `
kernel: davin
egress:
  - {name: us, exit_node: us-vps}
rules:
  - {domain_keyword: [openai], egress: us}
`
	s, path := newTestServer(t, validYAML)
	h := authed(s)

	// Alter to invalid kernel on disk
	invalidYAML := `
kernel: unknown_kernel_mode
egress:
  - {name: us, exit_node: us-vps}
rules:
  - {domain_keyword: [openai], egress: us}
`
	if err := os.WriteFile(path, []byte(invalidYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := do(t, h, "POST", "/api/v1/config/reload", "", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on invalid kernel reload, got %d: %s", rec.Code, rec.Body.String())
	}

	if s.reloadsFailed.Load() != 1 {
		t.Errorf("reloadsFailed = %d, want 1", s.reloadsFailed.Load())
	}

	// Live state MUST remain untouched and valid
	cfg, engine, _ := s.snapshot()
	if cfg.Kernel != "davin" {
		t.Errorf("live config kernel corrupted: got %s, want davin", cfg.Kernel)
	}
	if engine == nil || engine.Len() != 1 {
		t.Errorf("live rule engine corrupted: got %v", engine)
	}
}

func TestAdversarial_Reload_ConcurrentLoad(t *testing.T) {
	s, path := newTestServer(t, `
kernel: davin
egress: [{name: us, exit_node: us-vps}]
rules: [{domain_keyword: [openai], egress: us}]
`)
	h := authed(s)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx%2 == 0 {
				_ = os.WriteFile(path, []byte(`
kernel: davin
egress: [{name: us, exit_node: us-vps}]
rules: [{domain_keyword: [openai], egress: us}]
`), 0o600)
			}
			rec := do(t, h, "POST", "/api/v1/config/reload", "", nil)
			if rec.Code != http.StatusOK && rec.Code != http.StatusBadRequest {
				t.Errorf("unexpected status during concurrent reload: %d", rec.Code)
			}
		}(i)
	}
	wg.Wait()

	// Verify server did not deadlock or panic
	cfg, _, _ := s.snapshot()
	if cfg == nil {
		t.Fatal("server snapshot nil after concurrent reload")
	}
}
