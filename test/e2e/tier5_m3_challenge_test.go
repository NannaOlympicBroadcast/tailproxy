package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/panel"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/service"
)

// =============================================================================
// Tier 5 (Challenger 2) - Stress Testing cmdCheck & tpctl check
// =============================================================================

// T5.C1: Empirical CLI stress tests for tailproxy check and tpctl check across valid,
// missing, invalid, and malformed kernel configurations.
func TestTier5_Adversarial_CLICheck_Comprehensive(t *testing.T) {
	tmpDir := t.TempDir()

	validDavin := sampleValidConfig("davin")
	pathDavin := filepath.Join(tmpDir, "davin.yaml")
	if err := os.WriteFile(pathDavin, []byte(validDavin), 0o600); err != nil {
		t.Fatal(err)
	}

	validBacarra := sampleValidConfig("bacarra")
	pathBacarra := filepath.Join(tmpDir, "bacarra.yaml")
	if err := os.WriteFile(pathBacarra, []byte(validBacarra), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. Verify tailproxy check on valid Davin & Bacarra configs
	out, err := runGoCLI(t, "./cmd/tailproxy", "check", "-c", pathDavin)
	if err != nil || !strings.Contains(out, "配置有效") || !strings.Contains(out, "内核模式 davin") {
		t.Fatalf("tailproxy check valid davin failed: err=%v, out=%s", err, out)
	}

	out, err = runGoCLI(t, "./cmd/tailproxy", "check", "-c", pathBacarra)
	if err != nil || !strings.Contains(out, "配置有效") || !strings.Contains(out, "内核模式 bacarra") {
		t.Fatalf("tailproxy check valid bacarra failed: err=%v, out=%s", err, out)
	}

	// 2. Verify tpctl check on valid Davin & Bacarra configs
	out, err = runGoCLI(t, "./cmd/tpctl", "--state-dir", tmpDir, "check", "-c", pathDavin)
	if err != nil || !strings.Contains(out, "配置有效") || !strings.Contains(out, "内核模式 davin") {
		t.Fatalf("tpctl check valid davin failed: err=%v, out=%s", err, out)
	}

	out, err = runGoCLI(t, "./cmd/tpctl", "--state-dir", tmpDir, "check", "-c", pathBacarra)
	if err != nil || !strings.Contains(out, "配置有效") || !strings.Contains(out, "内核模式 bacarra") {
		t.Fatalf("tpctl check valid bacarra failed: err=%v, out=%s", err, out)
	}

	// 3. Verify missing config file rejection
	missingPath := filepath.Join(tmpDir, "nonexistent.yaml")
	_, err = runGoCLI(t, "./cmd/tailproxy", "check", "-c", missingPath)
	if err == nil {
		t.Fatalf("expected tailproxy check to fail on missing file")
	}

	_, err = runGoCLI(t, "./cmd/tpctl", "--state-dir", tmpDir, "check", "-c", missingPath)
	if err == nil {
		t.Fatalf("expected tpctl check to fail on missing file")
	}

	// 4. Verify malformed kernel value rejection
	malformedKernel := strings.Replace(validDavin, "kernel: davin", "kernel: non_existent_kernel", 1)
	pathMalformed := filepath.Join(tmpDir, "malformed.yaml")
	if err := os.WriteFile(pathMalformed, []byte(malformedKernel), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = runGoCLI(t, "./cmd/tailproxy", "check", "-c", pathMalformed)
	if err == nil {
		t.Fatalf("expected tailproxy check to reject unknown kernel, but got success: %s", out)
	}

	out, err = runGoCLI(t, "./cmd/tpctl", "--state-dir", tmpDir, "check", "-c", pathMalformed)
	if err == nil {
		t.Fatalf("expected tpctl check to reject unknown kernel, but got success: %s", out)
	}

	// 5. Verify strict unknown field rejection (e.g. kernel_mode)
	unknownFieldYAML := strings.Replace(validDavin, "kernel: davin", "kernel_mode: davin", 1)
	pathUnknownField := filepath.Join(tmpDir, "unknown_field.yaml")
	if err := os.WriteFile(pathUnknownField, []byte(unknownFieldYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = runGoCLI(t, "./cmd/tailproxy", "check", "-c", pathUnknownField)
	if err == nil {
		t.Fatalf("expected tailproxy check to reject unknown field, but got success: %s", out)
	}
}

// =============================================================================
// Tier 5 (Challenger 2) - Config Reload Kernel Mode Alteration & State Preservation
// =============================================================================

// T5.C2: When kernel mode is altered on disk and reloaded via panel API,
// it must issue a restart requirement warning and never corrupt live state.
func TestTier5_Adversarial_Reload_KernelModeAlteration(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	davinContent := sampleValidConfig("davin")
	if err := os.WriteFile(cfgPath, []byte(davinContent), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := panel.New(cfgPath, "test-version", panel.Options{})
	if err != nil {
		t.Fatalf("failed to initialize panel: %v", err)
	}

	// Alter to bacarra
	bacarraContent := sampleValidConfig("bacarra")
	if err := os.WriteFile(cfgPath, []byte(bacarraContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Perform reload request
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/config/reload", nil)
	req.Host = "127.0.0.1:7708"
	req.Header.Set("Authorization", "Bearer "+s.Token())
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on reload, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse reload JSON: %v", err)
	}

	warning, ok := resp["warning"].(string)
	if !ok || !strings.Contains(warning, "kernel") || !strings.Contains(warning, "重启") {
		t.Fatalf("expected warning requiring restart for kernel alteration, got: %v", resp)
	}

	// Query /api/v1/status to verify status endpoint reflects new config
	// with appropriate bacarra fallback components since runtime was nil
	recStatus := httptest.NewRecorder()
	reqStatus := httptest.NewRequest("GET", "/api/v1/status", nil)
	reqStatus.Host = "127.0.0.1:7708"
	reqStatus.Header.Set("Authorization", "Bearer "+s.Token())
	s.Handler().ServeHTTP(recStatus, reqStatus)

	if recStatus.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on status, got %d: %s", recStatus.Code, recStatus.Body.String())
	}

	var statusResp map[string]any
	if err := json.Unmarshal(recStatus.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("failed to parse status JSON: %v", err)
	}

	if statusResp["kernel"] != "bacarra" {
		t.Errorf("status response kernel = %v, want bacarra", statusResp["kernel"])
	}

	// Check fallback components reflect bacarra not running
	comps := statusResp["components"].([]any)
	foundKernel := false
	for _, c := range comps {
		cmap := c.(map[string]any)
		if cmap["name"] == "kernel" && cmap["state"] == "not_running" {
			foundKernel = true
		}
	}
	if !foundKernel {
		t.Errorf("expected kernel not_running component in status fallback")
	}
}

// =============================================================================
// Tier 5 (Challenger 2) - End-to-End tpctl status reflection
// =============================================================================

// T5.C3: Verify tpctl status accurately displays active kernel mode from live daemon state.
func TestTier5_Adversarial_TPCTL_Status_Reflection(t *testing.T) {
	tmpDir := t.TempDir()
	p := service.NewPaths(tmpDir)

	token := "tpctl-adversarial-test-token-123456"
	if err := os.WriteFile(p.Token, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Spin up fake panel server returning status with Bacarra kernel
	fakeStatus := map[string]any{
		"version":        "test-v1",
		"kernel":         "bacarra",
		"uptime_seconds": 120,
		"config_path":    filepath.Join(tmpDir, "config.yaml"),
		"rules":          3,
		"components": []map[string]string{
			{"name": "panel", "state": "running", "detail": "active"},
			{"name": "kernel", "state": "running", "detail": "bacarra (宿主官方 Tailscale 路由劫持)"},
			{"name": "tailscale_adapter", "state": "active", "detail": "Tailscale (索引 12)"},
			{"name": "route_manager", "state": "active", "detail": "已注入 2 条路由规则"},
		},
		"kernel_status": map[string]any{
			"adapter_name": "Tailscale",
			"routes":       []string{"198.18.0.0/15", "fc00::/18"},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/api/v1/status" {
			json.NewEncoder(w).Encode(fakeStatus)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	if err := p.WriteState(service.State{
		PID:       os.Getpid(),
		URL:       srv.URL + "/",
		TokenFile: p.Token,
		Kernel:    "bacarra",
		Started:   time.Now().Add(-2 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	out, err := runGoCLI(t, "./cmd/tpctl", "--state-dir", tmpDir, "status")
	if err != nil {
		t.Fatalf("tpctl status failed: %v, output: %s", err, out)
	}

	// Verify output contains kernel: bacarra and route hijacking table
	if !strings.Contains(out, "内核：bacarra") {
		t.Errorf("tpctl status output missing '内核：bacarra': %s", out)
	}
	if !strings.Contains(out, "Tailscale") {
		t.Errorf("tpctl status output missing 'Tailscale': %s", out)
	}
	if !strings.Contains(out, "198.18.0.0/15 -> Tailscale") {
		t.Errorf("tpctl status output missing hijacked route: %s", out)
	}
}
