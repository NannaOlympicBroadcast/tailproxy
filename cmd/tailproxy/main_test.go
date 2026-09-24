//go:build unix

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestBackgroundLifecycle builds the binary and drives start → status →
// token → stop against a real background process.
func TestBackgroundLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "tailproxy")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cfg := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfg, []byte("panel: {listen: '127.0.0.1:0'}\nrules: [{final: direct}]\n"), 0o600)
	stateDir := filepath.Join(dir, "state")
	run := func(args ...string) (string, error) {
		cmd := exec.Command(bin, append(args, "--state-dir", stateDir)...)
		cmd.Env = append(os.Environ(), "TAILPROXY_PANEL_TOKEN=")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	out, err := run("start", "--save-token", "-c", cfg)
	if err != nil {
		t.Fatalf("start: %v\n%s", err, out)
	}
	token := regexp.MustCompile(`访问令牌：(\S+)`).FindStringSubmatch(out)
	url := regexp.MustCompile(`面板地址：(http://\S+?/)`).FindStringSubmatch(out)
	if token == nil || url == nil || strings.Contains(url[1], ":0/") {
		t.Fatalf("start output lacks token or a real URL:\n%s", out)
	}
	var st struct{ PID int }
	data, _ := os.ReadFile(filepath.Join(stateDir, "tailproxy.json"))
	json.Unmarshal(data, &st)
	t.Cleanup(func() { syscall.Kill(st.PID, syscall.SIGKILL) })

	// The start command has returned; the background process keeps serving
	// with the same token.
	for _, delay := range []time.Duration{0, 1500 * time.Millisecond} {
		time.Sleep(delay)
		req, _ := http.NewRequest("GET", url[1]+"api/v1/status", nil)
		req.Header.Set("Authorization", "Bearer "+token[1])
		resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("status API after %v: %v %v", delay, resp, err)
		}
		resp.Body.Close()
	}
	// Detached: its own session (Linux /proc; field 6 of stat is the session id).
	if stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", st.PID)); err == nil {
		fields := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+1:]))
		if len(fields) < 4 || fields[3] != fmt.Sprint(st.PID) {
			t.Fatalf("background process is not a session leader: %s", stat)
		}
	}

	if out, err := run("start", "-c", cfg); err == nil || !strings.Contains(out, "已在运行") {
		t.Fatalf("second start: %v\n%s", err, out)
	}
	if out, err := run("status"); err != nil || !strings.Contains(out, "正在运行（后台）") {
		t.Fatalf("status: %v\n%s", err, out)
	}
	if out, err := run("token"); err != nil || strings.TrimSpace(out) != token[1] {
		t.Fatalf("token: %v %q, want %q", err, out, token[1])
	}
	logData, _ := os.ReadFile(filepath.Join(stateDir, "tailproxy.log"))
	if strings.Contains(string(logData), token[1]) {
		t.Fatal("token leaked into the log file")
	}

	if out, err := run("stop"); err != nil || !strings.Contains(out, "已停止") {
		t.Fatalf("stop: %v\n%s", err, out)
	}
	for _, f := range []string{"tailproxy.json", "tailproxy.token"} {
		if _, err := os.Stat(filepath.Join(stateDir, f)); !os.IsNotExist(err) {
			t.Fatalf("%s left behind after stop", f)
		}
	}
	if out, _ := run("status"); !strings.Contains(out, "未在运行") {
		t.Fatalf("status after stop:\n%s", out)
	}
}

func TestStartReportsStartupErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "tailproxy")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cfg := filepath.Join(dir, "bad.yaml")
	os.WriteFile(cfg, []byte("rules: [{domain: [a.com], egress: nope}]\n"), 0o600)
	out, err := exec.Command(bin, "start", "-c", cfg, "--state-dir", filepath.Join(dir, "s")).CombinedOutput()
	if err == nil || !strings.Contains(string(out), `unknown target "nope"`) {
		t.Fatalf("got %v\n%s", err, out)
	}
}
