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
// token → stop → start (same token) → rotate → ephemeral against real
// background processes.
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
	tokenFile := filepath.Join(stateDir, "tailproxy.token")
	run := func(args ...string) (string, error) {
		cmd := exec.Command(bin, append(args, "--state-dir", stateDir)...)
		cmd.Env = append(os.Environ(), "TAILPROXY_PANEL_TOKEN=")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	var pids []int
	t.Cleanup(func() {
		for _, pid := range pids {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	// start launches the service and returns the printed token and URL.
	start := func(args ...string) (token, url string) {
		t.Helper()
		out, err := run(append([]string{"start", "-c", cfg}, args...)...)
		if err != nil {
			t.Fatalf("start: %v\n%s", err, out)
		}
		tm := regexp.MustCompile(`访问令牌：(\S+)`).FindStringSubmatch(out)
		um := regexp.MustCompile(`面板地址：(http://\S+?/)`).FindStringSubmatch(out)
		if tm == nil || um == nil || strings.Contains(um[1], ":0/") {
			t.Fatalf("start output lacks token or a real URL:\n%s", out)
		}
		var st struct{ PID int }
		data, _ := os.ReadFile(filepath.Join(stateDir, "tailproxy.json"))
		json.Unmarshal(data, &st)
		pids = append(pids, st.PID)
		return tm[1], um[1]
	}
	apiStatus := func(url, token string) int {
		req, _ := http.NewRequest("GET", url+"api/v1/status", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
		if err != nil {
			t.Fatalf("status API: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	stop := func() {
		t.Helper()
		if out, err := run("stop"); err != nil || !strings.Contains(out, "已停止") {
			t.Fatalf("stop: %v\n%s", err, out)
		}
	}

	// 1. First start generates and persists the token.
	tok1, url := start()
	if got, err := os.ReadFile(tokenFile); err != nil || strings.TrimSpace(string(got)) != tok1 {
		t.Fatalf("token file %q, %v; want %q", got, err, tok1)
	}
	if info, _ := os.Stat(tokenFile); info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode %v", info.Mode().Perm())
	}
	pid := pids[len(pids)-1]
	if stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		fields := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+1:]))
		if len(fields) < 4 || fields[3] != fmt.Sprint(pid) {
			t.Fatalf("background process is not a session leader: %s", stat)
		}
	}
	time.Sleep(1500 * time.Millisecond)
	if code := apiStatus(url, tok1); code != 200 {
		t.Fatalf("token after 1.5s: %d", code)
	}
	if out, err := run("start", "-c", cfg); err == nil || !strings.Contains(out, "已在运行") {
		t.Fatalf("second start: %v\n%s", err, out)
	}
	if out, err := run("status"); err != nil || !strings.Contains(out, "持久化保存在") {
		t.Fatalf("status: %v\n%s", err, out)
	}
	if out, err := run("token"); err != nil || strings.TrimSpace(out) != tok1 {
		t.Fatalf("token: %v %q", err, out)
	}
	logData, _ := os.ReadFile(filepath.Join(stateDir, "tailproxy.log"))
	if strings.Contains(string(logData), tok1) {
		t.Fatal("token leaked into the log file")
	}

	// 2. Stop keeps the token; the next start reuses it.
	stop()
	if _, err := os.Stat(tokenFile); err != nil {
		t.Fatal("token file removed by stop")
	}
	if out, err := run("token"); err != nil || strings.TrimSpace(out) != tok1 {
		t.Fatalf("token while stopped: %v %q", err, out)
	}
	tok2, url := start()
	if tok2 != tok1 {
		t.Fatalf("restart changed the token: %q -> %q", tok1, tok2)
	}
	if code := apiStatus(url, tok1); code != 200 {
		t.Fatalf("persisted token after restart: %d", code)
	}

	// 3. Rotate: new token in the file, effective after a restart.
	out, err := run("token", "--rotate")
	tok3 := strings.SplitN(out, "\n", 2)[0]
	if err != nil || tok3 == tok1 || len(tok3) != 43 || !strings.Contains(out, "重启后生效") {
		t.Fatalf("rotate: %v\n%s", err, out)
	}
	if code := apiStatus(url, tok1); code != 200 {
		t.Fatalf("running service must keep its token until restart: %d", code)
	}
	stop()
	tok4, url := start()
	if tok4 != tok3 {
		t.Fatalf("after rotate+restart token %q, want %q", tok4, tok3)
	}
	if code := apiStatus(url, tok1); code != 401 {
		t.Fatalf("old token after rotation: %d, want 401", code)
	}
	stop()

	// 4. --ephemeral-token: one-off token, token file untouched.
	tok5, _ := start("--ephemeral-token")
	if tok5 == tok3 {
		t.Fatal("ephemeral start reused the persisted token")
	}
	if got, _ := os.ReadFile(tokenFile); strings.TrimSpace(string(got)) != tok3 {
		t.Fatal("ephemeral start modified the token file")
	}
	if out, err := run("token"); err == nil || !strings.Contains(out, "一次性令牌") {
		t.Fatalf("token with ephemeral service: %v\n%s", err, out)
	}
	stop()
	if _, err := os.Stat(filepath.Join(stateDir, "tailproxy.json")); !os.IsNotExist(err) {
		t.Fatal("state file left behind after stop")
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
