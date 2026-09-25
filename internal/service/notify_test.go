//go:build unix

package service

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNotify(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "notify.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Skip("unixgram not available:", err)
	}
	defer conn.Close()
	t.Setenv("NOTIFY_SOCKET", sock)
	if !UnderSystemd() {
		t.Fatal("UnderSystemd() = false with NOTIFY_SOCKET set")
	}
	if err := Notify("READY=1"); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "READY=1" {
		t.Fatalf("got %q, %v", buf[:n], err)
	}

	t.Setenv("NOTIFY_SOCKET", "")
	t.Setenv("INVOCATION_ID", "")
	if UnderSystemd() || Notify("READY=1") != nil {
		t.Fatal("without systemd, Notify must be a silent no-op")
	}
}

func TestChildEnvDropsSystemd(t *testing.T) {
	t.Setenv("INVOCATION_ID", "abc")
	t.Setenv("NOTIFY_SOCKET", "/run/x")
	t.Setenv("JOURNAL_STREAM", "8:123")
	t.Setenv("TAILPROXY_KEEP", "1")
	t.Setenv("NOTIFY_SOCKET", "")
	if UnderSystemd() {
		t.Fatal("INVOCATION_ID alone must not mean a tailproxy unit")
	}
	t.Setenv("NOTIFY_SOCKET", "/run/x")
	env := strings.Join(childEnv(), "\n")
	for _, k := range []string{"INVOCATION_ID=", "NOTIFY_SOCKET=", "JOURNAL_STREAM="} {
		if strings.Contains(env, k) {
			t.Errorf("child env keeps %s", k)
		}
	}
	if !strings.Contains(env, "TAILPROXY_KEEP=1") {
		t.Error("child env lost other variables")
	}
}
