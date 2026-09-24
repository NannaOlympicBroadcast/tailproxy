package panel

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadOrCreateToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailproxy.token")
	tok, created, err := LoadOrCreateToken(path)
	if err != nil || !created || len(tok) != 43 {
		t.Fatalf("first call: %q %v %v", tok, created, err)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", info.Mode().Perm())
		}
	}
	again, created, err := LoadOrCreateToken(path)
	if err != nil || created || again != tok {
		t.Fatalf("second call: %q %v %v, want the same token", again, created, err)
	}
	rotated, err := RotateToken(path)
	if err != nil || rotated == tok || len(rotated) != 43 {
		t.Fatalf("rotate: %q %v", rotated, err)
	}
	if got, _ := ReadTokenFile(path); got != rotated {
		t.Fatalf("after rotate file has %q, want %q", got, rotated)
	}
}

func TestTokenFileChecks(t *testing.T) {
	dir := t.TempDir()
	short := filepath.Join(dir, "short")
	os.WriteFile(short, []byte("abc\n"), 0o600)
	if _, _, err := LoadOrCreateToken(short); err == nil || !strings.Contains(err.Error(), "内容无效") {
		t.Fatalf("short token: %v", err)
	}
	if runtime.GOOS != "windows" {
		open := filepath.Join(dir, "open")
		os.WriteFile(open, []byte("0123456789abcdef0123\n"), 0o644)
		os.Chmod(open, 0o644)
		if _, _, err := LoadOrCreateToken(open); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Fatalf("world-readable token file: %v", err)
		}
	}
}

func TestNewWithTokenFile(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfg, []byte("rules: []\n"), 0o600)
	tokFile := filepath.Join(dir, "tailproxy.token")
	s1, err := New(cfg, "test", Options{TokenFile: tokFile})
	if err != nil || !s1.TokenCreated() || s1.TokenFile() != tokFile || s1.tokenSource() != "file:"+tokFile {
		t.Fatalf("first: %v created=%v file=%q", err, s1.TokenCreated(), s1.TokenFile())
	}
	s2, err := New(cfg, "test", Options{TokenFile: tokFile})
	if err != nil || s2.TokenCreated() || s2.Token() != s1.Token() {
		t.Fatalf("restart must reuse the persisted token: %v", err)
	}
	// An environment token still takes precedence and leaves the file alone.
	os.WriteFile(cfg, []byte("panel: {auth_token_env: TP_TEST_TOKEN}\nrules: []\n"), 0o600)
	t.Setenv("TP_TEST_TOKEN", "env-token-0123456789")
	s3, err := New(cfg, "test", Options{TokenFile: tokFile})
	if err != nil || s3.Token() != "env-token-0123456789" || s3.TokenFile() != "" {
		t.Fatalf("env precedence: %v %q %q", err, s3.Token(), s3.TokenFile())
	}
	if got, _ := ReadTokenFile(tokFile); got != s1.Token() {
		t.Fatal("env token must not overwrite the token file")
	}
}
