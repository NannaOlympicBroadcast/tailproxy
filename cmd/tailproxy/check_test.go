package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	os.WriteFile(good, []byte("egress: [{name: us, exit_node: us-vps}]\nrules:\n  - {domain_suffix: [openai.com], egress: us}\n  - {final: direct}\n"), 0o600)
	var out bytes.Buffer
	if err := check([]string{"-c", good}, &out); err != nil || !strings.Contains(out.String(), "配置有效") || !strings.Contains(out.String(), "出口 1 个") {
		t.Fatalf("good config: %v %q", err, out.String())
	}
	bad := filepath.Join(dir, "bad.yaml")
	os.WriteFile(bad, []byte("rules:\n  - {domain_suffix: [openai.com], egress: nowhere}\n"), 0o600)
	if err := check([]string{"-c", bad}, &out); err == nil || !strings.Contains(err.Error(), "nowhere") {
		t.Fatalf("unknown egress accepted: %v", err)
	}
	if err := check([]string{"-c", filepath.Join(dir, "missing.yaml")}, &out); err == nil {
		t.Fatal("missing file accepted")
	}
}
