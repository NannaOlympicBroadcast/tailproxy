package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The paths that write nothing: help, the plan, declining, no rights,
// and reverting when nothing was applied. Writing and reverting are
// tested in internal/browserpolicy.
func TestDoctor(t *testing.T) {
	state := filepath.Join(t.TempDir(), "browser-policy.json")
	yes := func() bool { return true }
	no := func() bool { return false }
	run := func(stdin string, admin func() bool, args ...string) (string, error) {
		var out bytes.Buffer
		err := doctor(args, strings.NewReader(stdin), &out, state, admin)
		return out.String(), err
	}
	if out, err := run("", yes, "-h"); err != nil || !strings.Contains(out, "--apply-browser-policy") {
		t.Fatalf("help: %v %q", err, out)
	}
	if out, err := run("", no, "--all-browsers"); err != nil || !strings.Contains(out, "未应用") || !strings.Contains(out, "DnsOverHttpsMode") {
		t.Fatalf("plan: %v %q", err, out)
	}
	if _, err := run("", no, "--apply-browser-policy", "--all-browsers"); err == nil || !strings.Contains(err.Error(), "管理员") {
		t.Fatalf("apply without rights: %v", err)
	}
	out, err := run("no\n", yes, "--apply-browser-policy", "--all-browsers")
	if err == nil || !strings.Contains(err.Error(), "已取消") || !strings.Contains(out, "输入 yes") {
		t.Fatalf("declined: %v %q", err, out)
	}
	if _, err := os.Stat(state); err == nil {
		t.Fatal("state written after declining")
	}
	if out, err := run("", yes, "--revert-browser-policy"); err != nil || !strings.Contains(out, "没有需要撤销") {
		t.Fatalf("revert with nothing applied: %v %q", err, out)
	}
	if _, err := run("", yes, "--apply-browser-policy", "--revert-browser-policy"); err == nil {
		t.Fatal("both flags accepted")
	}
}
