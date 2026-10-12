package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStress_Check_ValidConfigurations(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name       string
		yaml       string
		wantKernel string
	}{
		{
			name: "ExplicitDavin",
			yaml: `
kernel: davin
egress: [{name: us, exit_node: us-vps}]
rules:
  - {domain_suffix: [openai.com], egress: us}
  - {final: direct}
`,
			wantKernel: "davin",
		},
		{
			name: "DefaultOmittedKernel",
			yaml: `
egress: [{name: us, exit_node: us-vps}]
rules:
  - {domain_suffix: [openai.com], egress: us}
  - {final: direct}
`,
			wantKernel: "davin",
		},
		{
			name: "ExplicitBacarra",
			yaml: `
kernel: bacarra
dns:
  mode: fakeip
rules:
  - {ip_cidr: [1.1.1.0/24], egress: direct}
  - {final: direct}
`,
			wantKernel: "bacarra",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name+".yaml")
			if err := os.WriteFile(path, []byte(tt.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := check([]string{"-c", path}, &out); err != nil {
				t.Fatalf("check failed on valid config: %v, output: %s", err, out.String())
			}
			str := out.String()
			if !strings.Contains(str, "配置有效") {
				t.Errorf("output missing '配置有效': %s", str)
			}
			if !strings.Contains(str, "内核模式 "+tt.wantKernel) {
				t.Errorf("output missing '内核模式 %s': %s", tt.wantKernel, str)
			}
		})
	}
}

func TestStress_Check_MissingAndCorruptFiles(t *testing.T) {
	dir := t.TempDir()

	// 1. Missing file
	var out bytes.Buffer
	missingPath := filepath.Join(dir, "does_not_exist.yaml")
	if err := check([]string{"-c", missingPath}, &out); err == nil {
		t.Errorf("expected error for missing file, got nil")
	}

	// 2. Directory path instead of file
	if err := check([]string{"-c", dir}, &out); err == nil {
		t.Errorf("expected error for directory path, got nil")
	}

	// 3. Corrupt YAML syntax
	corruptPath := filepath.Join(dir, "corrupt.yaml")
	if err := os.WriteFile(corruptPath, []byte("kernel: [unclosed list\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := check([]string{"-c", corruptPath}, &out); err == nil {
		t.Errorf("expected error for corrupt YAML syntax, got nil")
	}

	// 4. Empty file
	emptyPath := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(emptyPath, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	// An empty file has no rules/egress, check if it fails or passes
	// empty config has empty rules, which is valid or empty
	_ = check([]string{"-c", emptyPath}, &out)
}

func TestStress_Check_MalformedAndUnknownKernelOptions(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name      string
		yaml      string
		wantError string
	}{
		{
			name: "UnknownKernelModeString",
			yaml: `
kernel: invalid_mode
egress: [{name: us, exit_node: us-vps}]
rules: [{final: direct}]
`,
			wantError: "unknown kernel",
		},
		{
			name: "CaseSensitivityDavin",
			yaml: `
kernel: Davin
egress: [{name: us, exit_node: us-vps}]
rules: [{final: direct}]
`,
			wantError: "unknown kernel",
		},
		{
			name: "CaseSensitivityBacarra",
			yaml: `
kernel: BACARRA
egress: [{name: us, exit_node: us-vps}]
rules: [{final: direct}]
`,
			wantError: "unknown kernel",
		},
		{
			name: "IntegerKernelOption",
			yaml: `
kernel: 1234
egress: [{name: us, exit_node: us-vps}]
rules: [{final: direct}]
`,
			wantError: "unknown kernel mode",
		},
		{
			name: "BooleanKernelOption",
			yaml: `
kernel: true
egress: [{name: us, exit_node: us-vps}]
rules: [{final: direct}]
`,
			wantError: "unknown kernel mode",
		},
		{
			name: "ListKernelOption",
			yaml: `
kernel: ["davin"]
egress: [{name: us, exit_node: us-vps}]
rules: [{final: direct}]
`,
			wantError: "cannot unmarshal",
		},
		{
			name: "UnknownFieldKernelMode",
			yaml: `
kernel_mode: davin
egress: [{name: us, exit_node: us-vps}]
rules: [{final: direct}]
`,
			wantError: "not found in type config.Config",
		},
		{
			name: "UnknownFieldKernelType",
			yaml: `
kernel_type: bacarra
egress: [{name: us, exit_node: us-vps}]
rules: [{final: direct}]
`,
			wantError: "not found in type config.Config",
		},
		{
			name: "UnknownFieldKernelEngine",
			yaml: `
kernel_engine: davin
egress: [{name: us, exit_node: us-vps}]
rules: [{final: direct}]
`,
			wantError: "not found in type config.Config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name+".yaml")
			if err := os.WriteFile(path, []byte(tt.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			err := check([]string{"-c", path}, &out)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil. Output: %s", tt.wantError, out.String())
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantError)
			}
		})
	}
}

func TestStress_Check_CLIArgumentHandling(t *testing.T) {
	dir := t.TempDir()
	goodPath := filepath.Join(dir, "good.yaml")
	if err := os.WriteFile(goodPath, []byte("egress: [{name: us, exit_node: us-vps}]\nrules: [{final: direct}]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer

	// 1. Extra positional argument
	err := check([]string{"-c", goodPath, "unexpected_extra_arg"}, &out)
	if err == nil || !strings.Contains(err.Error(), "unexpected argument") {
		t.Fatalf("expected 'unexpected argument' error, got: %v", err)
	}
	if !strings.Contains(out.String(), "用法：tailproxy check") {
		t.Errorf("expected usage output on bad args, got: %s", out.String())
	}

	// 2. Help flag (-h / -help)
	out.Reset()
	err = check([]string{"-h"}, &out)
	if err != nil {
		t.Fatalf("expected nil error on help flag, got: %v", err)
	}
	if !strings.Contains(out.String(), "用法：tailproxy check") {
		t.Errorf("expected usage output on -h, got: %s", out.String())
	}

	// 3. Unknown flag
	out.Reset()
	err = check([]string{"-unknown-flag"}, &out)
	if err == nil {
		t.Fatalf("expected error on unknown flag, got nil")
	}
}
