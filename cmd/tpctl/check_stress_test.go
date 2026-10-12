package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStress_TPCTL_Check_ValidConfigurations(t *testing.T) {
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
			out := withStdout(t, func() {
				if err := run("tpctl", []string{"--state-dir", dir, "check", "-c", path}); err != nil {
					t.Fatalf("tpctl check failed on valid config: %v", err)
				}
			})
			if !strings.Contains(out, "配置有效") {
				t.Errorf("tpctl check output missing '配置有效': %s", out)
			}
			if !strings.Contains(out, "内核模式 "+tt.wantKernel) {
				t.Errorf("tpctl check output missing '内核模式 %s': %s", tt.wantKernel, out)
			}
		})
	}
}

func TestStress_TPCTL_Check_MissingAndCorruptFiles(t *testing.T) {
	dir := t.TempDir()

	// 1. Missing file
	missingPath := filepath.Join(dir, "missing.yaml")
	if err := run("tpctl", []string{"--state-dir", dir, "check", "-c", missingPath}); err == nil {
		t.Errorf("tpctl check should fail on missing file, got nil")
	}

	// 2. Directory path
	if err := run("tpctl", []string{"--state-dir", dir, "check", "-c", dir}); err == nil {
		t.Errorf("tpctl check should fail on directory path, got nil")
	}

	// 3. Corrupt YAML syntax
	corruptPath := filepath.Join(dir, "corrupt.yaml")
	if err := os.WriteFile(corruptPath, []byte("kernel: [unclosed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run("tpctl", []string{"--state-dir", dir, "check", "-c", corruptPath}); err == nil {
		t.Errorf("tpctl check should fail on corrupt YAML, got nil")
	}
}

func TestStress_TPCTL_Check_MalformedAndUnknownKernelOptions(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name      string
		yaml      string
		wantError string
	}{
		{
			name:      "UnknownKernelModeString",
			yaml:      "kernel: unknown_kernel\negress: [{name: us, exit_node: us-vps}]\nrules: [{final: direct}]\n",
			wantError: "unknown kernel mode",
		},
		{
			name:      "CaseSensitivityDavin",
			yaml:      "kernel: Davin\negress: [{name: us, exit_node: us-vps}]\nrules: [{final: direct}]\n",
			wantError: "unknown kernel mode",
		},
		{
			name:      "CaseSensitivityBacarra",
			yaml:      "kernel: BACARRA\negress: [{name: us, exit_node: us-vps}]\nrules: [{final: direct}]\n",
			wantError: "unknown kernel mode",
		},
		{
			name:      "IntegerKernelOption",
			yaml:      "kernel: 9999\negress: [{name: us, exit_node: us-vps}]\nrules: [{final: direct}]\n",
			wantError: "unknown kernel mode",
		},
		{
			name:      "BooleanKernelOption",
			yaml:      "kernel: false\negress: [{name: us, exit_node: us-vps}]\nrules: [{final: direct}]\n",
			wantError: "unknown kernel mode",
		},
		{
			name:      "ListKernelOption",
			yaml:      "kernel: [\"davin\"]\negress: [{name: us, exit_node: us-vps}]\nrules: [{final: direct}]\n",
			wantError: "cannot unmarshal",
		},
		{
			name:      "UnknownFieldKernelMode",
			yaml:      "kernel_mode: davin\negress: [{name: us, exit_node: us-vps}]\nrules: [{final: direct}]\n",
			wantError: "not found in type config.Config",
		},
		{
			name:      "UnknownFieldKernelType",
			yaml:      "kernel_type: bacarra\negress: [{name: us, exit_node: us-vps}]\nrules: [{final: direct}]\n",
			wantError: "not found in type config.Config",
		},
		{
			name:      "UnknownFieldKernelEngine",
			yaml:      "kernel_engine: davin\negress: [{name: us, exit_node: us-vps}]\nrules: [{final: direct}]\n",
			wantError: "not found in type config.Config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name+".yaml")
			if err := os.WriteFile(path, []byte(tt.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			err := run("tpctl", []string{"--state-dir", dir, "check", "-c", path})
			if err == nil {
				t.Fatalf("expected tpctl check error containing %q, got nil", tt.wantError)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantError)
			}
		})
	}
}

func TestStress_TPCTL_Check_CLIArgumentHandling(t *testing.T) {
	dir := t.TempDir()
	goodPath := filepath.Join(dir, "good.yaml")
	if err := os.WriteFile(goodPath, []byte("egress: [{name: us, exit_node: us-vps}]\nrules: [{final: direct}]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. Extra positional argument
	err := run("tpctl", []string{"--state-dir", dir, "check", "-c", goodPath, "spurious_arg"})
	if err == nil || !strings.Contains(err.Error(), "unexpected argument") {
		t.Fatalf("expected 'unexpected argument' error, got: %v", err)
	}

	// 2. Help flag (-h)
	out := withStdout(t, func() {
		err = run("tpctl", []string{"--state-dir", dir, "check", "-h"})
		if err != nil {
			t.Fatalf("expected nil error on tpctl check -h, got: %v", err)
		}
	})
	if !strings.Contains(out, "用法：tpctl check") {
		t.Errorf("expected usage output on tpctl check -h, got: %s", out)
	}
}
