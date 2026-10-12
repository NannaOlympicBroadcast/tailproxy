package main

import (
	"strings"
	"testing"
)

func TestAdversarial_ParseCaptureArgs(t *testing.T) {
	// 1. Valid bare "down"
	subcmd, dir, err := parseCaptureArgs([]string{"down"})
	if err != nil {
		t.Fatalf("parseCaptureArgs(['down']) error: %v", err)
	}
	if subcmd != "down" {
		t.Errorf("subcmd = %q, want 'down'", subcmd)
	}
	if dir == "" {
		t.Errorf("expected default stateDir to be populated")
	}

	// 2. Valid with --state-dir after "down"
	subcmd, dir, err = parseCaptureArgs([]string{"down", "--state-dir", "C:\\test\\dir"})
	if err != nil {
		t.Fatalf("parseCaptureArgs with --state-dir error: %v", err)
	}
	if subcmd != "down" || dir != "C:\\test\\dir" {
		t.Errorf("subcmd=%q, dir=%q; want down and C:\\test\\dir", subcmd, dir)
	}

	// 3. Valid with --state-dir before "down"
	subcmd, dir, err = parseCaptureArgs([]string{"--state-dir", "C:\\test\\dir", "down"})
	if err != nil {
		t.Fatalf("parseCaptureArgs with leading --state-dir error: %v", err)
	}
	if subcmd != "down" || dir != "C:\\test\\dir" {
		t.Errorf("subcmd=%q, dir=%q; want down and C:\\test\\dir", subcmd, dir)
	}

	// 4. Invalid subcommands
	invalidInputs := [][]string{
		{},
		{""},
		{"up"},
		{"status"},
		{"down", "extra"},
		{"extra", "down"},
		{"down", "--unknown-flag"},
		{"--invalid"},
	}

	for _, input := range invalidInputs {
		t.Run(strings.Join(input, "_"), func(t *testing.T) {
			_, _, err := parseCaptureArgs(input)
			if err == nil {
				t.Fatalf("parseCaptureArgs(%v) expected error, got nil", input)
			}
		})
	}
}
