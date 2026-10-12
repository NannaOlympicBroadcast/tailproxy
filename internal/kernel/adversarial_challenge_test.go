package kernel

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
)

func TestAdversarialParseMode(t *testing.T) {
	testCases := []struct {
		input     string
		wantMode  Mode
		expectErr bool
	}{
		// Valid cases
		{"davin", ModeDavin, false},
		{"bacarra", ModeBacarra, false},

		// Empty string
		{"", "", true},

		// Case sensitivity
		{"DAVIN", "", true},
		{"BACARRA", "", true},
		{"Davin", "", true},
		{"Bacarra", "", true},
		{"DaViN", "", true},
		{"BaCaRrA", "", true},

		// Whitespace
		{" davin", "", true},
		{"davin ", "", true},
		{" bacarra", "", true},
		{"bacarra ", "", true},
		{" davin ", "", true},
		{"\tdavin", "", true},
		{"bacarra\n", "", true},
		{"   ", "", true},

		// Typos and alternatives
		{"david", "", true},
		{"baccara", "", true},
		{"tsnet", "", true},
		{"wireguard", "", true},
		{"auto", "", true},
		{"null", "", true},
		{"0", "", true},
		{"1", "", true},
		{"true", "", true},
		{"false", "", true},

		// Unicode & injections
		{"davin\x00", "", true},
		{"d\u0430vin", "", true},
		{"b\u0430carra", "", true},
		{strings.Repeat("bacarra", 500), "", true},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("ParseMode(%q)", tc.input), func(t *testing.T) {
			mode, err := ParseMode(tc.input)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("ParseMode(%q) expected error, got nil (mode=%q)", tc.input, mode)
				}
				if mode != "" {
					t.Fatalf("ParseMode(%q) expected empty mode on error, got %q", tc.input, mode)
				}
			} else {
				if err != nil {
					t.Fatalf("ParseMode(%q) unexpected error: %v", tc.input, err)
				}
				if mode != tc.wantMode {
					t.Fatalf("ParseMode(%q) = %q, want %q", tc.input, mode, tc.wantMode)
				}
			}
		})
	}
}

func TestAdversarialModeMethods(t *testing.T) {
	// IsValid oracle
	if !ModeDavin.IsValid() {
		t.Errorf("ModeDavin.IsValid() must be true")
	}
	if !ModeBacarra.IsValid() {
		t.Errorf("ModeBacarra.IsValid() must be true")
	}
	invalidModes := []Mode{
		"",
		"DAVIN",
		"BACARRA",
		"davin ",
		" bacarra",
		"invalid",
		"tsnet",
	}
	for _, m := range invalidModes {
		if m.IsValid() {
			t.Errorf("Mode(%q).IsValid() expected false, got true", m)
		}
	}

	// String() oracle
	if ModeDavin.String() != "davin" {
		t.Errorf("ModeDavin.String() = %q, want %q", ModeDavin.String(), "davin")
	}
	if ModeBacarra.String() != "bacarra" {
		t.Errorf("ModeBacarra.String() = %q, want %q", ModeBacarra.String(), "bacarra")
	}

	// FromConfig oracle
	if FromConfig("") != ModeDavin {
		t.Errorf("FromConfig(\"\") must default to ModeDavin, got %q", FromConfig(""))
	}
	if FromConfig("davin") != ModeDavin {
		t.Errorf("FromConfig(\"davin\") must be ModeDavin, got %q", FromConfig("davin"))
	}
	if FromConfig("bacarra") != ModeBacarra {
		t.Errorf("FromConfig(\"bacarra\") must be ModeBacarra, got %q", FromConfig("bacarra"))
	}
	if FromConfig("unknown") != Mode("unknown") {
		t.Errorf("FromConfig(\"unknown\") = %q, want %q", FromConfig("unknown"), Mode("unknown"))
	}
}

func TestConcurrentParseModeStress(t *testing.T) {
	const goroutines = 1000
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)

	inputs := []string{
		"davin",
		"bacarra",
		"DAVIN",
		"",
		"invalid",
		"davin ",
	}

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		in := inputs[i%len(inputs)]
		go func(s string) {
			defer wg.Done()
			m, err := ParseMode(s)
			if s == "davin" {
				if err != nil || m != ModeDavin {
					errCh <- fmt.Errorf("unexpected error for davin: %v, mode=%v", err, m)
				}
			} else if s == "bacarra" {
				if err != nil || m != ModeBacarra {
					errCh <- fmt.Errorf("unexpected error for bacarra: %v, mode=%v", err, m)
				}
			} else {
				if err == nil {
					errCh <- fmt.Errorf("expected error for %q, got nil (mode=%v)", s, m)
				}
			}
		}(in)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent stress error: %v", err)
	}
}

func TestParseModeRandomFuzz(t *testing.T) {
	r := rand.New(rand.NewSource(1337))
	for i := 0; i < 500; i++ {
		// Generate random string
		length := r.Intn(20)
		bytes := make([]byte, length)
		for j := 0; j < length; j++ {
			bytes[j] = byte(r.Intn(256))
		}
		str := string(bytes)
		mode, err := ParseMode(str)
		if str == "davin" {
			if err != nil || mode != ModeDavin {
				t.Fatalf("fuzz failed on valid 'davin': %v", err)
			}
		} else if str == "bacarra" {
			if err != nil || mode != ModeBacarra {
				t.Fatalf("fuzz failed on valid 'bacarra': %v", err)
			}
		} else {
			if err == nil {
				t.Fatalf("fuzz accepted invalid string %q as mode %q", str, mode)
			}
		}
	}
}
