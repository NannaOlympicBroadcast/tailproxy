package config

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
)

func TestAdversarialYAMLKernelPayloads(t *testing.T) {
	testCases := []struct {
		name      string
		yaml      string
		expectErr bool
		errSubstr string
		wantMode  string
	}{
		// Valid cases
		{
			name:      "explicit davin",
			yaml:      "kernel: davin\nrules: []\n",
			expectErr: false,
			wantMode:  KernelDavin,
		},
		{
			name:      "explicit bacarra",
			yaml:      "kernel: bacarra\nrules: []\n",
			expectErr: false,
			wantMode:  KernelBacarra,
		},
		{
			name:      "omitted kernel defaults to davin",
			yaml:      "rules: []\n",
			expectErr: false,
			wantMode:  KernelDavin,
		},
		{
			name:      "empty string quoted defaults to davin",
			yaml:      "kernel: \"\"\nrules: []\n",
			expectErr: false,
			wantMode:  KernelDavin,
		},
		{
			name:      "empty single quoted defaults to davin",
			yaml:      "kernel: ''\nrules: []\n",
			expectErr: false,
			wantMode:  KernelDavin,
		},
		{
			name:      "null defaults to davin",
			yaml:      "kernel: null\nrules: []\n",
			expectErr: false,
			wantMode:  KernelDavin,
		},
		{
			name:      "tilde null defaults to davin",
			yaml:      "kernel: ~\nrules: []\n",
			expectErr: false,
			wantMode:  KernelDavin,
		},

		// Case sensitivity attacks
		{
			name:      "uppercase DAVIN",
			yaml:      "kernel: DAVIN\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "uppercase BACARRA",
			yaml:      "kernel: BACARRA\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "titlecase Davin",
			yaml:      "kernel: Davin\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "titlecase Bacarra",
			yaml:      "kernel: Bacarra\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "mixed case DaViN",
			yaml:      "kernel: DaViN\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "mixed case BaCaRrA",
			yaml:      "kernel: BaCaRrA\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},

		// Whitespace attacks
		{
			name:      "leading space on davin",
			yaml:      "kernel: \" davin\"\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "trailing space on davin",
			yaml:      "kernel: \"davin \"\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "leading space on bacarra",
			yaml:      "kernel: \" bacarra\"\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "trailing space on bacarra",
			yaml:      "kernel: \"bacarra \"\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "both spaces on davin",
			yaml:      "kernel: \" davin \"\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "tab prefix",
			yaml:      "kernel: \"\\tdavin\"\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "tab suffix",
			yaml:      "kernel: \"bacarra\\t\"\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "only spaces",
			yaml:      "kernel: \"   \"\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "newline in string",
			yaml:      "kernel: \"davin\\n\"\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},

		// Numeric & type attacks
		{
			name:      "number 0",
			yaml:      "kernel: 0\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "number 123",
			yaml:      "kernel: 123\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "float 3.14",
			yaml:      "kernel: 3.14\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "boolean true",
			yaml:      "kernel: true\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "boolean false",
			yaml:      "kernel: false\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "list type",
			yaml:      "kernel: [davin]\nrules: []\n",
			expectErr: true,
		},
		{
			name:      "mapping type",
			yaml:      "kernel: {mode: davin}\nrules: []\n",
			expectErr: true,
		},
		{
			name:      "list of mappings",
			yaml:      "kernel: [{a: 1}]\nrules: []\n",
			expectErr: true,
		},

		// Typos and close misspellings
		{
			name:      "typo david",
			yaml:      "kernel: david\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "typo baccara",
			yaml:      "kernel: baccara\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "typo barraca",
			yaml:      "kernel: barraca\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "unrelated mode tsnet",
			yaml:      "kernel: tsnet\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "unrelated mode wireguard",
			yaml:      "kernel: wireguard\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},

		// Injection & special characters
		{
			name:      "null byte injection",
			yaml:      "kernel: \"davin\\x00\"\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "cyrillic homoglyph davin",
			yaml:      "kernel: \"d\u0430vin\"\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "cyrillic homoglyph bacarra",
			yaml:      "kernel: \"b\u0430carra\"\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "extremely long string",
			yaml:      fmt.Sprintf("kernel: %s\nrules: []\n", strings.Repeat("davin", 2000)),
			expectErr: true,
			errSubstr: "kernel",
		},
		{
			name:      "unknown field rejection",
			yaml:      "kernel_mode: davin\nrules: []\n",
			expectErr: true,
			errSubstr: "kernel_mode",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse([]byte(tc.yaml))
			if tc.expectErr {
				if err == nil {
					t.Fatalf("Parse(%q) expected error, but got nil; cfg.Kernel=%q", tc.yaml, cfg.Kernel)
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("Parse(%q) error %v does not contain expected substring %q", tc.yaml, err, tc.errSubstr)
				}
			} else {
				if err != nil {
					t.Fatalf("Parse(%q) unexpected error: %v", tc.yaml, err)
				}
				if cfg.Kernel != tc.wantMode {
					t.Fatalf("Parse(%q) cfg.Kernel = %q, want %q", tc.yaml, cfg.Kernel, tc.wantMode)
				}
			}
		})
	}
}

func TestDirectValidateWithoutDefaults(t *testing.T) {
	// Directly constructing Config without applyDefaults:
	// A zero-value Kernel string MUST fail Validate() because Validate() does not mutate defaults.
	cfgZero := &Config{
		Kernel: "",
		Rules:  []Rule{},
		Panel:  Panel{Listen: "127.0.0.1:7708"},
	}
	err := cfgZero.Validate()
	if err == nil {
		t.Fatalf("cfgZero.Validate() expected error for empty Kernel, got nil")
	}
	if !strings.Contains(err.Error(), "kernel") {
		t.Fatalf("expected error mentioning kernel, got: %v", err)
	}

	// Valid explicitly set Kernel
	cfgDavin := &Config{
		Kernel: KernelDavin,
		Rules:  []Rule{},
		Panel:  Panel{Listen: "127.0.0.1:7708"},
	}
	if err := cfgDavin.Validate(); err != nil {
		t.Fatalf("cfgDavin.Validate() unexpected error: %v", err)
	}

	cfgBacarra := &Config{
		Kernel: KernelBacarra,
		Rules:  []Rule{},
		Panel:  Panel{Listen: "127.0.0.1:7708"},
	}
	if err := cfgBacarra.Validate(); err != nil {
		t.Fatalf("cfgBacarra.Validate() unexpected error: %v", err)
	}
}

func TestConcurrentParsingAndValidationStress(t *testing.T) {
	const iterations = 500
	var wg sync.WaitGroup
	errCh := make(chan error, iterations)

	payloads := []string{
		"rules: []\n",
		"kernel: davin\nrules: []\n",
		"kernel: bacarra\nrules: []\n",
		"kernel: invalid\nrules: []\n",
		"kernel: DAVIN\nrules: []\n",
		"kernel: \"\"\nrules: []\n",
	}

	for i := 0; i < iterations; i++ {
		wg.Add(1)
		payload := payloads[i%len(payloads)]
		go func(p string) {
			defer wg.Done()
			cfg, err := Parse([]byte(p))
			if strings.Contains(p, "invalid") || strings.Contains(p, "DAVIN") {
				if err == nil {
					errCh <- fmt.Errorf("expected error for payload %q, got nil", p)
				}
			} else {
				if err != nil {
					errCh <- fmt.Errorf("unexpected error for payload %q: %w", p, err)
				}
				if cfg == nil || (cfg.Kernel != KernelDavin && cfg.Kernel != KernelBacarra) {
					errCh <- fmt.Errorf("unexpected kernel mode in parsed config for payload %q", p)
				}
			}
		}(payload)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent stress failure: %v", err)
	}
}

func TestKernelMutationFuzz(t *testing.T) {
	// Oracle: Only strictly "davin" and "bacarra" are valid. Any random perturbation must fail.
	baseWords := []string{"davin", "bacarra"}
	separators := []string{" ", "\t", "\n", "\r", "-", "_", ":", "\"", "'"}

	r := rand.New(rand.NewSource(42))
	for i := 0; i < 300; i++ {
		base := baseWords[r.Intn(len(baseWords))]
		// Apply mutation
		mutationType := r.Intn(4)
		var mutated string
		switch mutationType {
		case 0:
			// Random capitalization
			chars := []rune(base)
			idx := r.Intn(len(chars))
			chars[idx] = rune(strings.ToUpper(string(chars[idx]))[0])
			mutated = string(chars)
		case 1:
			// Add prefix or suffix separator
			sep := separators[r.Intn(len(separators))]
			if r.Intn(2) == 0 {
				mutated = sep + base
			} else {
				mutated = base + sep
			}
		case 2:
			// Byte substitution
			chars := []rune(base)
			idx := r.Intn(len(chars))
			chars[idx] = rune('a' + r.Intn(26))
			mutated = string(chars)
			if mutated == "davin" || mutated == "bacarra" {
				continue
			}
		case 3:
			// Truncation or addition
			if len(base) > 2 && r.Intn(2) == 0 {
				mutated = base[:len(base)-1]
			} else {
				mutated = base + "x"
			}
		}

		yamlPayload := fmt.Sprintf("kernel: %q\nrules: []\n", mutated)
		cfg, err := Parse([]byte(yamlPayload))
		if mutated == "davin" || mutated == "bacarra" {
			if err != nil {
				t.Fatalf("unexpected failure for valid mutation %q: %v", mutated, err)
			}
		} else {
			if err == nil {
				t.Fatalf("oracle violation: mutation %q was accepted! Resulting kernel=%q", mutated, cfg.Kernel)
			}
		}
	}
}
