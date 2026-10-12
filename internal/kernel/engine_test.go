package kernel

import (
	"context"
	"reflect"
	"testing"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/panel"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
)

func TestModeConstants(t *testing.T) {
	if ModeDavin != "davin" {
		t.Fatalf("ModeDavin = %q, want %q", ModeDavin, "davin")
	}
	if ModeBacarra != "bacarra" {
		t.Fatalf("ModeBacarra = %q, want %q", ModeBacarra, "bacarra")
	}
	if !ModeDavin.IsValid() {
		t.Errorf("ModeDavin.IsValid() = false, want true")
	}
	if !ModeBacarra.IsValid() {
		t.Errorf("ModeBacarra.IsValid() = false, want true")
	}
	if Mode("invalid").IsValid() {
		t.Errorf("Mode(\"invalid\").IsValid() = true, want false")
	}
	if Mode("").IsValid() {
		t.Errorf("Mode(\"\").IsValid() = true, want false")
	}
	if ModeDavin.String() != "davin" {
		t.Errorf("ModeDavin.String() = %q, want %q", ModeDavin.String(), "davin")
	}
}

func TestParseMode(t *testing.T) {
	tests := []struct {
		input   string
		want    Mode
		wantErr bool
	}{
		{"davin", ModeDavin, false},
		{"bacarra", ModeBacarra, false},
		{"unknown", "", true},
		{"", "", true},
		{"DAVIN", "", true},
	}
	for _, tt := range tests {
		got, err := ParseMode(tt.input)
		if tt.wantErr && err == nil {
			t.Errorf("ParseMode(%q) expected error, got nil", tt.input)
		} else if !tt.wantErr && err != nil {
			t.Errorf("ParseMode(%q) unexpected error: %v", tt.input, err)
		} else if !tt.wantErr && got != tt.want {
			t.Errorf("ParseMode(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestFromConfig(t *testing.T) {
	if got := FromConfig(""); got != ModeDavin {
		t.Errorf("FromConfig(\"\") = %q, want %q", got, ModeDavin)
	}
	if got := FromConfig("davin"); got != ModeDavin {
		t.Errorf("FromConfig(\"davin\") = %q, want %q", got, ModeDavin)
	}
	if got := FromConfig("bacarra"); got != ModeBacarra {
		t.Errorf("FromConfig(\"bacarra\") = %q, want %q", got, ModeBacarra)
	}
	if got := FromConfig("custom"); got != Mode("custom") {
		t.Errorf("FromConfig(\"custom\") = %q, want %q", got, Mode("custom"))
	}
}

// stubEngine implements the Engine interface for verification.
type stubEngine struct {
	mode       Mode
	started    bool
	closed     bool
	tornDown   bool
	reloaded   bool
	statusData any
	comps      []panel.Component
}

var _ Engine = (*stubEngine)(nil)

func (s *stubEngine) Type() Mode {
	return s.mode
}

func (s *stubEngine) Start(ctx context.Context) error {
	s.started = true
	return nil
}

func (s *stubEngine) Close() error {
	s.closed = true
	return nil
}

func (s *stubEngine) Reload(cfg *config.Config, rules *rule.Engine) error {
	s.reloaded = true
	return nil
}

func (s *stubEngine) Status() any {
	return s.statusData
}

func (s *stubEngine) Components() []panel.Component {
	return s.comps
}

func (s *stubEngine) Teardown() error {
	s.tornDown = true
	return nil
}

func TestEngineInterfaceMethods(t *testing.T) {
	comp := panel.Component{
		Name:   "kernel",
		State:  "running",
		Detail: "bacarra",
	}
	status := map[string]string{"state": "ok"}
	eng := &stubEngine{
		mode:       ModeBacarra,
		statusData: status,
		comps:      []panel.Component{comp},
	}

	var iface Engine = eng

	if iface.Type() != ModeBacarra {
		t.Errorf("iface.Type() = %q, want %q", iface.Type(), ModeBacarra)
	}
	if err := iface.Start(context.Background()); err != nil {
		t.Errorf("iface.Start() error = %v", err)
	}
	if !eng.started {
		t.Errorf("eng.started = false, want true")
	}

	if err := iface.Reload(&config.Config{}, nil); err != nil {
		t.Errorf("iface.Reload() error = %v", err)
	}
	if !eng.reloaded {
		t.Errorf("eng.reloaded = false, want true")
	}

	if !reflect.DeepEqual(iface.Status(), status) {
		t.Errorf("iface.Status() = %v, want %v", iface.Status(), status)
	}

	comps := iface.Components()
	if len(comps) != 1 || comps[0].Detail != "bacarra" {
		t.Errorf("iface.Components() = %+v, want detail 'bacarra'", comps)
	}

	if err := iface.Close(); err != nil {
		t.Errorf("iface.Close() error = %v", err)
	}
	if !eng.closed {
		t.Errorf("eng.closed = false, want true")
	}

	if err := iface.Teardown(); err != nil {
		t.Errorf("iface.Teardown() error = %v", err)
	}
	if !eng.tornDown {
		t.Errorf("eng.tornDown = false, want true")
	}
}

func TestRegistryAndNew(t *testing.T) {
	// Test nil config error
	if _, err := New(nil, "", nil); err == nil {
		t.Fatal("New(nil) expected error, got nil")
	}

	testMode := Mode("test-mode")
	called := false
	Register(testMode, func(cfg *config.Config, stateDir string, logf func(string, ...any)) (Engine, error) {
		called = true
		return &stubEngine{mode: testMode}, nil
	})

	modes := RegisteredModes()
	found := false
	for _, m := range modes {
		if m == testMode {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("RegisteredModes() does not contain %q: %v", testMode, modes)
	}

	cfg := &config.Config{Kernel: string(testMode)}
	eng, err := New(cfg, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("New with registered mode failed: %v", err)
	}
	if !called {
		t.Fatal("factory was not invoked")
	}
	if eng.Type() != testMode {
		t.Fatalf("eng.Type() = %q, want %q", eng.Type(), testMode)
	}

	// Test unregistered mode
	unregCfg := &config.Config{Kernel: "unregistered-kernel"}
	if _, err := New(unregCfg, "", nil); err == nil {
		t.Fatal("New with unregistered mode expected error, got nil")
	}
}
