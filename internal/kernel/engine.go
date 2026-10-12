// Package kernel defines the proxy engine abstraction interface and common
// types for tailproxy's dual-kernel architecture (Davin and Bacarra).
package kernel

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/panel"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
)

// Mode denotes the proxy kernel operation mode.
type Mode string

const (
	// ModeDavin is the embedded tsnet multi-node transparent proxy engine mode.
	ModeDavin Mode = "davin"
	// ModeBacarra is the host routing table hijacking engine mode interfacing
	// with the official Tailscale client.
	ModeBacarra Mode = "bacarra"
)

// IsValid reports whether m is a supported kernel mode.
func (m Mode) IsValid() bool {
	return m == ModeDavin || m == ModeBacarra
}

// String returns the string representation of m.
func (m Mode) String() string {
	return string(m)
}

// ParseMode parses a string into a Mode, returning an error if unrecognized.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case ModeDavin:
		return ModeDavin, nil
	case ModeBacarra:
		return ModeBacarra, nil
	default:
		return "", fmt.Errorf("unknown kernel mode: %q", s)
	}
}

// FromConfig converts a config kernel string into a Mode, defaulting to ModeDavin if empty.
func FromConfig(k string) Mode {
	if k == "" {
		return ModeDavin
	}
	return Mode(k)
}

// Engine is the unified interface implemented by both Davin and Bacarra engines.
type Engine interface {
	// Type returns the active kernel type (ModeDavin or ModeBacarra).
	Type() Mode

	// Start launches engine background workers, listeners, and resources.
	Start(ctx context.Context) error

	// Close gracefully shuts down the engine and releases all allocated resources.
	Close() error

	// Reload dynamically applies configuration and rule updates without restart.
	Reload(cfg *config.Config, rules *rule.Engine) error

	// Status returns serializable operational status for CLI and panel.
	Status() any

	// Components returns panel component items for web UI and tpctl status.
	Components() []panel.Component

	// Teardown cleans up any stale routes or state left by crashes or previous runs.
	Teardown() error
}

// Factory instantiates an Engine for the given configuration.
type Factory func(cfg *config.Config, stateDir string, logf func(string, ...any)) (Engine, error)

var (
	factoriesMu sync.RWMutex
	factories   = make(map[Mode]Factory)
)

// Register registers an Engine factory for the specified mode.
func Register(mode Mode, f Factory) {
	factoriesMu.Lock()
	defer factoriesMu.Unlock()
	factories[mode] = f
}

// RegisteredModes returns all registered kernel modes sorted alphabetically.
func RegisteredModes() []Mode {
	factoriesMu.RLock()
	defer factoriesMu.RUnlock()
	modes := make([]Mode, 0, len(factories))
	for m := range factories {
		modes = append(modes, m)
	}
	sort.Slice(modes, func(i, j int) bool { return modes[i] < modes[j] })
	return modes
}

// New returns a new Engine for cfg based on cfg.Kernel.
func New(cfg *config.Config, stateDir string, logf func(string, ...any)) (Engine, error) {
	if cfg == nil {
		return nil, errors.New("kernel: nil configuration")
	}
	mode := FromConfig(cfg.Kernel)
	factoriesMu.RLock()
	factory, ok := factories[mode]
	factoriesMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("kernel: unsupported or unregistered kernel mode %q (registered: %v)", mode, RegisteredModes())
	}
	return factory(cfg, stateDir, logf)
}
