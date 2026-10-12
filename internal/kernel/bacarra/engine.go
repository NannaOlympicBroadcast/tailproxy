package bacarra

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/fakeip"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/kernel"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/panel"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
)

func init() {
	kernel.Register(kernel.ModeBacarra, func(cfg *config.Config, stateDir string, logf func(string, ...any)) (kernel.Engine, error) {
		return New(cfg, stateDir, logf)
	})
}

var _ kernel.Engine = (*Engine)(nil)

// Engine implements kernel.Engine for Bacarra mode (host routing table hijacking via official Tailscale adapter).
type Engine struct {
	mu       sync.RWMutex
	cfg      *config.Config
	stateDir string
	logf     func(string, ...any)

	adapter  *AdapterInfo
	routes   *RouteManager
	pool     *fakeip.Pool
	poolFile string
	rules    func() *rule.Engine

	started bool
	closed  bool
}

// New creates a new Bacarra Engine by discovering the official Tailscale adapter on the host.
func New(cfg *config.Config, stateDir string, logf func(string, ...any)) (*Engine, error) {
	if logf == nil {
		logf = log.Printf
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	adapter, err := DiscoverAdapter(ctx)
	if err != nil {
		return nil, fmt.Errorf("bacarra: adapter discovery failed: %w", err)
	}

	rm, err := NewRouteManager(adapter, stateDir, logf)
	if err != nil {
		return nil, fmt.Errorf("bacarra: route manager init failed: %w", err)
	}

	return NewEngineWithManager(cfg, stateDir, logf, adapter, rm)
}

// NewEngineWithManager creates an Engine with an explicitly supplied AdapterInfo and RouteManager.
// This allows testing and specialized route manipulation without touching physical interfaces.
func NewEngineWithManager(cfg *config.Config, stateDir string, logf func(string, ...any), adapter *AdapterInfo, rm *RouteManager) (*Engine, error) {
	if adapter == nil {
		return nil, errors.New("bacarra: adapter cannot be nil")
	}
	if rm == nil {
		return nil, errors.New("bacarra: route manager cannot be nil")
	}
	if logf == nil {
		logf = log.Printf
	}

	e := &Engine{
		cfg:      cfg,
		stateDir: stateDir,
		logf:     logf,
		adapter:  adapter,
		routes:   rm,
	}

	if cfg != nil && cfg.DNS.Mode == "fakeip" {
		v4, v6 := fakeip.DefaultInet4, fakeip.DefaultInet6
		if cfg.DNS.FakeIP.Inet4 != "" {
			if parsed, err := config.ParsePrefix(cfg.DNS.FakeIP.Inet4); err == nil {
				v4 = parsed
			}
		}
		if cfg.DNS.FakeIP.Inet6 != "" {
			if parsed, err := config.ParsePrefix(cfg.DNS.FakeIP.Inet6); err == nil {
				v6 = parsed
			}
		}
		pool, err := fakeip.New(v4, v6)
		if err != nil {
			return nil, fmt.Errorf("bacarra: fakeip init failed: %w", err)
		}
		e.pool = pool
		if stateDir != "" {
			e.poolFile = filepath.Join(stateDir, "fakeip.json")
			if err := e.pool.Load(e.poolFile); err != nil && !errors.Is(err, os.ErrNotExist) {
				logf("bacarra: %v (starting with an empty FakeIP table)", err)
			}
		}
	}

	return e, nil
}

// SetRules configures the dynamic rule engine getter.
func (e *Engine) SetRules(fn func() *rule.Engine) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = fn
}

// Type returns kernel.ModeBacarra.
func (e *Engine) Type() kernel.Mode {
	return kernel.ModeBacarra
}

// Start initiates Bacarra engine operation by calculating and injecting host routes.
func (e *Engine) Start(ctx context.Context) error {
	e.mu.Lock()
	e.started = true
	e.mu.Unlock()
	return e.applyRoutes()
}

func (e *Engine) applyRoutes() error {
	e.mu.RLock()
	var prefixes []netip.Prefix
	if e.pool != nil {
		prefixes = append(prefixes, e.pool.Prefixes()...)
	}
	if e.rules != nil && e.rules() != nil {
		prefixes = append(prefixes, e.rules().RoutedPrefixes()...)
	}
	rm := e.routes
	e.mu.RUnlock()

	if rm != nil {
		return rm.Apply(prefixes)
	}
	return nil
}

// Close safely removes all injected host routes and saves the FakeIP pool table if active.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true

	var errs []error
	if e.routes != nil {
		if err := e.routes.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if e.pool != nil && e.poolFile != "" {
		if err := e.pool.Save(e.poolFile); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Reload applies updated configuration and rule sets, synchronizing routing table diffs.
func (e *Engine) Reload(cfg *config.Config, rules *rule.Engine) error {
	e.mu.Lock()
	e.cfg = cfg
	if rules != nil {
		e.rules = func() *rule.Engine { return rules }
	}
	e.mu.Unlock()
	return e.applyRoutes()
}

// Status returns operational statistics and currently injected route prefixes.
func (e *Engine) Status() any {
	e.mu.RLock()
	defer e.mu.RUnlock()

	routes := make([]string, 0)
	if e.routes != nil {
		for _, p := range e.routes.AppliedRoutes() {
			routes = append(routes, p.String())
		}
	}
	adapterName := ""
	adapterIndex := 0
	adapterIPs := make([]string, 0)
	if e.adapter != nil {
		adapterName = e.adapter.Name
		adapterIndex = e.adapter.Index
		for _, ip := range e.adapter.IPs {
			adapterIPs = append(adapterIPs, ip.String())
		}
	}
	return map[string]any{
		"mode":          string(kernel.ModeBacarra),
		"adapter_name":  adapterName,
		"adapter_index": adapterIndex,
		"adapter_ips":   adapterIPs,
		"routes":        routes,
		"routes_count":  len(routes),
	}
}

// Components returns panel components reflecting active Bacarra adapter and route hijacking state.
func (e *Engine) Components() []panel.Component {
	e.mu.RLock()
	defer e.mu.RUnlock()

	appliedCount := 0
	if e.routes != nil {
		appliedCount = len(e.routes.AppliedRoutes())
	}
	return []panel.Component{
		{
			Name:   "kernel",
			State:  "running",
			Detail: fmt.Sprintf("bacarra (宿主官方 Tailscale 路由劫持，网卡: %s)", e.adapter.Name),
		},
		{
			Name:   "tailscale_adapter",
			State:  "active",
			Detail: fmt.Sprintf("%s (索引 %d, 地址 %v)", e.adapter.Name, e.adapter.Index, e.adapter.IPs),
		},
		{
			Name:   "route_manager",
			State:  "active",
			Detail: fmt.Sprintf("已注入 %d 条路由规则 (FakeIP + CIDR)", appliedCount),
		},
	}
}

// Teardown cleans up any stale routes left in the state directory from previous crashes.
func (e *Engine) Teardown() error {
	return TeardownStale(e.stateDir, e.logf)
}

// Adapter returns the underlying official Tailscale AdapterInfo.
func (e *Engine) Adapter() *AdapterInfo {
	return e.adapter
}

// RouteManager returns the underlying RouteManager.
func (e *Engine) RouteManager() *RouteManager {
	return e.routes
}

// Pool returns the FakeIP pool if DNS mode is fakeip.
func (e *Engine) Pool() *fakeip.Pool {
	return e.pool
}
