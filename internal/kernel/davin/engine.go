package davin

import (
	"context"
	"log"
	"sync"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/egress"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/kernel"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/panel"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/proxy"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
)

func init() {
	kernel.Register(kernel.ModeDavin, func(cfg *config.Config, stateDir string, logf func(string, ...any)) (kernel.Engine, error) {
		return New(cfg, stateDir, logf)
	})
}

var _ kernel.Engine = (*Engine)(nil)

// Engine implements kernel.Engine for Davin mode (embedded multi-node tsnet proxy).
type Engine struct {
	mu       sync.RWMutex
	cfg      *config.Config
	stateDir string
	logf     func(string, ...any)

	mgr     *egress.Manager
	tracker *proxy.Tracker
	router  *proxy.Router
}

// New constructs a new Davin mode kernel Engine.
func New(cfg *config.Config, stateDir string, logf func(string, ...any)) (*Engine, error) {
	if logf == nil {
		logf = log.Printf
	}
	mgr, err := egress.New(cfg, stateDir, logf)
	if err != nil {
		return nil, err
	}
	tracker := proxy.NewTracker()
	router := &proxy.Router{
		Egress:  mgr,
		Tracker: tracker,
	}
	return &Engine{
		cfg:      cfg,
		stateDir: stateDir,
		logf:     logf,
		mgr:      mgr,
		tracker:  tracker,
		router:   router,
	}, nil
}

// Type returns kernel.ModeDavin.
func (e *Engine) Type() kernel.Mode {
	return kernel.ModeDavin
}

// Start starts the underlying egress slot manager.
func (e *Engine) Start(ctx context.Context) error {
	e.mgr.Start(ctx)
	return nil
}

// Close gracefully closes all egress nodes and listeners.
func (e *Engine) Close() error {
	return e.mgr.Close()
}

// Reload applies updated configuration and rules dynamically.
func (e *Engine) Reload(cfg *config.Config, rules *rule.Engine) error {
	e.mu.Lock()
	e.cfg = cfg
	if rules != nil && e.router != nil {
		e.router.Rules = func() *rule.Engine { return rules }
	}
	e.mu.Unlock()
	return e.mgr.Apply(cfg)
}

// Status returns runtime status from the egress manager.
func (e *Engine) Status() any {
	return e.mgr.Status()
}

// Components returns panel components reflecting Davin kernel and egress slots.
func (e *Engine) Components() []panel.Component {
	state, detail := e.mgr.Summary()
	return []panel.Component{
		{Name: "kernel", State: "running", Detail: "davin (嵌入式 tsnet 多节点透明代理)"},
		{Name: "egress_manager", State: state, Detail: detail},
	}
}

// Teardown cleans up any state (noop in Davin mode).
func (e *Engine) Teardown() error {
	return nil
}

// Manager returns the underlying egress.Manager.
func (e *Engine) Manager() *egress.Manager {
	return e.mgr
}

// Router returns the underlying proxy.Router.
func (e *Engine) Router() *proxy.Router {
	return e.router
}

// Tracker returns the underlying proxy.Tracker.
func (e *Engine) Tracker() *proxy.Tracker {
	return e.tracker
}
