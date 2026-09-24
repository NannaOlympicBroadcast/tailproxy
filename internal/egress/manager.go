// Package egress manages the exit-node slots (DESIGN §4.4): one embedded
// tsnet node per configured exit node, plus fallback / latency groups.
package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"tailscale.com/tsnet"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
)

// Manager owns all slots and groups.
type Manager struct {
	order  []string // config order, slots and groups
	slots  map[string]*Slot
	groups map[string]*group
	logf   func(string, ...any)

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type group struct {
	name    string
	kind    string // fallback | latency
	members []*Slot
	check   *config.HealthCheck
	every   time.Duration

	mu       sync.Mutex
	selected string
}

// New builds the slots for cfg. Each slot keeps its tsnet state (node key,
// prefs) under stateDir/tsnet/<name>, so it stays the same tailnet device
// across restarts. Nothing connects until Start.
func New(cfg *config.Config, stateDir string, logf func(string, ...any)) (*Manager, error) {
	if logf == nil {
		logf = log.Printf
	}
	m := &Manager{slots: map[string]*Slot{}, groups: map[string]*group{}, logf: logf}
	authKey := ""
	if cfg.Tailnet.AuthKeyEnv != "" {
		authKey = os.Getenv(cfg.Tailnet.AuthKeyEnv)
	}
	tsnetLogf := func(string, ...any) {}
	if os.Getenv("TAILPROXY_TSNET_DEBUG") != "" {
		tsnetLogf = logf
	}
	for _, e := range cfg.Egress {
		m.order = append(m.order, e.Name)
		if e.IsGroup() {
			continue
		}
		dir := filepath.Join(stateDir, "tsnet", e.Name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		name := e.Name
		var lastMu sync.Mutex
		var last string
		srv := &tsnet.Server{
			Dir:           dir,
			Hostname:      "tailproxy-" + name,
			AuthKey:       authKey,
			ControlURL:    cfg.Tailnet.ControlURL,
			AdvertiseTags: cfg.Tailnet.AdvertiseTags,
			Logf:          tsnetLogf,
			// tsnet repeats "go to <login URL>" every few seconds while
			// waiting for login; log each distinct message once.
			UserLogf: func(format string, args ...any) {
				msg := fmt.Sprintf(format, args...)
				lastMu.Lock()
				dup := msg == last
				last = msg
				lastMu.Unlock()
				if !dup {
					logf("egress %s: %s", name, msg)
				}
			},
		}
		m.slots[name] = newSlot(name, e.ExitNode, srv, cfg.DNS.PerEgressDoH, logf)
	}
	for _, e := range cfg.Egress {
		if !e.IsGroup() {
			continue
		}
		g := &group{name: e.Name, kind: e.Type, check: e.HealthCheck}
		for _, mname := range e.Members {
			g.members = append(g.members, m.slots[mname])
		}
		if e.HealthCheck != nil {
			d, err := time.ParseDuration(e.HealthCheck.Interval)
			if err != nil || d < 5*time.Second {
				return nil, fmt.Errorf("egress %q: health_check.interval %q must be a duration of at least 5s", e.Name, e.HealthCheck.Interval)
			}
			if e.HealthCheck.URL == "" {
				return nil, fmt.Errorf("egress %q: health_check.url is required", e.Name)
			}
			g.every = d
		}
		m.groups[e.Name] = g
	}
	return m, nil
}

// Start connects all slots in the background and starts health checks.
func (m *Manager) Start(ctx context.Context) {
	ctx, m.cancel = context.WithCancel(ctx)
	for _, s := range m.slots {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			s.run(ctx)
		}()
	}
	for _, g := range m.groups {
		if g.check == nil {
			continue
		}
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			t := time.NewTicker(g.every)
			defer t.Stop()
			for {
				for _, s := range g.members {
					s.checkHealth(ctx, g.check.URL)
				}
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		}()
	}
}

// Close stops all slots.
func (m *Manager) Close() error {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	var errs []error
	for _, s := range m.slots {
		if !s.started.Load() {
			continue
		}
		if err := s.srv.Close(); err != nil && !errors.Is(err, io.EOF) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Dial connects to host:port through the egress named target (a slot or a
// group) and returns the slot that carried the connection.
func (m *Manager) Dial(ctx context.Context, target, host string, port uint16) (net.Conn, string, error) {
	if s, ok := m.slots[target]; ok {
		c, err := s.Dial(ctx, host, port)
		return c, s.name, err
	}
	g, ok := m.groups[target]
	if !ok {
		return nil, "", fmt.Errorf("unknown egress %q", target)
	}
	s, err := g.pick()
	if err != nil {
		return nil, "", err
	}
	c, err := s.Dial(ctx, host, port)
	return c, s.name, err
}

// DialTailnet connects to a tailnet address (100.x IP or MagicDNS name) via
// any connected slot; tailnet traffic does not use the exit node.
func (m *Manager) DialTailnet(ctx context.Context, host string, port uint16) (net.Conn, string, error) {
	for _, name := range m.order {
		if s, ok := m.slots[name]; ok && s.tailnetUp() {
			c, err := s.dialTailnet(ctx, host, port)
			return c, s.name, err
		}
	}
	return nil, "", fmt.Errorf("%w: no egress slot is connected to the tailnet", ErrNotReady)
}

func (g *group) pick() (*Slot, error) {
	var best *Slot
	bestRTT := 0.0
	for _, s := range g.members {
		if !s.Ready() {
			continue
		}
		ok, rtt, measured := s.healthOK()
		if !ok {
			continue
		}
		if g.kind == "fallback" {
			best = s
			break
		}
		// latency: lowest measured RTT; unmeasured members only as a last resort
		if best == nil || (measured && (bestRTT == 0 || rtt < bestRTT)) {
			best, bestRTT = s, rtt
		}
	}
	if best == nil {
		return nil, fmt.Errorf("%w: no member of group %s is ready", ErrNotReady, g.name)
	}
	g.mu.Lock()
	g.selected = best.name
	g.mu.Unlock()
	return best, nil
}

// Status returns every slot and group in config order.
func (m *Manager) Status() []Status {
	var out []Status
	for _, name := range m.order {
		if s, ok := m.slots[name]; ok {
			out = append(out, s.Status())
			continue
		}
		g := m.groups[name]
		st := Status{Name: g.name, Kind: "group", State: StateExitNodePending, Detail: "没有就绪的成员"}
		for _, s := range g.members {
			st.Members = append(st.Members, s.name)
		}
		if s, err := g.pick(); err == nil {
			st.State, st.Detail, st.Selected = StateReady, "", s.name
		}
		out = append(out, st)
	}
	return out
}

// Summary describes the manager for the panel's component list.
func (m *Manager) Summary() (state, detail string) {
	if len(m.slots) == 0 {
		return "idle", "配置中没有出口槽位"
	}
	ready := 0
	for _, s := range m.slots {
		if s.Ready() {
			ready++
		}
	}
	state = "running"
	if ready < len(m.slots) {
		state = "degraded"
	}
	return state, fmt.Sprintf("%d/%d 个出口槽位就绪", ready, len(m.slots))
}
