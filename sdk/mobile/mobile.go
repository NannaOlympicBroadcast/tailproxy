// Package mobile is the tailproxy SDK in a form gomobile can bind for
// Android (AAR) and iOS (xcframework): only strings, ints, bools, errors
// and small interfaces cross the boundary, and structured data is JSON.
//
//	gomobile bind -target=android -androidapi 24 ./sdk/mobile
//	gomobile bind -target=ios ./sdk/mobile
//
// A VPN app creates the engine with its Protector (Android:
// VpnService.protect), starts it, establishes the VPN with the stack's DNS
// address as DNS server and the routes it wants, and passes the TUN file
// descriptor to StartTUN. The Android and iOS apps themselves are not part
// of this repository yet (DESIGN M3).
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/NannaOlympicBroadcast/tailproxy/sdk"
)

// Logger receives the engine's log lines.
type Logger interface {
	Log(line string)
}

// Protector makes a socket bypass the app's own VPN (Android:
// VpnService.protect(fd)); it returns false on failure.
type Protector interface {
	Protect(fd int) bool
}

// Engine is an embedded tailproxy.
type Engine struct {
	e *sdk.Engine

	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	running bool
	tunDone chan error
}

// NewEngine parses configYAML (config.yaml) and prepares an engine that
// keeps its state in stateDir. log and protector may be nil.
func NewEngine(configYAML, stateDir string, log Logger, protector Protector) (*Engine, error) {
	cfg, err := sdk.ParseConfig([]byte(configYAML))
	if err != nil {
		return nil, err
	}
	o := sdk.Options{Config: cfg, StateDir: stateDir}
	if log != nil {
		o.Logf = func(format string, args ...any) { log.Log(fmt.Sprintf(format, args...)) }
	}
	if protector != nil {
		o.Protect = protector.Protect
	}
	e, err := sdk.New(o)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{e: e, ctx: ctx, cancel: cancel}, nil
}

// Start brings up the Tailscale nodes in the background.
func (m *Engine) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return nil
	}
	if err := m.e.Start(m.ctx); err != nil {
		return err
	}
	m.running = true
	return nil
}

// StartSOCKS serves a SOCKS5 inbound on a loopback address
// ("127.0.0.1:0" picks a port) and returns the address it listens on.
func (m *Engine) StartSOCKS(addr string) (string, error) {
	ln, err := sdk.ListenSOCKS(addr)
	if err != nil {
		return "", err
	}
	go m.e.ServeSOCKS(m.ctx, ln)
	return ln.Addr().String(), nil
}

// StartTUN serves the VPN's TUN file descriptor (the engine owns and
// closes it). dnsAddr is the DNS server address given to the VPN (routed
// into it); dnsUpstreams is a comma-separated list of the underlying
// network's DNS servers ("" uses dns.direct_upstream from the config).
func (m *Engine) StartTUN(fd int, mtu int, dnsAddr, dnsUpstreams string) error {
	a, err := netip.ParseAddr(dnsAddr)
	if err != nil {
		return fmt.Errorf("dnsAddr: %w", err)
	}
	var ups []string
	for _, u := range strings.Split(dnsUpstreams, ",") {
		if u = strings.TrimSpace(u); u != "" {
			ups = append(ups, u)
		}
	}
	m.mu.Lock()
	if m.tunDone != nil {
		m.mu.Unlock()
		return errors.New("a TUN is already being served")
	}
	done := make(chan error, 1)
	m.tunDone = done
	m.mu.Unlock()
	go func() { done <- m.e.ServeTUNFD(m.ctx, fd, mtu, sdk.TUNOptions{DNSAddr: a, DNSUpstreams: ups}) }()
	return nil
}

// Stop stops everything; the engine cannot be started again.
func (m *Engine) Stop() {
	m.cancel()
	m.e.Close()
}

// UpdateConfig switches to a new configuration.
func (m *Engine) UpdateConfig(configYAML string) error {
	cfg, err := sdk.ParseConfig([]byte(configYAML))
	if err != nil {
		return err
	}
	return m.e.SetConfig(cfg)
}

// SetAuthKey saves a Tailscale auth key and logs waiting nodes in.
func (m *Engine) SetAuthKey(key string) error { return m.e.SetAuthKey(key) }

// EgressJSON is the main node and egress states (login URLs included)
// as JSON, in the format of the REST API's /api/v1/egress.
func (m *Engine) EgressJSON() string { return toJSON(m.e.Egress()) }

// AccountJSON is the main Tailscale node's state as JSON: whether it is
// logged in, the login URL while it waits, the tailnet.
func (m *Engine) AccountJSON() string { return toJSON(m.e.Account()) }

// ConnectionsJSON is the active and recent connections as JSON.
func (m *Engine) ConnectionsJSON() string { return toJSON(m.e.Connections()) }

// MatchJSON reports how the rules route a destination (domain or ip may
// be empty) as JSON.
func (m *Engine) MatchJSON(domain, ip string, port int) (string, error) {
	r, err := m.e.Match(domain, ip, uint16(port))
	if err != nil {
		return "", err
	}
	return toJSON(r), nil
}

func toJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf(`{"error":%q}`, err.Error())
	}
	return string(b)
}
