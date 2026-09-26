// Package sdk embeds tailproxy in another Go program: the same rules,
// Tailscale exit-node / relay egresses, connection tracking and DNS as the
// tailproxy service, without running it as a separate process.
//
// An application can route its own traffic by dialing through the engine
// (DialContext, HTTPClient), offer a local SOCKS5 inbound (ServeSOCKS), or
// act as a VPN by handing the engine a TUN device or file descriptor
// (ServeTUN, ServeTUNFD) whose routes and system DNS the application or
// the platform VPN framework has set up — the Android / iOS apps are built
// on this (see the mobile subpackage for a gomobile-friendly API).
//
// System-wide capture (nftables TPROXY, creating TUN devices and routes,
// changing system DNS) stays in the tailproxy command; embedding apps
// should not take over the host's routing.
package sdk

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/egress"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/proxy"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
)

// Types shared with the tailproxy service. They are aliases, so the full
// field sets documented in config.example.yaml and the REST API apply.
type (
	// Config is a parsed tailproxy configuration (config.yaml).
	Config = config.Config
	// Rule is one routing rule.
	Rule = config.Rule
	// Conn describes a connection in Connections.
	Conn = proxy.ConnView
	// Connections is a snapshot of active and recent connections.
	Connections = proxy.Snapshot
	// EgressStatus is the state of one egress (exit node slot, relay,
	// group) or of the main Tailscale node.
	EgressStatus = egress.Status
	// MatchResult is the routing decision for a destination.
	MatchResult = rule.Result
	// Account is the main Tailscale node: login state, login URL,
	// tailnet name.
	Account = egress.Account
)

// ErrRejected is returned by DialContext for destinations a rule rejects.
var ErrRejected = proxy.ErrRejected

// ParseConfig parses a tailproxy configuration (YAML), with defaults
// applied and validated as by the tailproxy service.
func ParseConfig(yaml []byte) (*Config, error) { return config.Parse(yaml) }

// LoadConfig reads and parses a configuration file.
func LoadConfig(path string) (*Config, error) { return config.Load(path) }

// Options configure an Engine.
type Options struct {
	// Config is required (ParseConfig / LoadConfig).
	Config *Config
	// StateDir keeps the Tailscale node state, saved auth key and relay
	// tokens, and the FakeIP table; created if missing. Required.
	StateDir string
	// Logf receives log lines (default: the standard logger).
	Logf func(format string, args ...any)
	// Protect, if set, is called with every socket the engine opens
	// toward the Internet before it connects — direct dials, upstream DNS
	// and, on Android, the Tailscale nodes' own sockets — and must return
	// true once the socket bypasses the app's VPN (Android:
	// VpnService.protect). Without it, direct dials use the default route.
	Protect func(fd int) bool
}

// Engine is an embedded tailproxy.
type Engine struct {
	opts    Options
	logf    func(string, ...any)
	egress  *egress.Manager
	tracker *proxy.Tracker
	router  *proxy.Router
	dialer  net.Dialer // direct / upstream DNS dialer (protected)

	mu     sync.RWMutex
	cfg    *Config
	rules  *rule.Engine
	cancel context.CancelFunc
	closed bool
}

// New prepares an engine; Start brings up its Tailscale nodes.
func New(o Options) (*Engine, error) {
	if o.Config == nil {
		return nil, errors.New("sdk: Options.Config is required")
	}
	if o.StateDir == "" {
		return nil, errors.New("sdk: Options.StateDir is required")
	}
	if err := os.MkdirAll(o.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("sdk: state dir: %w", err)
	}
	logf := o.Logf
	if logf == nil {
		logf = log.Printf
	}
	rules, err := rule.Compile(o.Config.Rules)
	if err != nil {
		return nil, err
	}
	if o.Protect != nil {
		setPlatformProtect(o.Protect)
	}
	mgr, err := egress.New(o.Config, filepath.Clean(o.StateDir), logf)
	if err != nil {
		return nil, err
	}
	e := &Engine{opts: o, logf: logf, egress: mgr, tracker: proxy.NewTracker(), cfg: o.Config, rules: rules}
	e.dialer = net.Dialer{Control: e.control}
	e.router = &proxy.Router{Rules: e.currentRules, Egress: mgr, Tracker: e.tracker, Direct: e.dialer,
		UnknownDomain: o.Config.DNS.UnknownDomain}
	return e, nil
}

// control applies Options.Protect to a socket before it connects.
func (e *Engine) control(network, address string, rc syscall.RawConn) error {
	if e.opts.Protect == nil {
		return nil
	}
	var ok bool
	if err := rc.Control(func(fd uintptr) { ok = e.opts.Protect(int(fd)) }); err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("sdk: Protect refused the socket for %s", address)
	}
	return nil
}

func (e *Engine) currentRules() *rule.Engine {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rules
}

// Start brings up the Tailscale nodes (main node and exit-node slots) in
// the background; it returns at once. They log in with a saved or
// configured auth key, or report a login URL in Egress.
func (e *Engine) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("sdk: engine is closed")
	}
	if e.cancel != nil {
		return errors.New("sdk: engine already started")
	}
	ctx, e.cancel = context.WithCancel(ctx)
	e.egress.Start(ctx)
	return nil
}

// Close stops the engine and its Tailscale nodes. Connections made through
// it are not closed; close them yourself.
func (e *Engine) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	cancel := e.cancel
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return e.egress.Close()
}

// DialContext connects to address ("host:port"; a domain or an IP) as
// the rules decide: directly, through an exit node or relay, into the
// tailnet, or not at all (ErrRejected). network is "tcp" or "udp" (a
// connected UDP socket). The connection shows in Connections with
// inbound "sdk" until it is closed.
func (e *Engine) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("sdk: bad port in %q", address)
	}
	d := proxy.Dest{Port: uint16(port)}
	if ip, err := netip.ParseAddr(host); err == nil {
		d.IP = ip.Unmap()
	} else {
		d.Domain, d.DomainSrc = host, "sdk"
	}
	var (
		c   net.Conn
		rec *proxy.Conn
	)
	switch network {
	case "tcp", "tcp4", "tcp6":
		c, rec, err = e.router.ConnectDest(ctx, "sdk", "local", d)
	case "udp", "udp4", "udp6":
		c, rec, err = e.router.ConnectUDP(ctx, "sdk", "local", d)
	default:
		return nil, fmt.Errorf("sdk: network %q not supported (tcp or udp)", network)
	}
	if err != nil {
		return nil, err
	}
	return e.router.Track(c, rec), nil
}

// HTTPClient is an HTTP client whose connections go through DialContext.
func (e *Engine) HTTPClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext:         e.DialContext,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 15 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConns:        32,
	}}
}

// Match reports how the rules route a destination, without connecting.
// domain or ip may be empty.
func (e *Engine) Match(domain, ip string, port uint16) (MatchResult, error) {
	q := rule.Query{Domain: domain, Port: port}
	if ip != "" {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			return MatchResult{}, err
		}
		q.IP = a.Unmap()
	}
	return e.currentRules().Match(q), nil
}

// SetConfig switches to a new configuration: rules at once, egresses as
// the tailproxy service does on a reload.
func (e *Engine) SetConfig(cfg *Config) error {
	rules, err := rule.Compile(cfg.Rules)
	if err != nil {
		return err
	}
	if err := e.egress.Apply(cfg); err != nil {
		return err
	}
	e.mu.Lock()
	e.cfg, e.rules = cfg, rules
	e.router.UnknownDomain = cfg.DNS.UnknownDomain
	e.mu.Unlock()
	return nil
}

// Config is the configuration in use.
func (e *Engine) Config() *Config {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg
}

// Connections returns the active and recent connections.
func (e *Engine) Connections() Connections { return e.tracker.Snapshot() }

// Egress returns the state of the main node and every egress, including
// login URLs while a node waits for authentication.
func (e *Engine) Egress() []EgressStatus { return e.egress.Status() }

// Account returns the main Tailscale node's state (logged in or not, the
// login URL while it waits, the tailnet).
func (e *Engine) Account() Account { return e.egress.Account() }

// SetAuthKey saves a Tailscale auth key (reusable keys let every egress
// log in without a browser) and logs waiting nodes in with it.
func (e *Engine) SetAuthKey(key string) error { return e.egress.SetAuthKey(key) }

// ServeSOCKS serves a SOCKS5 inbound (CONNECT and UDP ASSOCIATE, no
// authentication) on ln until ctx ends. Use ListenSOCKS for a listener:
// it only accepts loopback addresses.
func (e *Engine) ServeSOCKS(ctx context.Context, ln net.Listener) error {
	return (&proxy.SOCKS{Router: e.router, Logf: e.logf}).Serve(ctx, ln)
}

// ListenSOCKS binds a loopback address for ServeSOCKS ("127.0.0.1:0" picks
// a port).
func ListenSOCKS(addr string) (net.Listener, error) { return proxy.ListenSOCKS(addr) }
