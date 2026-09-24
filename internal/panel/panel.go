// Package panel serves the tailproxy web panel, its REST API and /metrics on a
// single port (DESIGN §4.10, default 127.0.0.1:7708).
package panel

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
)

//go:embed static
var staticFS embed.FS

// egressNotRunning is shown when the panel runs without a Runtime (tests,
// or a build without the egress manager): the tsnet
// slot manager (DESIGN §4.4, milestone M0) is not part of this build.
const egressNotRunning = "出口管理器没有运行，这里只列出配置中的出口"

// Component is one entry of the panel's component list.
type Component struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

// Runtime exposes the running proxy (egress manager, inbounds, connection
// tracker) to the panel. Values returned are serialized as JSON.
type Runtime interface {
	Components() []Component
	Egress() any
	Connections() any
}

// Server is the web panel. Create it with New and run it with ListenAndServe.
type Server struct {
	cfgPath string
	version string
	started time.Time

	// token is always set: every API call needs it. At most one of tokenEnv
	// (environment variable) and tokenFile (persisted file) is set; neither
	// means a one-off token generated for this run.
	token        string
	tokenEnv     string
	tokenFile    string
	tokenCreated bool // tokenFile did not exist and was created by this run
	loopback     bool // panel.listen is a loopback address
	runtime      Runtime

	bound atomic.Pointer[string] // actual listen address once Listen succeeded

	mu     sync.RWMutex
	cfg    *config.Config
	engine *rule.Engine
	loaded time.Time
	rev    string // config.Revision of the file content cfg was parsed from

	writeMu sync.Mutex // serializes config reloads and rule saves

	requests      atomic.Uint64
	ruleTests     atomic.Uint64
	reloadsOK     atomic.Uint64
	reloadsFailed atomic.Uint64
	ruleSaves     atomic.Uint64
}

// Options controls where the panel token comes from.
type Options struct {
	// TokenFile persists the token: it is read from this file, or generated
	// and written there (mode 0600) if the file does not exist, so the token
	// survives restarts. Empty means a one-off token for this run only.
	TokenFile string

	// Runtime, if set, provides live egress state and connections.
	Runtime Runtime
}

// New loads the configuration at cfgPath and prepares the panel. Access
// always requires a token, taken from, in order: the environment variable
// named by panel.auth_token_env (if set and non-empty), opts.TokenFile, or a
// random token generated for this run.
func New(cfgPath, version string, opts Options) (*Server, error) {
	s := &Server{cfgPath: cfgPath, version: version, started: time.Now(), runtime: opts.Runtime}
	if err := s.loadFromDisk(); err != nil {
		return nil, err
	}
	cfg := s.cfg
	if env := cfg.Panel.AuthTokenEnv; env != "" {
		if v := os.Getenv(env); v != "" {
			if len(v) < MinTokenLen {
				return nil, fmt.Errorf("panel token from $%s is shorter than %d characters", env, MinTokenLen)
			}
			s.token, s.tokenEnv = v, env
		}
	}
	if s.token == "" && opts.TokenFile != "" {
		t, created, err := LoadOrCreateToken(opts.TokenFile)
		if err != nil {
			return nil, err
		}
		s.token, s.tokenFile, s.tokenCreated = t, opts.TokenFile, created
	}
	if s.token == "" {
		t, err := generateToken()
		if err != nil {
			return nil, err
		}
		s.token = t
	}
	loopback, err := isLoopbackListen(cfg.Panel.Listen)
	if err != nil {
		return nil, err
	}
	s.loopback = loopback
	return s, nil
}

// Token returns the panel access token.
func (s *Server) Token() string { return s.token }

// TokenEnv returns the environment variable the token was read from, or "".
func (s *Server) TokenEnv() string { return s.tokenEnv }

// TokenFile returns the file the token is persisted in, or "".
func (s *Server) TokenFile() string { return s.tokenFile }

// TokenCreated reports whether this run generated and saved a new token file.
func (s *Server) TokenCreated() bool { return s.tokenCreated }

// URL returns a browser URL for the panel. An unspecified listen host
// (0.0.0.0, ::, empty) is shown as 127.0.0.1.
func (s *Server) URL() string {
	addr := s.Addr()
	if b := s.bound.Load(); b != nil {
		addr = *b
	}
	host, port, _ := net.SplitHostPort(addr)
	if ip, err := netip.ParseAddr(host); host == "" || (err == nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/"
}

// LoginURL returns URL with the token in the fragment. The fragment is never
// sent to the server; the page reads it, stores it and removes it.
func (s *Server) LoginURL() string {
	return s.URL() + "#token=" + url.QueryEscape(s.token)
}

// Addr returns the configured listen address.
func (s *Server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Panel.Listen
}

// TailnetRequested reports whether panel.tailnet is set. Serving the panel on
// the tailnet needs the ts egress slot, which this build does not have yet.
func (s *Server) TailnetRequested() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Panel.Tailnet
}

// ListenAndServe serves the panel until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := s.Listen()
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Listen binds panel.listen. Afterwards URL reports the actual address, which
// matters when the configured port is 0.
func (s *Server) Listen() (net.Listener, error) {
	ln, err := net.Listen("tcp", s.Addr())
	if err != nil {
		return nil, fmt.Errorf("panel: listen %s: %w", s.Addr(), err)
	}
	addr := ln.Addr().String()
	s.bound.Store(&addr)
	return ln, nil
}

// Serve serves the panel on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Handler returns the panel's HTTP handler.
func (s *Server) Handler() http.Handler {
	static, _ := fs.Sub(staticFS, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("GET /api/v1/status", s.auth(s.handleStatus))
	mux.HandleFunc("GET /api/v1/config", s.auth(s.handleConfig))
	mux.HandleFunc("POST /api/v1/config/reload", s.auth(s.handleReload))
	mux.HandleFunc("GET /api/v1/egress", s.auth(s.handleEgress))
	mux.HandleFunc("GET /api/v1/connections", s.auth(s.handleConnections))
	mux.HandleFunc("GET /api/v1/rules", s.auth(s.handleRules))
	mux.HandleFunc("PUT /api/v1/rules", s.auth(s.handleRulesPut))
	mux.HandleFunc("POST /api/v1/rules/test", s.auth(s.handleRuleTest))
	mux.HandleFunc("GET /metrics", s.auth(s.handleMetrics))
	return s.hostGuard(mux)
}

// hostGuard blocks DNS-rebinding attacks against a loopback-only panel by
// only accepting loopback Host headers (defense in depth on top of the token).
func (s *Server) hostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if s.loopback && !isLoopbackHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && isCrossSite(r) {
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="tailproxy"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		h(w, r)
	}
}

func (s *Server) snapshot() (*config.Config, *rule.Engine, time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg, s.engine, s.loaded
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg, engine, loaded := s.snapshot()
	slots, groups := 0, 0
	for _, e := range cfg.Egress {
		if e.IsGroup() {
			groups++
		} else {
			slots++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":        s.version,
		"started_at":     s.started.UTC().Format(time.RFC3339),
		"uptime_seconds": int64(time.Since(s.started).Seconds()),
		"config_path":    s.cfgPath,
		"config_loaded":  loaded.UTC().Format(time.RFC3339),
		"panel_listen":   cfg.Panel.Listen,
		"token_source":   s.tokenSource(),
		"rules":          engine.Len(),
		"egress_slots":   slots,
		"egress_groups":  groups,
		"components":     s.components(),
	})
}

func (s *Server) components() []Component {
	out := []Component{
		{Name: "panel", State: "running"},
		{Name: "config", State: "loaded"},
		{Name: "rule_engine", State: "ready"},
	}
	if s.runtime != nil {
		return append(out, s.runtime.Components()...)
	}
	return append(out,
		Component{Name: "egress_manager", State: "not_running", Detail: egressNotRunning},
		Component{Name: "capture", State: "not_running"},
	)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	cfg, _, _ := s.snapshot()
	// The config holds only env var names, never secret values.
	writeJSON(w, http.StatusOK, cfg)
}

// loadFromDisk reads, validates and compiles the config file and swaps it in.
// On error the current state is kept.
func (s *Server) loadFromDisk() error {
	data, err := os.ReadFile(s.cfgPath)
	if err != nil {
		return err
	}
	cfg, err := config.Parse(data)
	if err != nil {
		return err
	}
	engine, err := rule.Compile(cfg.Rules)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cfg, s.engine, s.loaded, s.rev = cfg, engine, time.Now(), config.Revision(data)
	s.mu.Unlock()
	return nil
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	old, _, _ := s.snapshot()
	if err := s.loadFromDisk(); err != nil {
		s.reloadsFailed.Add(1)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.reloadsOK.Add(1)
	cfg, engine, _ := s.snapshot()
	resp := map[string]any{"ok": true, "rules": engine.Len()}
	var restart []string
	if cfg.Panel != old.Panel {
		restart = append(restart, "panel")
	}
	if !sameJSON(cfg.Egress, old.Egress) || !sameJSON(cfg.Tailnet, old.Tailnet) {
		restart = append(restart, "egress / tailnet")
	}
	if !sameJSON(cfg.Capture, old.Capture) || !sameJSON(cfg.DNS, old.DNS) {
		restart = append(restart, "capture / dns")
	}
	if len(restart) > 0 {
		resp["warning"] = "规则已生效；" + strings.Join(restart, "、") + " 配置的变更需要重启 tailproxy 才会生效"
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleEgress(w http.ResponseWriter, r *http.Request) {
	cfg, _, _ := s.snapshot()
	if s.runtime == nil {
		writeJSON(w, http.StatusOK, map[string]any{"configured": cfg.Egress, "runtime": nil, "detail": egressNotRunning})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": cfg.Egress, "runtime": s.runtime.Egress()})
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	if s.runtime == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "proxy is not running"})
		return
	}
	writeJSON(w, http.StatusOK, s.runtime.Connections())
}

// SetRuntime attaches the running proxy. Call it before serving.
func (s *Server) SetRuntime(rt Runtime) { s.runtime = rt }

// Config returns the currently loaded configuration.
func (s *Server) Config() *config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Engine returns the current rule engine. It changes when rules are saved
// or the config is reloaded, so callers should fetch it per connection.
func (s *Server) Engine() *rule.Engine {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.engine
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	cfg, rev := s.cfg, s.rev
	s.mu.RUnlock()
	implicitFinal := len(cfg.Rules) == 0 || cfg.Rules[len(cfg.Rules)-1].Final == ""
	targets := []string{config.TargetDirect, config.TargetTailnet, config.TargetReject}
	for _, e := range cfg.Egress {
		targets = append(targets, e.Name)
	}
	rules := cfg.Rules
	if rules == nil {
		rules = []config.Rule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rules":          rules,
		"implicit_final": implicitFinal,
		"targets":        targets,
		"revision":       rev,
	})
}

type ruleTestRequest struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	Port   uint16 `json:"port"`
	// Rules, when set, tests against this unsaved draft instead of the
	// running rules. The draft is validated against the current egress list.
	Rules *[]config.Rule `json:"rules,omitempty"`
}

func (s *Server) handleRuleTest(w http.ResponseWriter, r *http.Request) {
	var req ruleTestRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRulesBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	q := rule.Query{Domain: req.Domain, Port: req.Port}
	if ipStr := strings.TrimSpace(req.IP); ipStr != "" {
		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ip: " + err.Error()})
			return
		}
		q.IP = ip
	}
	if strings.TrimSpace(q.Domain) == "" && !q.IP.IsValid() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain or ip is required"})
		return
	}
	cfg, engine, _ := s.snapshot()
	if req.Rules != nil {
		var err error
		if engine, err = compileDraft(cfg, *req.Rules); err != nil {
			writeValidationError(w, err)
			return
		}
	}
	s.ruleTests.Add(1)
	writeJSON(w, http.StatusOK, engine.Match(q))
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	cfg, engine, _ := s.snapshot()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP tailproxy_build_info Build information.\n# TYPE tailproxy_build_info gauge\ntailproxy_build_info{version=%q} 1\n", s.version)
	fmt.Fprintf(w, "# HELP tailproxy_uptime_seconds Seconds since the process started.\n# TYPE tailproxy_uptime_seconds gauge\ntailproxy_uptime_seconds %d\n", int64(time.Since(s.started).Seconds()))
	fmt.Fprintf(w, "# HELP tailproxy_rules Number of configured rules.\n# TYPE tailproxy_rules gauge\ntailproxy_rules %d\n", engine.Len())
	fmt.Fprintf(w, "# HELP tailproxy_egress_configured Number of configured egress entries.\n# TYPE tailproxy_egress_configured gauge\ntailproxy_egress_configured %d\n", len(cfg.Egress))
	fmt.Fprintf(w, "# HELP tailproxy_panel_http_requests_total HTTP requests served by the panel.\n# TYPE tailproxy_panel_http_requests_total counter\ntailproxy_panel_http_requests_total %d\n", s.requests.Load())
	fmt.Fprintf(w, "# HELP tailproxy_rule_tests_total Rule test requests.\n# TYPE tailproxy_rule_tests_total counter\ntailproxy_rule_tests_total %d\n", s.ruleTests.Load())
	fmt.Fprintf(w, "# HELP tailproxy_rule_saves_total Rule sets saved from the panel.\n# TYPE tailproxy_rule_saves_total counter\ntailproxy_rule_saves_total %d\n", s.ruleSaves.Load())
	fmt.Fprintf(w, "# HELP tailproxy_config_reloads_total Config reloads by result.\n# TYPE tailproxy_config_reloads_total counter\ntailproxy_config_reloads_total{result=\"ok\"} %d\ntailproxy_config_reloads_total{result=\"error\"} %d\n", s.reloadsOK.Load(), s.reloadsFailed.Load())
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func (s *Server) tokenSource() string {
	switch {
	case s.tokenEnv != "":
		return "env:" + s.tokenEnv
	case s.tokenFile != "":
		return "file:" + s.tokenFile
	}
	return "generated"
}

// isCrossSite reports whether a state-changing request came from another
// site: a page open in the user's browser that somehow obtained the token must
// still not be able to drive the panel.
func isCrossSite(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false // non-browser clients such as curl
	}
	u, err := url.Parse(origin)
	return err != nil || u.Host != r.Host
}

func isLoopbackListen(addr string) (bool, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false, fmt.Errorf("panel.listen: %w", err)
	}
	if host == "localhost" {
		return true, nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false, nil // hostname or empty (all interfaces): treat as exposed
	}
	return ip.IsLoopback(), nil
}

func isLoopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}
