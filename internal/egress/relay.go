package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/socks5"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/token"
)

// Relay-only states.
const (
	StateNoToken     = "no_token"
	StateUnreachable = "unreachable"
	StateAuthFailed  = "auth_failed"
)

// relayUser is the SOCKS5 username a `tailproxy relay` expects.
const relayUser = "tailproxy"

// relayProbeEvery is how often an idle relay is checked.
const relayProbeEvery = 20 * time.Second

// member is an exit that can carry traffic and be part of a group: an
// egress slot (own tailnet device + exit node) or a relay.
type member interface {
	Name() string
	Ready() bool
	Dial(ctx context.Context, host string, port uint16) (net.Conn, error)
	Status() Status
	checkHealth(ctx context.Context, url string)
	healthOK() (ok bool, rtt float64, measured bool)
}

// Relay is an egress that sends traffic through a `tailproxy relay` on
// another tailnet device. It is reached over the main node, so it needs no
// tailnet device of its own; the relay resolves names and dials from its
// own network.
type Relay struct {
	name      string
	tokenPath string
	// dialTailnet reaches the relay over the tailnet (the manager's main
	// node); loopback relays are dialed directly.
	dialTailnet func(ctx context.Context, host string, port uint16) (net.Conn, error)
	logf        func(string, ...any)

	mu       sync.Mutex
	addr     string
	tokenEnv string
	token    string
	tokenSrc string // "env:<NAME>", "file" or ""
	status   Status
	health   *Health
	cancel   context.CancelFunc
	done     chan struct{}
	kick     chan struct{}
}

func newRelay(name, addr, tokenEnv, tokenPath string, dialTailnet func(context.Context, string, uint16) (net.Conn, error), logf func(string, ...any)) *Relay {
	r := &Relay{name: name, tokenPath: tokenPath, dialTailnet: dialTailnet, logf: logf, kick: make(chan struct{}, 1)}
	r.status = Status{Name: name, Kind: "relay", State: StateStopped}
	r.configure(addr, tokenEnv)
	return r
}

// Name is the egress name.
func (r *Relay) Name() string { return r.name }

// configure sets the relay address and token source and reloads the token.
func (r *Relay) configure(addr, tokenEnv string) {
	tok, src, err := r.loadToken(tokenEnv)
	r.mu.Lock()
	changed := r.addr != addr || r.tokenEnv != tokenEnv || r.token != tok
	r.addr, r.tokenEnv, r.token, r.tokenSrc = addr, tokenEnv, tok, src
	r.status.Relay, r.status.TokenSource = addr, src
	if err != nil {
		r.status.State, r.status.Detail = StateError, err.Error()
	} else if tok == "" {
		r.status.State, r.status.Detail = StateNoToken, r.noTokenDetail()
	} else if changed && r.status.State == StateReady {
		r.status.State, r.status.Detail = StateStarting, "正在重新检查中继"
	}
	r.mu.Unlock()
	if changed {
		r.poke()
	}
}

func (r *Relay) noTokenDetail() string {
	if r.tokenEnv != "" {
		return fmt.Sprintf("环境变量 $%s 为空：填入中继令牌（在中继机器上执行 tailproxy relay token 查看）", r.tokenEnv)
	}
	return "还没有中继令牌：在中继机器上执行 tailproxy relay token 查看，然后在面板里填入"
}

// loadToken reads the token from tokenEnv if set, else from the token file.
func (r *Relay) loadToken(tokenEnv string) (tok, src string, err error) {
	if tokenEnv != "" {
		v := strings.TrimSpace(os.Getenv(tokenEnv))
		if v != "" && len(v) < token.MinLen {
			return "", "", fmt.Errorf("$%s 太短（至少 %d 个字符）", tokenEnv, token.MinLen)
		}
		return v, "env:" + tokenEnv, nil
	}
	v, err := token.ReadFile(r.tokenPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	return v, "file", nil
}

// setToken saves tok to the token file (mode 0600) and re-checks the relay.
func (r *Relay) setToken(tok string) error {
	tok = strings.TrimSpace(tok)
	if len(tok) < token.MinLen || strings.ContainsAny(tok, " \t\r\n") || len(tok) > 255 {
		return fmt.Errorf("中继令牌应为 %d–255 个非空白字符", token.MinLen)
	}
	r.mu.Lock()
	env := r.tokenEnv
	r.mu.Unlock()
	if env != "" {
		return fmt.Errorf("出口 %s 的令牌来自环境变量 $%s（relay_token_env），面板不能修改", r.name, env)
	}
	if err := os.MkdirAll(dirOf(r.tokenPath), 0o700); err != nil {
		return err
	}
	if err := writeFile0600(r.tokenPath, []byte(tok+"\n")); err != nil {
		return err
	}
	r.mu.Lock()
	r.token, r.tokenSrc = tok, "file"
	r.status.TokenSource = "file"
	r.status.State, r.status.Detail = StateStarting, "正在检查中继"
	r.mu.Unlock()
	r.poke()
	return nil
}

func dirOf(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		return path[:i]
	}
	return "."
}

// removeToken deletes the saved token file (egress removed).
func (r *Relay) removeToken() {
	if err := os.Remove(r.tokenPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		r.logf("egress %s: remove relay token: %v", r.name, err)
	}
}

func (r *Relay) poke() {
	select {
	case r.kick <- struct{}{}:
	default:
	}
}

// start runs the probe loop until parent is cancelled or stop is called.
func (r *Relay) start(parent context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil || parent.Err() != nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	r.cancel, r.done = cancel, make(chan struct{})
	if r.token != "" && r.status.State != StateError {
		r.status.State, r.status.Detail = StateStarting, ""
	}
	go r.run(ctx, r.done)
}

func (r *Relay) stop() {
	r.mu.Lock()
	cancel, done := r.cancel, r.done
	r.cancel, r.done = nil, nil
	r.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
	r.set(func(st *Status) { st.State, st.Detail = StateStopped, "" })
}

func (r *Relay) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	for {
		r.probe(ctx)
		wait := relayProbeEvery
		if st := r.Status().State; st != StateReady && st != StateNoToken {
			wait = 5 * time.Second // retry sooner while not working
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-r.kick:
			t.Stop()
		case <-t.C:
		}
	}
}

// probe connects and authenticates without opening a connection through
// the relay, and records the result.
func (r *Relay) probe(ctx context.Context) {
	r.mu.Lock()
	tok, state := r.token, r.status.State
	r.mu.Unlock()
	if state == StateError && tok == "" {
		return
	}
	if tok == "" {
		r.set(func(st *Status) { st.State, st.Detail = StateNoToken, r.noTokenDetail() })
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := r.connect(ctx)
	if err != nil {
		if ctx.Err() == nil || !errors.Is(err, context.Canceled) {
			r.fail(err)
		}
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := socks5.ClientAuth(c, &socks5.Credentials{User: relayUser, Password: tok}); err != nil {
		r.fail(err)
		return
	}
	r.ok()
}

// connect opens a TCP connection to the relay itself.
func (r *Relay) connect(ctx context.Context) (net.Conn, error) {
	r.mu.Lock()
	addr := r.addr
	r.mu.Unlock()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	if isLoopbackHost(host) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	c, err := r.dialTailnet(ctx, host, uint16(port))
	if err != nil && errors.Is(err, ErrNotReady) {
		return nil, fmt.Errorf("%w: 主节点还没有连上 tailnet（先在「出口」页登录）", ErrNotReady)
	}
	return c, err
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func (r *Relay) ok() {
	r.mu.Lock()
	was := r.status.State
	r.status.State, r.status.Detail = StateReady, ""
	addr := r.addr
	r.mu.Unlock()
	if was != StateReady {
		r.logf("egress %s: relay %s ready", r.name, addr)
	}
}

func (r *Relay) fail(err error) {
	state, detail := StateUnreachable, "连不上中继："+err.Error()
	switch {
	case errors.Is(err, socks5.ErrAuthFailed):
		state, detail = StateAuthFailed, "中继拒绝了令牌：在中继机器上执行 tailproxy relay token 查看正确的令牌后重新填入"
	case errors.Is(err, ErrNotReady):
		state, detail = StateStarting, "等待主节点连上 tailnet（先在「出口」页登录 Tailscale）"
	}
	r.mu.Lock()
	was := r.status.State
	r.status.State, r.status.Detail = state, detail
	addr := r.addr
	r.mu.Unlock()
	if was != state {
		r.logf("egress %s: relay %s: %v", r.name, addr, err)
	}
}

func (r *Relay) set(f func(*Status)) {
	r.mu.Lock()
	f(&r.status)
	r.mu.Unlock()
}

// Status returns a copy of the relay's status.
func (r *Relay) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.status
	if r.health != nil {
		h := *r.health
		st.Health = &h
	}
	return st
}

// Ready reports whether the last check reached the relay and it accepted
// the token.
func (r *Relay) Ready() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status.State == StateReady
}

// Dial asks the relay to connect to host:port. Names are sent unresolved, so
// the relay resolves them from its own network. Unlike a slot, a relay is
// tried whenever it has a token, so a relay that just came back works
// without waiting for the next probe; failure never falls back to the local
// network.
func (r *Relay) Dial(ctx context.Context, host string, port uint16) (net.Conn, error) {
	r.mu.Lock()
	tok, st := r.token, r.status
	r.mu.Unlock()
	if tok == "" || st.State == StateError || st.State == StateStopped {
		return nil, fmt.Errorf("%w: %s is %s %s", ErrNotReady, r.name, st.State, st.Detail)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c, err := r.connect(ctx)
	if err != nil {
		r.fail(err)
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { c.SetDeadline(time.Unix(1, 0)) })
	err = socks5.ClientConnect(c, &socks5.Credentials{User: relayUser, Password: tok}, host, port)
	stop()
	if err != nil {
		c.Close()
		var re *socks5.ReplyError
		if !errors.As(err, &re) { // a reply error is about the destination, not the relay
			r.fail(err)
		}
		return nil, err
	}
	c.SetDeadline(time.Time{})
	r.ok()
	return c, nil
}

func (r *Relay) checkHealth(ctx context.Context, url string) {
	h := &Health{URL: url, Checked: time.Now()}
	if tok := r.hasToken(); !tok {
		h.Error = "中继没有令牌"
	} else {
		probeHealth(ctx, url, r.Dial, h)
	}
	r.mu.Lock()
	r.health = h
	r.mu.Unlock()
}

func (r *Relay) hasToken() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.token != ""
}

func (r *Relay) healthOK() (ok bool, rtt float64, measured bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.health == nil {
		return true, 0, false
	}
	return r.health.OK, r.health.RTTMs, r.health.OK
}

// relayHost is the host part of the relay address, for matching devices.
func (r *Relay) relayHost() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, _, _ := net.SplitHostPort(r.addr)
	return h
}
