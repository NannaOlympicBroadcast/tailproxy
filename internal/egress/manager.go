// Package egress manages the Tailscale side of tailproxy (DESIGN §4.4): a
// main node you log in once with, and one embedded tsnet node per egress
// slot, each pinned to one exit node, plus fallback / latency groups.
package egress

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"tailscale.com/tsnet"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
)

// DefaultMainHostname is the main node's hostname unless tailnet.hostname
// is set. Egress slots are tailproxy-<name>.
const DefaultMainHostname = "tailproxy"

// authKeyFile holds an auth key saved from the panel (mode 0600).
const authKeyFile = "tailscale.authkey"

// Manager owns the main node, all egress slots and groups. Slots can be
// added, removed and re-pointed at runtime with Apply.
type Manager struct {
	stateDir  string
	tailnet   config.Tailnet
	logf      func(string, ...any)
	tsnetLogf func(string, ...any)

	keyMu      sync.Mutex
	authKey    string
	authKeySrc string // "env:<NAME>", "file" or ""

	mu         sync.RWMutex
	ctx        context.Context // nil until Start
	cancel     context.CancelFunc
	main       *Slot
	slots      map[string]*Slot
	order      []string // config order, slots and groups
	groups     map[string]*group
	defaultDoH string

	wg sync.WaitGroup
}

type group struct {
	name    string
	kind    string // fallback | latency
	members []*Slot
	check   *config.HealthCheck
	every   time.Duration

	mu       sync.Mutex
	selected string
	last     time.Time
}

// New builds the main node and the slots for cfg. Each node keeps its tsnet
// state under stateDir/tsnet/<name> (main: _main), so it stays the same
// tailnet device across restarts. Nothing connects until Start.
func New(cfg *config.Config, stateDir string, logf func(string, ...any)) (*Manager, error) {
	if logf == nil {
		logf = log.Printf
	}
	m := &Manager{stateDir: stateDir, tailnet: cfg.Tailnet, logf: logf, tsnetLogf: func(string, ...any) {}, slots: map[string]*Slot{}, groups: map[string]*group{}}
	if os.Getenv("TAILPROXY_TSNET_DEBUG") != "" {
		m.tsnetLogf = logf
	}
	if err := m.loadAuthKey(); err != nil {
		return nil, err
	}
	hostname := cfg.Tailnet.Hostname
	if hostname == "" {
		hostname = DefaultMainHostname
	}
	mainDir := filepath.Join(stateDir, "tsnet", "_main")
	if err := os.MkdirAll(mainDir, 0o700); err != nil {
		return nil, err
	}
	m.main = newSlot("", hostname, "", mainDir, cfg.DNS.PerEgressDoH, true, m.newServer, logf)
	if err := m.Apply(cfg); err != nil {
		return nil, err
	}
	return m, nil
}

// newServer builds a tsnet server for s with the current auth key. tsnet
// uses the key only if the node is not logged in yet.
func (m *Manager) newServer(s *Slot) *tsnet.Server {
	m.keyMu.Lock()
	key := m.authKey
	m.keyMu.Unlock()
	label := "egress " + s.name
	if s.main {
		label = "main node"
	}
	var lastMu sync.Mutex
	var last string
	return &tsnet.Server{
		Dir:           s.dir,
		Hostname:      s.hostname,
		AuthKey:       key,
		ControlURL:    m.tailnet.ControlURL,
		AdvertiseTags: m.tailnet.AdvertiseTags,
		Logf:          m.tsnetLogf,
		// tsnet repeats "go to <login URL>" every few seconds while
		// waiting for login; log each distinct message once.
		UserLogf: func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			lastMu.Lock()
			dup := msg == last
			last = msg
			lastMu.Unlock()
			if !dup {
				m.logf("%s: %s", label, msg)
			}
		},
	}
}

// Apply makes the running slots and groups match cfg.Egress: new slots are
// created (and started if the manager runs), removed ones are stopped,
// logged out and their state deleted, and changed exit nodes / DoH URLs are
// switched in place. cfg must already be validated.
func (m *Manager) Apply(cfg *config.Config) error {
	groups := map[string]*group{}
	for _, e := range cfg.Egress {
		if !e.IsGroup() {
			continue
		}
		g := &group{name: e.Name, kind: e.Type, check: e.HealthCheck}
		if e.HealthCheck != nil {
			d, err := time.ParseDuration(e.HealthCheck.Interval)
			if err != nil || d < 5*time.Second {
				return fmt.Errorf("egress %q: health_check.interval %q must be a duration of at least 5s", e.Name, e.HealthCheck.Interval)
			}
			if e.HealthCheck.URL == "" {
				return fmt.Errorf("egress %q: health_check.url is required", e.Name)
			}
			g.every = d
		}
		groups[e.Name] = g
	}

	m.mu.Lock()
	ctx := m.ctx
	want := map[string]bool{}
	var added []*Slot
	for _, e := range cfg.Egress {
		if e.IsGroup() {
			continue
		}
		want[e.Name] = true
		doh := cfg.DNS.PerEgressDoH
		if e.DoH != "" {
			doh = e.DoH
		}
		if s, ok := m.slots[e.Name]; ok {
			s.setSpec(e.ExitNode)
			s.setDoH(doh)
			continue
		}
		dir := filepath.Join(m.stateDir, "tsnet", e.Name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			m.mu.Unlock()
			return err
		}
		s := newSlot(e.Name, "tailproxy-"+e.Name, e.ExitNode, dir, doh, false, m.newServer, m.logf)
		m.slots[e.Name] = s
		added = append(added, s)
	}
	var removed []*Slot
	for name, s := range m.slots {
		if !want[name] {
			removed = append(removed, s)
			delete(m.slots, name)
		}
	}
	for _, e := range cfg.Egress {
		if g, ok := groups[e.Name]; ok {
			for _, mname := range e.Members {
				g.members = append(g.members, m.slots[mname])
			}
		}
	}
	m.order = m.order[:0]
	for _, e := range cfg.Egress {
		m.order = append(m.order, e.Name)
	}
	m.groups = groups
	m.defaultDoH = cfg.DNS.PerEgressDoH
	m.mu.Unlock()

	if ctx != nil {
		for _, s := range added {
			m.logf("egress %s: added (exit node %s)", s.name, s.spec)
			s.start(ctx)
		}
	}
	for _, s := range removed {
		s.logout(context.Background())
		s.stop()
		if err := os.RemoveAll(s.dir); err != nil {
			m.logf("egress %s: remove state: %v", s.name, err)
		}
		m.logf("egress %s: removed", s.name)
	}
	return nil
}

// Start connects the main node and all slots in the background and runs
// the group health checks.
func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	m.ctx, m.cancel = context.WithCancel(ctx)
	ctx = m.ctx
	slots := append([]*Slot{m.main}, m.slotList()...)
	m.mu.Unlock()
	for _, s := range slots {
		s.start(ctx)
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.healthLoop(ctx)
	}()
}

// healthLoop runs each group's health check when its interval has passed.
func (m *Manager) healthLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		m.mu.RLock()
		var due []*group
		for _, g := range m.groups {
			if g.check != nil && time.Since(g.last) >= g.every {
				due = append(due, g)
			}
		}
		m.mu.RUnlock()
		for _, g := range due {
			g.last = time.Now()
			for _, s := range g.members {
				s.checkHealth(ctx, g.check.URL)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// slotList returns the egress slots in config order. Caller holds m.mu.
func (m *Manager) slotList() []*Slot {
	var out []*Slot
	for _, name := range m.order {
		if s, ok := m.slots[name]; ok {
			out = append(out, s)
		}
	}
	return out
}

// Close stops all nodes. Their tailnet state is kept for the next start.
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
	}
	slots := append([]*Slot{m.main}, m.slotList()...)
	m.mu.Unlock()
	m.wg.Wait()
	for _, s := range slots {
		s.stop()
	}
	return nil
}

// Dial connects to host:port through the egress named target (a slot or a
// group) and returns the slot that carried the connection.
func (m *Manager) Dial(ctx context.Context, target, host string, port uint16) (net.Conn, string, error) {
	m.mu.RLock()
	s, isSlot := m.slots[target]
	g, isGroup := m.groups[target]
	m.mu.RUnlock()
	switch {
	case isSlot:
		c, err := s.Dial(ctx, host, port)
		return c, s.name, err
	case isGroup:
		s, err := g.pick()
		if err != nil {
			return nil, "", err
		}
		c, err := s.Dial(ctx, host, port)
		return c, s.name, err
	}
	return nil, "", fmt.Errorf("unknown egress %q", target)
}

// DialTailnet connects to a tailnet address (100.x IP or MagicDNS name) via
// the main node, or any connected slot; tailnet traffic skips exit nodes.
func (m *Manager) DialTailnet(ctx context.Context, host string, port uint16) (net.Conn, string, error) {
	m.mu.RLock()
	nodes := append([]*Slot{m.main}, m.slotList()...)
	m.mu.RUnlock()
	for _, s := range nodes {
		if s.tailnetUp() {
			c, err := s.dialTailnet(ctx, host, port)
			via := s.name
			if s.main {
				via = "main"
			}
			return c, via, err
		}
	}
	return nil, "", fmt.Errorf("%w: no node is connected to the tailnet", ErrNotReady)
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
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []Status{}
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
	main := m.main.Status()
	if main.State != StateReady {
		return "degraded", "主节点：" + main.State + "（在「出口」页登录 Tailscale）"
	}
	m.mu.RLock()
	slots := m.slotList()
	m.mu.RUnlock()
	if len(slots) == 0 {
		return "idle", "已登录 " + main.LoginName + "，还没有配置出口"
	}
	ready := 0
	for _, s := range slots {
		if s.Ready() {
			ready++
		}
	}
	state = "running"
	if ready < len(slots) {
		state = "degraded"
	}
	return state, fmt.Sprintf("已登录 %s，%d/%d 个出口就绪", main.LoginName, ready, len(slots))
}

// ---- account: one login, auth key, devices ----

// Account is the main node's login state plus how new nodes authenticate.
type Account struct {
	Main          Status `json:"main"`
	AuthKeySource string `json:"auth_key_source"`         // env:<NAME> | file | ""
	AuthKeyHint   string `json:"auth_key_hint,omitempty"` // first characters only
	AutoLogin     bool   `json:"auto_login"`              // new slots join without a login link
	KeysURL       string `json:"keys_url"`                // where to create an auth key
	EnvName       string `json:"auth_key_env_name,omitempty"`
}

// Account returns the main node's state and the auth key status.
func (m *Manager) Account() Account {
	m.keyMu.Lock()
	src, key := m.authKeySrc, m.authKey
	m.keyMu.Unlock()
	a := Account{Main: m.main.Status(), AuthKeySource: src, AutoLogin: key != "", KeysURL: "https://login.tailscale.com/admin/settings/keys", EnvName: m.tailnet.AuthKeyEnv}
	if key != "" {
		a.AuthKeyHint = keyHint(key)
	}
	return a
}

func keyHint(key string) string {
	if len(key) > 16 {
		return key[:16] + "…"
	}
	return "…"
}

func (m *Manager) loadAuthKey() error {
	if env := m.tailnet.AuthKeyEnv; env != "" {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			m.authKey, m.authKeySrc = v, "env:"+env
			return nil
		}
	}
	data, err := os.ReadFile(filepath.Join(m.stateDir, authKeyFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if k := strings.TrimSpace(string(data)); k != "" {
		m.authKey, m.authKeySrc = k, "file"
	}
	return nil
}

// SetAuthKey saves key (mode 0600) and restarts every node still waiting for
// login, so they register with it. Nodes already logged in are unaffected.
func (m *Manager) SetAuthKey(key string) error {
	key = strings.TrimSpace(key)
	if !strings.HasPrefix(key, "tskey-") || strings.ContainsAny(key, " \t\r\n") || len(key) < 20 {
		return errors.New("这不像一个 Tailscale auth key（应以 tskey- 开头）")
	}
	m.keyMu.Lock()
	if strings.HasPrefix(m.authKeySrc, "env:") {
		m.keyMu.Unlock()
		return fmt.Errorf("auth key 来自环境变量 $%s，面板不能修改", strings.TrimPrefix(m.authKeySrc, "env:"))
	}
	path := filepath.Join(m.stateDir, authKeyFile)
	if err := writeFile0600(path, []byte(key+"\n")); err != nil {
		m.keyMu.Unlock()
		return err
	}
	m.authKey, m.authKeySrc = key, "file"
	m.keyMu.Unlock()
	m.logf("tailscale: auth key saved; logging in waiting nodes")
	m.restartWaiting()
	return nil
}

// ClearAuthKey deletes the saved auth key. Logged-in nodes stay logged in;
// nodes added later need their own login link.
func (m *Manager) ClearAuthKey() error {
	m.keyMu.Lock()
	defer m.keyMu.Unlock()
	if strings.HasPrefix(m.authKeySrc, "env:") {
		return fmt.Errorf("auth key 来自环境变量 $%s，面板不能删除", strings.TrimPrefix(m.authKeySrc, "env:"))
	}
	if err := os.Remove(filepath.Join(m.stateDir, authKeyFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	m.authKey, m.authKeySrc = "", ""
	return nil
}

func (m *Manager) restartWaiting() {
	m.mu.RLock()
	ctx := m.ctx
	nodes := append([]*Slot{m.main}, m.slotList()...)
	m.mu.RUnlock()
	if ctx == nil {
		return
	}
	for _, s := range nodes {
		if s.running() && s.needsLogin() {
			s.stop()
			s.start(ctx)
		}
	}
}

// Peer is one device in the tailnet, as seen by the main node.
type Peer struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"` // MagicDNS name, or hostname
	Hostname       string     `json:"hostname"`
	IPs            []string   `json:"tailscale_ips"`
	OS             string     `json:"os,omitempty"`
	Owner          string     `json:"owner,omitempty"`
	Tags           []string   `json:"tags,omitempty"`
	Online         bool       `json:"online"`
	LastSeen       *time.Time `json:"last_seen,omitempty"`
	ExitNodeOption bool       `json:"exit_node_option"` // offers an exit node and is approved
	Country        string     `json:"country,omitempty"`
	Tailproxy      string     `json:"tailproxy,omitempty"` // "main" or egress name if it is one of ours
	UsedBy         []string   `json:"used_by,omitempty"`   // egress slots using it as exit node
}

// Peers lists the tailnet's devices, read from the main node (or, before it
// is logged in, from any connected slot). It returns nil when no node is
// logged in yet.
func (m *Manager) Peers(ctx context.Context) ([]Peer, error) {
	m.mu.RLock()
	nodes := append([]*Slot{m.main}, m.slotList()...)
	m.mu.RUnlock()
	var from *Slot
	for _, s := range nodes {
		if s.tailnetUp() {
			from = s
			break
		}
	}
	if from == nil {
		return nil, nil
	}
	ts, err := from.tsStatus(ctx)
	if err != nil {
		return nil, err
	}
	ours := map[string]string{}
	used := map[string][]string{}
	for _, s := range nodes {
		s.mu.Lock()
		self, exit := string(s.selfID), string(s.exitID)
		s.mu.Unlock()
		name := s.name
		if s.main {
			name = "main"
		}
		if self != "" {
			ours[self] = name
		}
		if exit != "" {
			used[exit] = append(used[exit], name)
		}
	}
	out := []Peer{}
	for _, p := range ts.Peer {
		e := Peer{
			ID: string(p.ID), Name: peerName(p), Hostname: p.HostName, OS: p.OS,
			Online: p.Online, ExitNodeOption: p.ExitNodeOption,
			Tailproxy: ours[string(p.ID)], UsedBy: used[string(p.ID)],
		}
		for _, ip := range p.TailscaleIPs {
			e.IPs = append(e.IPs, ip.String())
		}
		if u, ok := ts.User[p.UserID]; ok {
			e.Owner = u.LoginName
		}
		if p.Tags != nil {
			e.Tags = p.Tags.AsSlice()
		}
		if !p.Online && !p.LastSeen.IsZero() {
			ls := p.LastSeen
			e.LastSeen = &ls
		}
		if p.Location != nil {
			e.Country = p.Location.Country
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Online != out[j].Online {
			return out[i].Online
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

func writeFile0600(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	_, werr := tmp.Write(data)
	if err := errors.Join(werr, tmp.Sync(), tmp.Close()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
