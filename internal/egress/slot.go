package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

// Slot states reported to the panel.
const (
	StateStarting         = "starting"
	StateNeedsLogin       = "needs_login"
	StateNeedsMachineAuth = "needs_machine_auth"
	StateExitNodePending  = "exit_node_pending"
	StateExitNodeOffline  = "exit_node_offline"
	StateReady            = "ready"
	StateStopped          = "stopped"
	StateError            = "error"
)

// ErrNotReady is returned when a connection is routed to a slot that cannot
// carry traffic yet.
var ErrNotReady = errors.New("egress not ready")

// Slot is one embedded tsnet node pinned to one exit node (DESIGN §4.4).
type Slot struct {
	name string
	spec string // exit node as configured: hostname, 100.x IP or StableID
	srv  *tsnet.Server
	doh  *DoH
	logf func(string, ...any)

	started atomic.Bool // srv.Start succeeded; tsnet.Server.Close panics otherwise

	mu     sync.Mutex
	status Status
	exitID tailcfg.StableNodeID
	health *Health
}

// Status is a slot's or group's runtime state as shown in the panel.
type Status struct {
	Name         string        `json:"name"`
	Kind         string        `json:"kind"` // "slot" or "group"
	State        string        `json:"state"`
	Detail       string        `json:"detail,omitempty"`
	AuthURL      string        `json:"auth_url,omitempty"`
	Hostname     string        `json:"hostname,omitempty"`
	TailscaleIPs []string      `json:"tailscale_ips,omitempty"`
	ExitNode     *ExitNodeInfo `json:"exit_node,omitempty"`
	Health       *Health       `json:"health,omitempty"`
	Members      []string      `json:"members,omitempty"`
	Selected     string        `json:"selected,omitempty"` // group: member currently used
}

// ExitNodeInfo describes the exit node a slot uses.
type ExitNodeInfo struct {
	Spec   string `json:"spec"`
	ID     string `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
	Online bool   `json:"online"`
}

// Health is the last health check of a slot.
type Health struct {
	URL     string    `json:"url"`
	OK      bool      `json:"ok"`
	RTTMs   float64   `json:"rtt_ms,omitempty"`
	Checked time.Time `json:"checked"`
	Error   string    `json:"error,omitempty"`
}

func newSlot(name, spec string, srv *tsnet.Server, dohURL string, logf func(string, ...any)) *Slot {
	s := &Slot{name: name, spec: spec, srv: srv, logf: logf}
	s.status = Status{Name: name, Kind: "slot", State: StateStarting, Hostname: srv.Hostname, ExitNode: &ExitNodeInfo{Spec: spec}}
	s.doh = NewDoH(dohURL, &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			ap, err := netip.ParseAddrPort(addr)
			if err != nil {
				return nil, fmt.Errorf("DoH URL must use an IP address, got %s", addr)
			}
			return s.dialIP(ctx, ap)
		},
		ForceAttemptHTTP2: true,
	}})
	return s
}

// run starts the node and keeps its status (and exit node pref) current.
func (s *Slot) run(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	if err := s.srv.Start(); err != nil {
		s.set(func(st *Status) { st.State, st.Detail = StateError, err.Error() })
		return
	}
	s.started.Store(true)
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		s.refresh(ctx)
		select {
		case <-ctx.Done():
			s.set(func(st *Status) { st.State, st.Detail = StateStopped, "" })
			return
		case <-t.C:
		}
	}
}

func (s *Slot) refresh(ctx context.Context) {
	lc, err := s.srv.LocalClient()
	if err != nil {
		s.set(func(st *Status) { st.State, st.Detail = StateError, err.Error() })
		return
	}
	qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ts, err := lc.Status(qctx)
	if err != nil {
		if ctx.Err() == nil {
			s.set(func(st *Status) { st.State, st.Detail = StateError, "status: "+err.Error() })
		}
		return
	}

	var ips []string
	for _, ip := range ts.TailscaleIPs {
		ips = append(ips, ip.String())
	}
	s.set(func(st *Status) { st.TailscaleIPs, st.AuthURL = ips, "" })

	switch ts.BackendState {
	case ipn.Running.String():
	case ipn.NeedsLogin.String():
		s.set(func(st *Status) {
			st.State, st.AuthURL = StateNeedsLogin, ts.AuthURL
			st.Detail = "需要登录：打开 auth_url，或设置 tailnet.auth_key_env 指向的 auth key 后重启"
		})
		return
	case ipn.NeedsMachineAuth.String():
		s.set(func(st *Status) {
			st.State, st.Detail = StateNeedsMachineAuth, "需要在 Tailscale 管理后台批准这台设备"
		})
		return
	default:
		s.set(func(st *Status) { st.State, st.Detail = StateStarting, "backend "+ts.BackendState })
		return
	}

	s.mu.Lock()
	want := s.exitID
	s.mu.Unlock()
	if cur := ts.ExitNodeStatus; cur != nil && want != "" && cur.ID == want {
		online := cur.Online
		s.set(func(st *Status) {
			st.ExitNode.ID, st.ExitNode.Online = string(cur.ID), online
			st.State, st.Detail = StateReady, ""
			if !online {
				st.State, st.Detail = StateExitNodeOffline, "出口节点当前不在线"
			}
		})
		return
	}

	peer, err := findExitNode(ts, s.spec)
	if err != nil {
		s.set(func(st *Status) { st.State, st.Detail = StateExitNodePending, err.Error() })
		return
	}
	if _, err := lc.EditPrefs(qctx, &ipn.MaskedPrefs{
		Prefs:         ipn.Prefs{ExitNodeID: peer.ID},
		ExitNodeIDSet: true,
	}); err != nil {
		s.set(func(st *Status) {
			st.State, st.Detail = StateExitNodePending, "设置出口节点失败："+err.Error()
		})
		return
	}
	s.mu.Lock()
	s.exitID = peer.ID
	s.mu.Unlock()
	s.logf("egress %s: exit node %s (%s) selected", s.name, peerName(peer), peer.ID)
	s.set(func(st *Status) {
		st.ExitNode.ID, st.ExitNode.Name, st.ExitNode.Online = string(peer.ID), peerName(peer), peer.Online
		st.State, st.Detail = StateExitNodePending, "已设置出口节点，等待生效"
	})
}

// findExitNode matches spec against the peers' StableID, hostname, MagicDNS
// name (full or first label) and Tailscale IPs.
func findExitNode(ts *ipnstate.Status, spec string) (*ipnstate.PeerStatus, error) {
	want := strings.TrimSuffix(strings.ToLower(spec), ".")
	for _, p := range ts.Peer {
		dns := strings.TrimSuffix(strings.ToLower(p.DNSName), ".")
		match := string(p.ID) == spec || strings.EqualFold(p.HostName, want) || dns == want ||
			strings.SplitN(dns, ".", 2)[0] == want
		for _, ip := range p.TailscaleIPs {
			match = match || ip.String() == want
		}
		if !match {
			continue
		}
		if !p.ExitNodeOption {
			return nil, fmt.Errorf("节点 %s 没有提供出口节点，或尚未在管理后台批准（需要 --advertise-exit-node 并批准，且 ACL 授予 autogroup:internet）", peerName(p))
		}
		return p, nil
	}
	return nil, fmt.Errorf("在 tailnet 中找不到出口节点 %q（按主机名、MagicDNS 名、100.x IP 或 StableID 匹配）", spec)
}

func peerName(p *ipnstate.PeerStatus) string {
	if p.DNSName != "" {
		return strings.TrimSuffix(p.DNSName, ".")
	}
	return p.HostName
}

func (s *Slot) set(f func(*Status)) {
	s.mu.Lock()
	f(&s.status)
	s.mu.Unlock()
}

// Status returns a copy of the slot's status.
func (s *Slot) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.status
	en := *s.status.ExitNode
	st.ExitNode = &en
	st.TailscaleIPs = append([]string(nil), s.status.TailscaleIPs...)
	if s.health != nil {
		h := *s.health
		st.Health = &h
	}
	return st
}

// Ready reports whether traffic can go through the exit node.
func (s *Slot) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status.State == StateReady
}

// tailnetUp reports whether the node is connected (exit node not required).
func (s *Slot) tailnetUp() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.status.State {
	case StateReady, StateExitNodePending, StateExitNodeOffline:
		return true
	}
	return false
}

// Dial connects to host:port through the slot's exit node. Domain names are
// resolved with DoH through the same exit node, so no DNS query leaves via
// the local network.
func (s *Slot) Dial(ctx context.Context, host string, port uint16) (net.Conn, error) {
	if !s.Ready() {
		st := s.Status()
		return nil, fmt.Errorf("%w: %s is %s %s", ErrNotReady, s.name, st.State, st.Detail)
	}
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip.Unmap()}
	} else {
		if addrs, err = s.doh.Lookup(ctx, host); err != nil {
			return nil, err
		}
	}
	var errs []error
	for _, a := range addrs {
		c, err := s.dialIP(ctx, netip.AddrPortFrom(a, port))
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func (s *Slot) dialIP(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return s.srv.Dial(ctx, "tcp", ap.String())
}

// dialTailnet dials a tailnet address; MagicDNS names are resolved by tsnet.
func (s *Slot) dialTailnet(ctx context.Context, host string, port uint16) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return s.srv.Dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
}

// checkHealth fetches url through the exit node and records the result.
func (s *Slot) checkHealth(ctx context.Context, url string) {
	h := &Health{URL: url, Checked: time.Now()}
	defer func() {
		s.mu.Lock()
		s.health = h
		s.mu.Unlock()
	}()
	if !s.Ready() {
		h.Error = "出口未就绪"
		return
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port, err := strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				return nil, err
			}
			return s.Dial(ctx, host, uint16(port))
		},
		DisableKeepAlives: true,
	}}
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		h.Error = err.Error()
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		h.Error = err.Error()
		return
	}
	resp.Body.Close()
	h.RTTMs = float64(time.Since(start).Microseconds()) / 1000
	h.OK = resp.StatusCode < 400
	if !h.OK {
		h.Error = resp.Status
	}
}

func (s *Slot) healthOK() (ok bool, rtt float64, measured bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.health == nil {
		return true, 0, false
	}
	return s.health.OK, s.health.RTTMs, s.health.OK
}
