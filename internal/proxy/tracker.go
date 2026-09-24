// Package proxy routes connections from the inbounds (SOCKS5, TPROXY) to
// direct / reject / tailnet / egress targets according to the rule engine,
// and tracks them for the panel.
package proxy

import (
	"sync"
	"sync/atomic"
	"time"
)

const recentMax = 200

// Conn is one proxied connection.
type Conn struct {
	ID        uint64
	Started   time.Time
	Inbound   string
	Source    string
	Host      string // domain if known, else the destination IP
	Port      uint16
	DestIP    string // original destination IP (transparent capture), if any
	DomainSrc string // where Host came from: socks, fakeip, tls, http; "" for none
	ECH       bool   // ClientHello had ECH: a sniffed Host is only the outer name
	RuleIndex int
	Reason    string
	Target    string // rule target: direct, reject, tailnet or an egress name
	Via       string // slot that carried it (egress / tailnet)

	up, down atomic.Int64

	mu    sync.Mutex
	ended time.Time
	err   string
}

// ConnView is the JSON form of a Conn.
type ConnView struct {
	ID        uint64     `json:"id"`
	Started   time.Time  `json:"started"`
	Ended     *time.Time `json:"ended,omitempty"`
	Inbound   string     `json:"inbound"`
	Source    string     `json:"source"`
	Host      string     `json:"host"`
	Port      uint16     `json:"port"`
	DestIP    string     `json:"dest_ip,omitempty"`
	DomainSrc string     `json:"domain_source,omitempty"`
	ECH       bool       `json:"ech,omitempty"`
	RuleIndex int        `json:"rule_index"`
	Reason    string     `json:"reason"`
	Target    string     `json:"target"`
	Via       string     `json:"via,omitempty"`
	Up        int64      `json:"up"`
	Down      int64      `json:"down"`
	Error     string     `json:"error,omitempty"`
}

// Tracker keeps active connections and the most recent finished ones.
type Tracker struct {
	next   atomic.Uint64
	total  atomic.Uint64
	failed atomic.Uint64

	mu     sync.Mutex
	active map[uint64]*Conn
	recent []*Conn // ring, newest last
}

// NewTracker returns an empty tracker.
func NewTracker() *Tracker { return &Tracker{active: map[uint64]*Conn{}} }

func (t *Tracker) add(c *Conn) {
	c.ID = t.next.Add(1)
	c.Started = time.Now()
	t.total.Add(1)
	t.mu.Lock()
	t.active[c.ID] = c
	t.mu.Unlock()
}

// finish marks c done; err is empty on a clean close.
func (t *Tracker) finish(c *Conn, err string) {
	c.mu.Lock()
	c.ended, c.err = time.Now(), err
	c.mu.Unlock()
	if err != "" {
		t.failed.Add(1)
	}
	t.mu.Lock()
	delete(t.active, c.ID)
	t.recent = append(t.recent, c)
	if len(t.recent) > recentMax {
		t.recent = t.recent[len(t.recent)-recentMax:]
	}
	t.mu.Unlock()
}

func (c *Conn) view() ConnView {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := ConnView{
		ID: c.ID, Started: c.Started, Inbound: c.Inbound, Source: c.Source, Host: c.Host, Port: c.Port,
		DestIP: c.DestIP, DomainSrc: c.DomainSrc, ECH: c.ECH,
		RuleIndex: c.RuleIndex, Reason: c.Reason, Target: c.Target, Via: c.Via,
		Up: c.up.Load(), Down: c.down.Load(), Error: c.err,
	}
	if !c.ended.IsZero() {
		e := c.ended
		v.Ended = &e
	}
	return v
}

// Snapshot is what the panel shows.
type Snapshot struct {
	Active []ConnView `json:"active"`
	Recent []ConnView `json:"recent"` // newest first
	Total  uint64     `json:"total"`
	Failed uint64     `json:"failed"`
}

// Snapshot returns active connections (oldest first) and recent ones (newest first).
func (t *Tracker) Snapshot() Snapshot {
	t.mu.Lock()
	active := make([]*Conn, 0, len(t.active))
	for _, c := range t.active {
		active = append(active, c)
	}
	recent := append([]*Conn(nil), t.recent...)
	t.mu.Unlock()
	s := Snapshot{Active: []ConnView{}, Recent: []ConnView{}, Total: t.total.Load(), Failed: t.failed.Load()}
	for _, c := range active {
		s.Active = append(s.Active, c.view())
	}
	sortByID(s.Active)
	for i := len(recent) - 1; i >= 0; i-- {
		s.Recent = append(s.Recent, recent[i].view())
	}
	return s
}

func sortByID(v []ConnView) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j].ID < v[j-1].ID; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}
