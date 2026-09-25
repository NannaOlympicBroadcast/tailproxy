// Package iplearn remembers which name an address was resolved for (DESIGN
// §4.8 L4). Addresses come from DNS answers passing through tailproxy and
// from periodic resolution of the host names written in rules. When a
// captured connection's name cannot be seen (the app resolved through its
// own DoH and the ClientHello uses ECH, or real-IP DNS mode), the address
// still leads back to a name. Several names can share an address (CDNs):
// the most recent answer wins, which is the same trade-off App Connectors
// make (DESIGN S3).
package iplearn

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// TTL bounds applied to learned entries.
const (
	MinTTL     = time.Minute
	MaxTTL     = time.Hour
	maxEntries = 1 << 16
)

type entry struct {
	name    string
	expires time.Time
}

// Table maps addresses to names. It is safe for concurrent use.
type Table struct {
	mu  sync.Mutex
	m   map[netip.Addr]entry
	now func() time.Time
	// gen increases whenever an address is added that was not known.
	gen uint64
}

// New returns an empty table.
func New() *Table { return &Table{m: map[netip.Addr]entry{}, now: time.Now} }

// Add records that name resolved to addrs, valid for ttl (clamped).
func (t *Table) Add(name string, addrs []netip.Addr, ttl time.Duration) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" {
		return
	}
	ttl = min(max(ttl, MinTTL), MaxTTL)
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	exp := now.Add(ttl)
	for _, a := range addrs {
		a = a.Unmap()
		if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() {
			continue
		}
		old, ok := t.m[a]
		if !ok && len(t.m) >= maxEntries {
			t.evictExpired(now)
			if len(t.m) >= maxEntries {
				continue
			}
		}
		if !ok || old.name != name {
			t.gen++
		}
		t.m[a] = entry{name: name, expires: exp}
	}
}

func (t *Table) evictExpired(now time.Time) {
	for a, e := range t.m {
		if now.After(e.expires) {
			delete(t.m, a)
		}
	}
}

// Lookup returns the name last resolved to a, if still valid.
func (t *Table) Lookup(a netip.Addr) (string, bool) {
	a = a.Unmap()
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.m[a]
	if !ok || t.now().After(e.expires) {
		return "", false
	}
	return e.name, true
}

// Addrs returns the valid addresses whose name satisfies keep, sorted, and
// the table generation (to tell whether anything changed since).
func (t *Table) Addrs(keep func(name string) bool) ([]netip.Addr, uint64) {
	t.mu.Lock()
	now := t.now()
	t.evictExpired(now)
	var out []netip.Addr
	for a, e := range t.m {
		if keep == nil || keep(e.name) {
			out = append(out, a)
		}
	}
	gen := t.gen
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out, gen
}

// Len returns the number of entries (including expired ones not yet
// evicted).
func (t *Table) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}
