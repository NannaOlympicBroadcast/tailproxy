// Package fakeip hands out addresses from a reserved range (default
// 198.18.0.0/15, RFC 2544, and fc00::/18 — the same pools as sing-box,
// DESIGN §4.2) to domain names, so a later connection to the address can
// be traced back to the name the client looked up.
package fakeip

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"strings"
	"sync"
)

// Default pools.
var (
	DefaultInet4 = netip.MustParsePrefix("198.18.0.0/15")
	DefaultInet6 = netip.MustParsePrefix("fc00::/18")
)

// maxEntries caps the table even for huge (IPv6) pools. Addresses are
// reused round-robin, so a name keeps its address until 65536 other names
// have been looked up since.
const maxEntries = 1 << 16

// Pool maps names to fake addresses and back. It is safe for concurrent use.
type Pool struct {
	v4, v6 *family

	mu sync.Mutex
}

type family struct {
	prefix netip.Prefix
	size   int // usable addresses
	next   int // next offset to hand out, 0..size-1
	byName map[string]int
	byOff  map[int]string
}

func newFamily(p netip.Prefix) (*family, error) {
	p = p.Masked()
	bits := p.Addr().BitLen() - p.Bits()
	if bits < 2 {
		return nil, fmt.Errorf("fakeip pool %s is too small", p)
	}
	size := maxEntries
	if bits < 17 {
		size = 1<<bits - 2 // skip the network and last address
	}
	return &family{prefix: p, size: size, byName: map[string]int{}, byOff: map[int]string{}}, nil
}

// addr returns the address at offset off (offset 0 is prefix+1).
func (f *family) addr(off int) netip.Addr {
	base := new(big.Int).SetBytes(f.prefix.Addr().AsSlice())
	base.Add(base, big.NewInt(int64(off+1)))
	b := base.FillBytes(make([]byte, f.prefix.Addr().BitLen()/8))
	a, _ := netip.AddrFromSlice(b)
	return a
}

// offset is the inverse of addr; ok is false outside the pool's range.
func (f *family) offset(a netip.Addr) (int, bool) {
	if !f.prefix.Contains(a) {
		return 0, false
	}
	d := new(big.Int).Sub(new(big.Int).SetBytes(a.AsSlice()), new(big.Int).SetBytes(f.prefix.Addr().AsSlice()))
	off := int(d.Int64()) - 1
	if !d.IsInt64() || off < 0 || off >= f.size {
		return 0, false
	}
	return off, true
}

func (f *family) get(name string) netip.Addr {
	if off, ok := f.byName[name]; ok {
		return f.addr(off)
	}
	off := f.next
	f.next = (f.next + 1) % f.size
	if old, ok := f.byOff[off]; ok {
		delete(f.byName, old)
	}
	f.byName[name], f.byOff[off] = off, name
	return f.addr(off)
}

// New creates a pool. inet6 may be the zero Prefix to hand out IPv4 only.
func New(inet4, inet6 netip.Prefix) (*Pool, error) {
	p := &Pool{}
	var err error
	if !inet4.IsValid() || !inet4.Addr().Is4() {
		return nil, errors.New("fakeip: an IPv4 pool is required")
	}
	if p.v4, err = newFamily(inet4); err != nil {
		return nil, err
	}
	if inet6.IsValid() {
		if !inet6.Addr().Is6() || inet6.Addr().Is4In6() {
			return nil, fmt.Errorf("fakeip: %s is not an IPv6 prefix", inet6)
		}
		if p.v6, err = newFamily(inet6); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

// V4 returns name's fake IPv4 address, allocating one if needed.
func (p *Pool) V4(name string) netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.v4.get(normalize(name))
}

// V6 returns name's fake IPv6 address; ok is false without an IPv6 pool.
func (p *Pool) V6(name string) (netip.Addr, bool) {
	if p.v6 == nil {
		return netip.Addr{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.v6.get(normalize(name)), true
}

// Contains reports whether a is inside one of the pools, allocated or not.
func (p *Pool) Contains(a netip.Addr) bool {
	a = a.Unmap()
	return p.v4.prefix.Contains(a) || (p.v6 != nil && p.v6.prefix.Contains(a))
}

// Prefixes returns the pools, for capture rules.
func (p *Pool) Prefixes() []netip.Prefix {
	out := []netip.Prefix{p.v4.prefix}
	if p.v6 != nil {
		out = append(out, p.v6.prefix)
	}
	return out
}

// Lookup returns the name a fake address was handed out for.
func (p *Pool) Lookup(a netip.Addr) (string, bool) {
	a = a.Unmap()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, f := range []*family{p.v4, p.v6} {
		if f == nil {
			continue
		}
		if off, ok := f.offset(a); ok {
			name, ok := f.byOff[off]
			return name, ok
		}
	}
	return "", false
}

type snapshot struct {
	Inet4 string         `json:"inet4"`
	Inet6 string         `json:"inet6,omitempty"`
	Next4 int            `json:"next4"`
	Next6 int            `json:"next6,omitempty"`
	V4    map[string]int `json:"v4"`
	V6    map[string]int `json:"v6,omitempty"`
}

// Save writes the table to path (mode 0600), so clients that cached fake
// addresses keep working after a restart.
func (p *Pool) Save(path string) error {
	p.mu.Lock()
	s := snapshot{Inet4: p.v4.prefix.String(), Next4: p.v4.next, V4: p.v4.byName}
	if p.v6 != nil {
		s.Inet6, s.Next6, s.V6 = p.v6.prefix.String(), p.v6.next, p.v6.byName
	}
	data, err := json.Marshal(s)
	p.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load restores a table written by Save. A missing file, or one written for
// different pools, is ignored.
func (p *Pool) Load(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var s snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("fakeip: %s: %w", path, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	restore := func(f *family, prefix string, next int, m map[string]int) {
		if f == nil || prefix != f.prefix.String() {
			return
		}
		for name, off := range m {
			if off >= 0 && off < f.size {
				f.byName[name], f.byOff[off] = off, name
			}
		}
		if next >= 0 && next < f.size {
			f.next = next
		}
	}
	restore(p.v4, s.Inet4, s.Next4, s.V4)
	restore(p.v6, s.Inet6, s.Next6, s.V6)
	return nil
}
