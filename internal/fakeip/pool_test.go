package fakeip

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
)

func TestAllocateAndLookup(t *testing.T) {
	p, err := New(DefaultInet4, DefaultInet6)
	if err != nil {
		t.Fatal(err)
	}
	a := p.V4("Chat.OpenAI.com.")
	if a.String() != "198.18.0.1" {
		t.Fatalf("first v4 = %s", a)
	}
	if b := p.V4("chat.openai.com"); b != a {
		t.Fatalf("same name got %s and %s", a, b)
	}
	if c := p.V4("example.com"); c.String() != "198.18.0.2" {
		t.Fatalf("second = %s", c)
	}
	v6, ok := p.V6("chat.openai.com")
	if !ok || !DefaultInet6.Contains(v6) || v6.String() != "fc00::1" {
		t.Fatalf("v6 = %s %v", v6, ok)
	}
	for _, x := range []netip.Addr{a, v6} {
		if name, ok := p.Lookup(x); !ok || name != "chat.openai.com" {
			t.Fatalf("lookup %s = %q %v", x, name, ok)
		}
	}
	if _, ok := p.Lookup(netip.MustParseAddr("198.18.9.9")); ok {
		t.Fatal("unallocated address resolved")
	}
	if !p.Contains(netip.MustParseAddr("198.19.255.254")) || p.Contains(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("contains")
	}
	if !p.Contains(netip.MustParseAddr("::ffff:198.18.0.1")) {
		t.Fatal("4in6 not unmapped")
	}
}

func TestRecycleOldest(t *testing.T) {
	p, _ := New(netip.MustParsePrefix("10.9.0.0/29"), netip.Prefix{}) // 6 usable
	for i := 0; i < 6; i++ {
		p.V4(fmt.Sprintf("n%d", i))
	}
	a := p.V4("n6") // reuses n0's address
	if name, _ := p.Lookup(a); name != "n6" || a.String() != "10.9.0.1" {
		t.Fatalf("recycle: %s %s", a, name)
	}
	if got := p.V4("n0"); got.String() != "10.9.0.2" {
		t.Fatalf("evicted name got %s", got)
	}
	if _, ok := p.V6("x"); ok {
		t.Fatal("v6 without pool")
	}
}

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fakeip.json")
	p, _ := New(DefaultInet4, DefaultInet6)
	a := p.V4("a.example")
	p.V6("a.example")
	if err := p.Save(path); err != nil {
		t.Fatal(err)
	}
	q, _ := New(DefaultInet4, DefaultInet6)
	if err := q.Load(path); err != nil {
		t.Fatal(err)
	}
	if name, ok := q.Lookup(a); !ok || name != "a.example" {
		t.Fatalf("restored lookup: %q %v", name, ok)
	}
	if b := q.V4("b.example"); b.String() != "198.18.0.2" {
		t.Fatalf("next after restore: %s", b)
	}
	// Different pool: ignored.
	r, _ := New(netip.MustParsePrefix("10.0.0.0/16"), netip.Prefix{})
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Lookup(netip.MustParseAddr("10.0.0.1")); ok {
		t.Fatal("loaded a table for another pool")
	}
}

func TestBadPools(t *testing.T) {
	if _, err := New(netip.Prefix{}, netip.Prefix{}); err == nil {
		t.Fatal("no v4")
	}
	if _, err := New(DefaultInet4, netip.MustParsePrefix("10.0.0.0/8")); err == nil {
		t.Fatal("v4 as v6")
	}
	if _, err := New(netip.MustParsePrefix("10.0.0.0/32"), netip.Prefix{}); err == nil {
		t.Fatal("tiny pool")
	}
}
