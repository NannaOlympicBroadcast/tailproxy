package iplearn

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestLearnLookupExpire(t *testing.T) {
	tb := New()
	now := time.Unix(1000, 0)
	tb.now = func() time.Time { return now }
	a, b := netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("2001:db8::9")
	tb.Add("Chat.OpenAI.com.", []netip.Addr{a, b, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::ffff:198.51.100.1")}, 5*time.Second)
	if n, ok := tb.Lookup(a); !ok || n != "chat.openai.com" {
		t.Fatalf("lookup: %q %v", n, ok)
	}
	if n, ok := tb.Lookup(netip.MustParseAddr("198.51.100.1")); !ok || n != "chat.openai.com" {
		t.Fatal("4in6 not unmapped")
	}
	if _, ok := tb.Lookup(netip.MustParseAddr("127.0.0.1")); ok {
		t.Fatal("loopback learned")
	}
	addrs, gen := tb.Addrs(nil)
	if len(addrs) != 3 || gen == 0 {
		t.Fatalf("addrs %v gen %d", addrs, gen)
	}
	// Same answer again: generation unchanged (nothing new for nft).
	tb.Add("chat.openai.com", []netip.Addr{a}, time.Hour)
	if _, g := tb.Addrs(nil); g != gen {
		t.Fatal("generation moved without a change")
	}
	// Shared address: the latest name wins, generation moves.
	tb.Add("cdn.example", []netip.Addr{a}, time.Hour)
	if n, _ := tb.Lookup(a); n != "cdn.example" {
		t.Fatalf("latest name: %s", n)
	}
	// TTL is clamped to at least a minute.
	now = now.Add(59 * time.Second)
	if _, ok := tb.Lookup(b); !ok {
		t.Fatal("expired before MinTTL")
	}
	now = now.Add(2 * time.Second)
	if _, ok := tb.Lookup(b); ok {
		t.Fatal("not expired after MinTTL")
	}
	keep := func(n string) bool { return strings.HasSuffix(n, "example") }
	if got, _ := tb.Addrs(keep); len(got) != 1 || got[0] != a {
		t.Fatalf("filtered: %v", got)
	}
}
