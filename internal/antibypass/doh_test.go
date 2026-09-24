package antibypass

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
)

func TestBuiltinAndAllow(t *testing.T) {
	l := New([]string{"dns.google", "8.8.8.8"})
	for name, want := range map[string]bool{
		"cloudflare-dns.com":           true,
		"security.cloudflare-dns.com.": true, // parent listed
		"DNS.QUAD9.NET":                true,
		"dns.google":                   false, // allowed
		"example.com":                  false,
		"notcloudflare-dns.com":        false,
	} {
		if got := l.BlockedDomain(name); got != want {
			t.Errorf("%s: got %v", name, got)
		}
	}
	v4, v6 := l.Addrs()
	has := func(s []netip.Addr, a string) bool {
		for _, x := range s {
			if x.String() == a {
				return true
			}
		}
		return false
	}
	if !has(v4, "1.1.1.1") || has(v4, "8.8.8.8") || !has(v6, "2606:4700:4700::1111") {
		t.Errorf("addrs: %v %v", v4, v6)
	}
	if _, _, src, _ := l.Stats(); src != "builtin" {
		t.Errorf("source %s", src)
	}
}

func TestUpdateAndCache(t *testing.T) {
	files := map[string]string{
		"/domains": "# comment\n0ms.dev\ndoh.example.net  # trailing comment\nnot a host\nlocalhost\n",
		"/v4":      "203.0.113.53        # doh.example.net\n",
		"/v6":      "2001:db8::53 # x\n",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	cache := filepath.Join(t.TempDir(), "doh.txt")
	l := New(nil)
	urls := []string{srv.URL + "/domains", srv.URL + "/v4", srv.URL + "/v6"}
	if err := l.Update(context.Background(), srv.Client(), urls, cache); err != nil {
		t.Fatal(err)
	}
	if !l.BlockedDomain("x.doh.example.net") || !l.BlockedDomain("cloudflare-dns.com") || l.BlockedDomain("localhost") {
		t.Fatal("downloaded list not applied (or builtin dropped)")
	}
	v4, v6 := l.Addrs()
	if len(v4) == 0 || len(v6) == 0 {
		t.Fatalf("addrs %v %v", v4, v6)
	}

	// A failed download keeps the current list.
	if err := l.Update(context.Background(), srv.Client(), append(urls, srv.URL+"/missing"), cache); err == nil {
		t.Fatal("partial download accepted")
	}
	if !l.BlockedDomain("0ms.dev") {
		t.Fatal("list shrank after a failed update")
	}

	m := New([]string{"0ms.dev"})
	if err := m.LoadCache(cache); err != nil {
		t.Fatal(err)
	}
	d, _, src, _ := m.Stats()
	if src != "cache" || !m.BlockedDomain("doh.example.net") || m.BlockedDomain("0ms.dev") || d == 0 {
		t.Fatalf("cache: src=%s", src)
	}
	if err := New(nil).LoadCache(filepath.Join(t.TempDir(), "none")); err != nil {
		t.Fatal(err)
	}
}
