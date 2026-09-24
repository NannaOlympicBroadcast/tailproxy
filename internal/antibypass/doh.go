// Package antibypass keeps the list of public encrypted-DNS endpoints that
// transparent capture blocks (DESIGN §4.8 L2): applications that resolve
// through their own DoH never ask tailproxy's DNS, so FakeIP cannot see the
// name. Blocking the endpoints makes them fall back to the system resolver.
package antibypass

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// builtin is used until the lists are downloaded (and if they never are):
// the providers browsers ship as DoH presets. Every entry also appears in
// the public lists (DESIGN S38).
var builtinDomains = []string{
	"cloudflare-dns.com", "mozilla.cloudflare-dns.com", "one.one.one.one",
	"dns.google", "dns.google.com", "dns.quad9.net", "doh.opendns.com",
	"dns.nextdns.io", "doh.cleanbrowsing.org", "dns.adguard-dns.com",
	"doh.pub", "dns.alidns.com", "doh.360.cn",
}

var builtinIPs = []string{
	"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
	"208.67.222.222", "208.67.220.220", "223.5.5.5", "223.6.6.6",
	"2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844",
	"2620:fe::fe", "2620:fe::9",
}

// Lists is the current block list. The zero value blocks nothing; use New.
type Lists struct {
	mu      sync.RWMutex
	domains map[string]bool
	ips     map[netip.Addr]bool
	allow   map[string]bool // names and addresses (doh_allow)
	source  string          // "builtin", "cache" or "download"
	updated time.Time
}

// New returns lists holding the built-in entries, minus allow.
func New(allow []string) *Lists {
	l := &Lists{allow: map[string]bool{}}
	for _, a := range allow {
		a = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a)), ".")
		if ip, err := netip.ParseAddr(a); err == nil {
			a = ip.Unmap().String()
		}
		if a != "" {
			l.allow[a] = true
		}
	}
	d, i := map[string]bool{}, map[netip.Addr]bool{}
	for _, s := range builtinDomains {
		d[s] = true
	}
	for _, s := range builtinIPs {
		i[netip.MustParseAddr(s)] = true
	}
	l.set(d, i, "builtin")
	return l
}

func (l *Lists) set(domains map[string]bool, ips map[netip.Addr]bool, source string) {
	for a := range l.allow {
		delete(domains, a)
		if ip, err := netip.ParseAddr(a); err == nil {
			delete(ips, ip)
		}
	}
	l.mu.Lock()
	l.domains, l.ips, l.source, l.updated = domains, ips, source, time.Now()
	l.mu.Unlock()
}

// BlockedDomain reports whether name or one of its parents is listed.
func (l *Lists) BlockedDomain(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.allow[name] {
		return false
	}
	for n := name; n != ""; {
		if l.domains[n] {
			return true
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			break
		}
		n = n[i+1:]
	}
	return false
}

// Addrs returns the listed addresses, sorted, split by family.
func (l *Lists) Addrs() (v4, v6 []netip.Addr) {
	l.mu.RLock()
	for a := range l.ips {
		if a.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	l.mu.RUnlock()
	less := func(s []netip.Addr) func(i, j int) bool { return func(i, j int) bool { return s[i].Less(s[j]) } }
	sort.Slice(v4, less(v4))
	sort.Slice(v6, less(v6))
	return
}

// Stats describes the lists for the panel.
func (l *Lists) Stats() (domains, ips int, source string, updated time.Time) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.domains), len(l.ips), l.source, l.updated
}

// Parse reads one list: an entry per line, "#" starts a comment; each
// entry is an IP address or a host name.
func Parse(r io.Reader, domains map[string]bool, ips map[netip.Addr]bool) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		e := strings.TrimSuffix(strings.ToLower(f[0]), ".")
		if ip, err := netip.ParseAddr(e); err == nil {
			ips[ip.Unmap()] = true
			continue
		}
		if validHost(e) {
			domains[e] = true
		}
	}
	return sc.Err()
}

func validHost(h string) bool {
	if len(h) == 0 || len(h) > 253 || !strings.Contains(h, ".") {
		return false
	}
	for _, c := range h {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}

// LoadCache restores lists saved by Update; a missing cache is not an
// error.
func (l *Lists) LoadCache(path string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	d, i := map[string]bool{}, map[netip.Addr]bool{}
	if err := Parse(f, d, i); err != nil {
		return err
	}
	if len(d)+len(i) == 0 {
		return nil
	}
	mergeBuiltin(d, i)
	l.set(d, i, "cache")
	return nil
}

func mergeBuiltin(d map[string]bool, i map[netip.Addr]bool) {
	for _, s := range builtinDomains {
		d[s] = true
	}
	for _, s := range builtinIPs {
		i[netip.MustParseAddr(s)] = true
	}
}

// Update downloads every URL (all must succeed, so a partial download
// never shrinks the list), replaces the lists and writes cachePath.
func (l *Lists) Update(ctx context.Context, client *http.Client, urls []string, cachePath string) error {
	d, i := map[string]bool{}, map[netip.Addr]bool{}
	for _, u := range urls {
		if err := fetch(ctx, client, u, d, i); err != nil {
			return fmt.Errorf("doh list %s: %w", u, err)
		}
	}
	if len(d)+len(i) == 0 {
		return errors.New("doh lists are empty")
	}
	mergeBuiltin(d, i)
	l.set(d, i, "download")
	if cachePath != "" {
		return writeCache(cachePath, d, i)
	}
	return nil
}

func fetch(ctx context.Context, client *http.Client, url string, d map[string]bool, i map[netip.Addr]bool) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	return Parse(io.LimitReader(resp.Body, 8<<20), d, i)
}

func writeCache(path string, d map[string]bool, i map[netip.Addr]bool) error {
	var b strings.Builder
	b.WriteString("# tailproxy DoH block list cache\n")
	names := make([]string, 0, len(d))
	for n := range d {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b.WriteString(n + "\n")
	}
	addrs := make([]netip.Addr, 0, len(i))
	for a := range i {
		addrs = append(addrs, a)
	}
	sort.Slice(addrs, func(x, y int) bool { return addrs[x].Less(addrs[y]) })
	for _, a := range addrs {
		b.WriteString(a.String() + "\n")
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
