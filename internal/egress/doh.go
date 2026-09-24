package egress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DefaultDoHURL resolves names through the exit node. An IP-literal URL needs
// no bootstrap lookup, so nothing is resolved outside the slot.
const DefaultDoHURL = "https://1.1.1.1/dns-query"

const (
	minCacheTTL = 30 * time.Second
	maxCacheTTL = 5 * time.Minute
)

// DoH is a small RFC 8484 client with a TTL cache. The HTTP client decides
// which path queries take; for a slot it dials through that slot's exit node.
type DoH struct {
	url    string
	client *http.Client
	// Logf, if set, reports failed and retried queries.
	Logf func(string, ...any)

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	addrs   []netip.Addr
	expires time.Time
}

// NewDoH returns a resolver that sends queries to url using client.
func NewDoH(url string, client *http.Client) *DoH {
	if url == "" {
		url = DefaultDoHURL
	}
	return &DoH{url: url, client: client, cache: map[string]cacheEntry{}}
}

// Lookup returns host's addresses, IPv4 first. A and AAAA are queried in
// parallel; each query gets a short timeout and one retry on a fresh
// connection, so a dead pooled connection costs seconds, not the caller's
// whole deadline. A result is cached only when both queries answered.
func (d *DoH) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	d.mu.Lock()
	if e, ok := d.cache[host]; ok && time.Now().Before(e.expires) {
		d.mu.Unlock()
		return e.addrs, nil
	}
	d.mu.Unlock()

	type result struct {
		addrs []netip.Addr
		ttl   time.Duration
		err   error
	}
	var v4, v6 result
	var wg sync.WaitGroup
	for _, q := range []struct {
		qt  dnsmessage.Type
		out *result
	}{{dnsmessage.TypeA, &v4}, {dnsmessage.TypeAAAA, &v6}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q.out.addrs, q.out.ttl, q.out.err = d.queryRetry(ctx, host, q.qt)
		}()
	}
	wg.Wait()

	addrs := append(append([]netip.Addr(nil), v4.addrs...), v6.addrs...)
	var errs []error
	for _, r := range []result{v4, v6} {
		if r.err != nil {
			errs = append(errs, r.err)
		}
	}
	if len(addrs) == 0 {
		if len(errs) > 0 {
			return nil, fmt.Errorf("resolve %s via %s: %w", host, d.url, errors.Join(errs...))
		}
		return nil, fmt.Errorf("resolve %s via %s: no A or AAAA records", host, d.url)
	}
	if len(errs) > 0 {
		if d.Logf != nil {
			d.Logf("doh: %s via %s: partial answer: %v", host, d.url, errors.Join(errs...))
		}
		return addrs, nil // usable, but not cached
	}
	ttl := maxCacheTTL
	for _, r := range []result{v4, v6} {
		if len(r.addrs) > 0 {
			ttl = min(ttl, r.ttl)
		}
	}
	ttl = min(max(ttl, minCacheTTL), maxCacheTTL)
	d.mu.Lock()
	d.cache[host] = cacheEntry{addrs: addrs, expires: time.Now().Add(ttl)}
	d.mu.Unlock()
	return addrs, nil
}

// queryTimeout bounds one DoH round trip.
const queryTimeout = 5 * time.Second

// queryRetry runs query and, if it fails for a reason other than the answer
// itself, drops pooled connections and tries once more.
func (d *DoH) queryRetry(ctx context.Context, host string, qt dnsmessage.Type) ([]netip.Addr, time.Duration, error) {
	addrs, ttl, err := d.query(ctx, host, qt)
	if err == nil || ctx.Err() != nil || errors.Is(err, errNoSuchHost) {
		return addrs, ttl, err
	}
	if d.Logf != nil {
		d.Logf("doh: %s %v via %s: %v; retrying on a new connection", host, qt, d.url, err)
	}
	d.client.CloseIdleConnections()
	return d.query(ctx, host, qt)
}

var errNoSuchHost = errors.New("no such host")

func (d *DoH) query(ctx context.Context, host string, qt dnsmessage.Type) ([]netip.Addr, time.Duration, error) {
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return nil, 0, err
	}
	// RFC 8484 §4.1: use ID 0 for cache friendliness.
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: qt, Class: dnsmessage.ClassINET}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(packed))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("DoH HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, 0, err
	}
	var reply dnsmessage.Message
	if err := reply.Unpack(body); err != nil {
		return nil, 0, fmt.Errorf("DoH reply: %w", err)
	}
	if reply.RCode == dnsmessage.RCodeNameError {
		return nil, 0, fmt.Errorf("%s: %w", host, errNoSuchHost)
	}
	if reply.RCode != dnsmessage.RCodeSuccess {
		return nil, 0, fmt.Errorf("DoH rcode %v", reply.RCode)
	}
	var addrs []netip.Addr
	ttl := maxCacheTTL
	for _, a := range reply.Answers {
		var ip netip.Addr
		switch r := a.Body.(type) {
		case *dnsmessage.AResource:
			ip = netip.AddrFrom4(r.A)
		case *dnsmessage.AAAAResource:
			ip = netip.AddrFrom16(r.AAAA)
		default:
			continue // CNAMEs etc.: the target's records follow in the answer
		}
		addrs = append(addrs, ip)
		ttl = min(ttl, time.Duration(a.Header.TTL)*time.Second)
	}
	return addrs, ttl, nil
}
