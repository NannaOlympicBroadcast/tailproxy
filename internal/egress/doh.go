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

// Lookup returns the IPv4 addresses of host, or its IPv6 addresses if it has
// no IPv4 address. Exit nodes commonly lack IPv6, so IPv4 is preferred.
func (d *DoH) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	d.mu.Lock()
	if e, ok := d.cache[host]; ok && time.Now().Before(e.expires) {
		d.mu.Unlock()
		return e.addrs, nil
	}
	d.mu.Unlock()

	var errs []error
	for _, qt := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		addrs, ttl, err := d.query(ctx, host, qt)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if len(addrs) > 0 {
			ttl = min(max(ttl, minCacheTTL), maxCacheTTL)
			d.mu.Lock()
			d.cache[host] = cacheEntry{addrs: addrs, expires: time.Now().Add(ttl)}
			d.mu.Unlock()
			return addrs, nil
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("resolve %s via %s: %w", host, d.url, errors.Join(errs...))
	}
	return nil, fmt.Errorf("resolve %s via %s: no A or AAAA records", host, d.url)
}

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
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
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
		return nil, 0, fmt.Errorf("%s: no such host", host)
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
