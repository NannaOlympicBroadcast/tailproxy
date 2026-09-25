package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
)

// ErrRejected is returned for connections matched by a reject rule.
var ErrRejected = errors.New("rejected by rule")

// Egress is the part of the egress manager the router needs.
type Egress interface {
	Dial(ctx context.Context, target, host string, port uint16) (net.Conn, string, error)
	DialTailnet(ctx context.Context, host string, port uint16) (net.Conn, string, error)
}

// Router picks a target for each connection and dials it.
type Router struct {
	Rules   func() *rule.Engine // current rules; changes with panel edits
	Egress  Egress
	Tracker *Tracker
	// Direct dials direct targets. With transparent capture its Control
	// sets the bypass mark and its Resolver skips the FakeIP front end.
	Direct net.Dialer
	// UnknownDomain applies when a transparently captured connection's
	// domain could not be determined (dns.unknown_domain): "" or
	// "ip_rules_only" matches IP rules only, "reject" refuses it, and
	// "egress:<name>" sends it there.
	UnknownDomain string
}

// Dest is where a connection goes, as far as the inbound knows.
type Dest struct {
	Domain    string     // "" if unknown
	IP        netip.Addr // real destination address; invalid for FakeIPs
	Port      uint16
	DomainSrc string // socks, fakeip, tls, http, learned
	ECH       bool
	// OuterSNI is the outer name of an ECH ClientHello. It is the
	// provider's public name, not the site, so it is kept out of Domain
	// and only outer_sni rules match it (DESIGN §4.8 L4).
	OuterSNI string
	// Transparent is set for captured connections, where UnknownDomain
	// applies.
	Transparent bool
}

// Connect matches host:port (a domain or an IP) against the rules and dials
// the target. The returned Conn is registered in the tracker; call Relay
// (or finish it) when done. On error the connection is already recorded as
// failed.
func (r *Router) Connect(ctx context.Context, inbound, source, host string, port uint16) (net.Conn, *Conn, error) {
	d := Dest{Port: port}
	if ip, err := netip.ParseAddr(host); err == nil {
		d.IP = ip.Unmap()
	} else {
		d.Domain, d.DomainSrc = host, "socks"
	}
	return r.ConnectDest(ctx, inbound, source, d)
}

// ConnectDest is Connect for a destination that may have both a domain and
// an address. Domain rules see the domain; IP rules see the real address.
func (r *Router) ConnectDest(ctx context.Context, inbound, source string, d Dest) (net.Conn, *Conn, error) {
	q := rule.Query{Domain: d.Domain, IP: d.IP, Port: d.Port, OuterSNI: d.OuterSNI}
	res := r.Rules().Match(q)
	// An explicit outer_sni match is the user's answer for an unknown
	// domain, so the unknown_domain policy does not override it.
	if d.Transparent && d.Domain == "" && !res.ByOuterSNI {
		switch {
		case r.UnknownDomain == "reject":
			res = rule.Result{RuleIndex: -1, Target: config.TargetReject, Reason: "domain unknown (dns.unknown_domain: reject)"}
		case strings.HasPrefix(r.UnknownDomain, "egress:") && res.RuleIndex < 0:
			res = rule.Result{RuleIndex: -1, Target: strings.TrimPrefix(r.UnknownDomain, "egress:"), Reason: "domain unknown (dns.unknown_domain)"}
		}
	}
	host := d.Domain
	if host == "" {
		host = d.IP.String()
	}
	c := &Conn{Inbound: inbound, Source: source, Host: host, Port: d.Port, DomainSrc: d.DomainSrc, ECH: d.ECH, OuterSNI: d.OuterSNI,
		RuleIndex: res.RuleIndex, Reason: res.Reason, Target: res.Target}
	if d.IP.IsValid() && d.Domain != "" {
		c.DestIP = d.IP.String()
	}
	r.Tracker.add(c)

	// Egresses resolve names themselves (at the exit), so they get the
	// domain; direct and tailnet keep the address the client chose, unless
	// it was a FakeIP.
	dialHost := host
	if d.IP.IsValid() && (res.Target == config.TargetDirect || res.Target == config.TargetTailnet) {
		dialHost = d.IP.String()
	}
	port := d.Port

	var (
		out net.Conn
		err error
	)
	switch res.Target {
	case config.TargetReject:
		err = ErrRejected
	case config.TargetDirect:
		dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		out, err = r.Direct.DialContext(dctx, "tcp", net.JoinHostPort(dialHost, strconv.Itoa(int(port))))
		cancel()
	case config.TargetTailnet:
		out, c.Via, err = r.Egress.DialTailnet(ctx, dialHost, port)
	default:
		out, c.Via, err = r.Egress.Dial(ctx, res.Target, dialHost, port)
	}
	if err != nil {
		r.Tracker.finish(c, err.Error())
		return nil, c, err
	}
	return out, c, nil
}

// Relay copies data both ways between the client and the target, counting
// bytes, and records the connection as finished when both sides are done.
func (r *Router) Relay(client, target net.Conn, c *Conn) {
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error
	pipe := func(dst, src net.Conn, n interface{ Add(int64) int64 }) {
		defer wg.Done()
		_, err := io.Copy(countWriter{dst, n}, src)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			errMu.Lock()
			if firstErr == nil {
				firstErr = err
			}
			errMu.Unlock()
		}
		// Half-close so the other side sees EOF but can still send.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	wg.Add(2)
	go pipe(target, client, &c.up)
	go pipe(client, target, &c.down)
	wg.Wait()
	client.Close()
	target.Close()
	msg := ""
	if firstErr != nil {
		msg = firstErr.Error()
	}
	r.Tracker.finish(c, msg)
}

type countWriter struct {
	w io.Writer
	n interface{ Add(int64) int64 }
}

func (cw countWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.n.Add(int64(n))
	return n, err
}

// describe is used in logs.
func describe(c *Conn) string {
	s := fmt.Sprintf("%s:%d -> %s", c.Host, c.Port, c.Target)
	if c.Via != "" && c.Via != c.Target {
		s += " via " + c.Via
	}
	return s
}
