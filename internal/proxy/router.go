package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
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
	Direct  net.Dialer
}

// Connect matches host:port against the rules and dials the target. The
// returned Conn is registered in the tracker; call Relay (or finish it) when
// done. On error the connection is already recorded as failed.
func (r *Router) Connect(ctx context.Context, inbound, source, host string, port uint16) (net.Conn, *Conn, error) {
	q := rule.Query{Port: port}
	if ip, err := netip.ParseAddr(host); err == nil {
		q.IP = ip.Unmap()
	} else {
		q.Domain = host
	}
	res := r.Rules().Match(q)
	c := &Conn{Inbound: inbound, Source: source, Host: host, Port: port, RuleIndex: res.RuleIndex, Reason: res.Reason, Target: res.Target}
	r.Tracker.add(c)

	var (
		out net.Conn
		err error
	)
	switch res.Target {
	case config.TargetReject:
		err = ErrRejected
	case config.TargetDirect:
		dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		out, err = r.Direct.DialContext(dctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		cancel()
	case config.TargetTailnet:
		out, c.Via, err = r.Egress.DialTailnet(ctx, host, port)
	default:
		out, c.Via, err = r.Egress.Dial(ctx, res.Target, host, port)
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
