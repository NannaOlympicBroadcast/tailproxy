package proxy

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/fakeip"
)

// UDPListener is where diverted UDP arrives: each packet comes with the
// destination the client sent it to (capture.UDPListener on Linux).
type UDPListener interface {
	ReadFrom(b []byte) (n int, client, orig netip.AddrPort, err error)
	Close() error
}

// DefaultUDPTimeout ends a UDP flow after this long without packets
// (sing-box's default udp_timeout, DESIGN §4.4).
const DefaultUDPTimeout = 5 * time.Minute

const (
	// failedFlowTTL keeps a flow that could not be routed, so its later
	// packets are dropped instead of each being routed (and logged) again.
	failedFlowTTL = 10 * time.Second
	// maxUDPFlows bounds the flow table; new flows beyond it are dropped.
	maxUDPFlows = 8192
	// flowQueue is how many packets wait while a flow is being set up.
	flowQueue = 32
)

// TransparentUDP is the inbound for UDP diverted by TPROXY. Packets are
// grouped into flows by (client, original destination); the first packet
// of a flow is routed like a TCP connection (FakeIP name, learned name or
// address), and the flow keeps that route until it is idle for Timeout.
// No payload is inspected: QUIC SNI sniffing is not implemented, so with
// neither FakeIP nor a learned name only IP rules apply.
type TransparentUDP struct {
	Router *Router
	// Pool maps FakeIPs back to names; nil in real-IP DNS mode.
	Pool *fakeip.Pool
	// Learned maps a real address back to the name it was resolved for.
	Learned func(netip.Addr) (string, bool)
	// Reply opens the socket that talks to the client for one flow: bound
	// to orig and connected to client (capture.DialUDPReply). Replies must
	// come from orig, or the client drops them.
	Reply   func(orig, client netip.AddrPort) (net.Conn, error)
	Timeout time.Duration
	Logf    func(string, ...any)

	mu    sync.Mutex
	flows map[flowKey]*udpFlow
}

type flowKey struct{ client, orig netip.AddrPort }

type udpFlow struct {
	key  flowKey
	in   chan []byte // packets from the listener, before and after setup
	last atomic.Int64
	done chan struct{}
	once sync.Once

	// Set by setup and owned by run, which closes them; nil for a flow
	// that could not be routed.
	up, down net.Conn
	c        *Conn
}

func (t *TransparentUDP) logf(format string, args ...any) {
	if t.Logf != nil {
		t.Logf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (t *TransparentUDP) timeout() time.Duration {
	if t.Timeout > 0 {
		return t.Timeout
	}
	return DefaultUDPTimeout
}

// Serve reads packets until ctx is cancelled or ln fails. Flows end with
// ctx too.
func (t *TransparentUDP) Serve(ctx context.Context, ln UDPListener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	defer t.closeAll()
	buf := make([]byte, 65535)
	for {
		n, client, orig, err := ln.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		t.dispatch(ctx, flowKey{client, orig}, append([]byte(nil), buf[:n]...))
	}
}

// Flows returns the number of live flows (tests, status).
func (t *TransparentUDP) Flows() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.flows)
}

func (t *TransparentUDP) dispatch(ctx context.Context, k flowKey, pkt []byte) {
	t.mu.Lock()
	f := t.flows[k]
	if f == nil {
		if t.flows == nil {
			t.flows = map[flowKey]*udpFlow{}
		}
		if len(t.flows) >= maxUDPFlows {
			t.mu.Unlock()
			return
		}
		f = &udpFlow{key: k, in: make(chan []byte, flowQueue), done: make(chan struct{})}
		t.flows[k] = f
		go t.run(ctx, f)
	}
	t.mu.Unlock()
	f.last.Store(time.Now().UnixNano())
	select {
	case f.in <- pkt:
	default: // queue full: drop, as a congested link would
	}
}

// run sets the flow up, pumps it and removes it when it ends.
func (t *TransparentUDP) run(ctx context.Context, f *udpFlow) {
	defer func() {
		t.mu.Lock()
		if t.flows[f.key] == f {
			delete(t.flows, f.key)
		}
		t.mu.Unlock()
	}()
	if err := t.setup(ctx, f); err != nil {
		// Keep the flow for a while so its packets are dropped quietly.
		timer := time.NewTimer(failedFlowTTL)
		defer timer.Stop()
		for {
			select {
			case <-f.in:
			case <-timer.C:
				return
			case <-ctx.Done():
				return
			}
		}
	}

	var errOnce sync.Once
	var firstErr error
	fail := func(err error) {
		if err != nil && !errors.Is(err, net.ErrClosed) {
			errOnce.Do(func() { firstErr = err })
		}
		f.close()
	}
	touch := func() { f.last.Store(time.Now().UnixNano()) }
	var pumps sync.WaitGroup
	pumps.Add(3)
	// client -> destination: packets from the listener (the first ones,
	// and any that race the reply socket) ...
	go func() {
		defer pumps.Done()
		for {
			select {
			case p := <-f.in:
				if _, err := f.up.Write(p); err != nil {
					fail(err)
					return
				}
				f.c.up.Add(int64(len(p)))
			case <-f.done:
				return
			}
		}
	}()
	// ... and packets the kernel delivers to the connected reply socket.
	go func() {
		defer pumps.Done()
		buf := make([]byte, 65535)
		for {
			n, err := f.down.Read(buf)
			if err != nil {
				fail(err)
				return
			}
			touch()
			if _, err := f.up.Write(buf[:n]); err != nil {
				fail(err)
				return
			}
			f.c.up.Add(int64(n))
		}
	}()
	// destination -> client.
	go func() {
		defer pumps.Done()
		buf := make([]byte, 65535)
		for {
			n, err := f.up.Read(buf)
			if err != nil {
				fail(err)
				return
			}
			touch()
			if _, err := f.down.Write(buf[:n]); err != nil {
				fail(err)
				return
			}
			f.c.down.Add(int64(n))
		}
	}()

	timeout := t.timeout()
	tick := time.NewTicker(min(timeout/4, 15*time.Second))
	defer tick.Stop()
	for {
		select {
		case <-f.done:
			f.up.Close()
			f.down.Close()
			// Let the pumps see the closed sockets before reading firstErr.
			pumps.Wait()
			t.Router.Tracker.finish(f.c, errMsg(firstErr))
			return
		case <-ctx.Done():
			f.close()
		case <-tick.C:
			if time.Since(time.Unix(0, f.last.Load())) > timeout {
				f.close()
			}
		}
	}
}

func errMsg(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// close ends the flow; run closes its sockets.
func (f *udpFlow) close() { f.once.Do(func() { close(f.done) }) }

// setup routes the flow and opens both sockets. On error the flow has been
// recorded as failed.
func (t *TransparentUDP) setup(ctx context.Context, f *udpFlow) error {
	orig, client := f.key.orig, f.key.client
	ip := orig.Addr().Unmap()
	d := Dest{Port: orig.Port(), Transparent: true}
	source := client.String()
	if t.Pool != nil && t.Pool.Contains(ip) {
		name, ok := t.Pool.Lookup(ip)
		if !ok {
			c := &Conn{Inbound: "tproxy", Network: "udp", Source: source, Host: ip.String(), Port: orig.Port(), RuleIndex: -1,
				Target: "reject", Reason: "unknown FakeIP"}
			t.Router.Tracker.add(c)
			t.Router.Tracker.finish(c, "FakeIP "+ip.String()+" has no name (mapping lost or recycled); the client will re-resolve")
			return errors.New("unknown FakeIP")
		}
		d.Domain, d.DomainSrc = name, "fakeip"
	} else {
		d.IP = ip
		if t.Learned != nil {
			if name, ok := t.Learned(ip); ok {
				d.Domain, d.DomainSrc = name, "learned"
			}
		}
	}
	t.Router.Tracker.bypass.observe(d)

	up, c, err := t.Router.ConnectUDP(ctx, "tproxy", source, d)
	if err != nil {
		t.logf("tproxy udp: %s: %v", describe(c), err)
		return err
	}
	down, err := t.Reply(orig, client)
	if err != nil {
		up.Close()
		t.Router.Tracker.finish(c, "reply socket: "+err.Error())
		t.logf("tproxy udp: %s: reply socket: %v", describe(c), err)
		return err
	}
	f.up, f.down, f.c = up, down, c
	return nil
}

func (t *TransparentUDP) closeAll() {
	t.mu.Lock()
	flows := make([]*udpFlow, 0, len(t.flows))
	for _, f := range t.flows {
		flows = append(flows, f)
	}
	t.mu.Unlock()
	for _, f := range flows {
		f.close()
	}
}
