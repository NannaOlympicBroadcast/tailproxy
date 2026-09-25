package proxy

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/fakeip"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/sniff"
)

// DefaultSniffTimeout bounds how long a captured connection waits for the
// client's first bytes (DESIGN §4.2). Server-first protocols (SSH, SMTP)
// wait this long once, then match IP rules only.
const DefaultSniffTimeout = 300 * time.Millisecond

// Transparent is the inbound for connections diverted by TPROXY: the
// listener's LocalAddr is the original destination.
type Transparent struct {
	Router *Router
	// Pool maps FakeIPs back to names; nil in real-IP DNS mode.
	Pool         *fakeip.Pool
	SniffTimeout time.Duration
	// ListenPort is the TPROXY port; direct connections to it are refused.
	ListenPort uint16
	// BlockDomain, if set, refuses connections to listed names (public DoH
	// endpoints seen in SNI, DESIGN §4.8 L2).
	BlockDomain func(string) bool
	// Learned, if set, maps a real address back to the name it was
	// resolved for (DESIGN §4.8 L4). It is used when sniffing finds no
	// name, and in place of an ECH outer SNI.
	Learned func(netip.Addr) (string, bool)
	Logf    func(string, ...any)
}

func (t *Transparent) logf(format string, args ...any) {
	if t.Logf != nil {
		t.Logf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// Serve accepts connections until ctx is cancelled or ln is closed.
func (t *Transparent) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go t.handle(ctx, c)
	}
}

func (t *Transparent) handle(ctx context.Context, client net.Conn) {
	la, ok := client.LocalAddr().(*net.TCPAddr)
	if !ok {
		client.Close()
		return
	}
	dst := la.AddrPort()
	ip := dst.Addr().Unmap()
	if ip.IsLoopback() && dst.Port() == t.ListenPort {
		client.Close() // someone dialed the TPROXY port itself
		return
	}
	d := Dest{Port: dst.Port(), Transparent: true}
	source := client.RemoteAddr().String()

	if t.Pool != nil && t.Pool.Contains(ip) {
		name, ok := t.Pool.Lookup(ip)
		if !ok {
			// The client cached a FakeIP whose mapping is gone (recycled,
			// or the table was lost). Guessing would misroute it.
			c := &Conn{Inbound: "tproxy", Source: source, Host: ip.String(), Port: dst.Port(), RuleIndex: -1, Target: "reject",
				Reason: "unknown FakeIP"}
			t.Router.Tracker.add(c)
			t.Router.Tracker.finish(c, "FakeIP "+ip.String()+" has no name (mapping lost or recycled); the client will re-resolve")
			client.Close()
			return
		}
		d.Domain, d.DomainSrc = name, "fakeip"
	} else {
		d.IP = ip
	}

	var in net.Conn = client
	if d.Domain == "" {
		timeout := t.SniffTimeout
		if timeout == 0 {
			timeout = DefaultSniffTimeout
		}
		res, wrapped := sniff.Peek(client, timeout)
		in = wrapped
		if res.Host != "" {
			d.Domain, d.DomainSrc, d.ECH = res.Host, res.Protocol, res.ECH
		}
		// ECH's outer SNI is only the provider's public name: a name the
		// client actually resolved to this address is better.
		if (d.Domain == "" || d.ECH) && t.Learned != nil {
			if name, ok := t.Learned(ip); ok {
				d.Domain, d.DomainSrc = name, "learned"
			}
		}
	}

	t.Router.Tracker.bypass.observe(d)
	if d.Domain != "" && t.BlockDomain != nil && t.BlockDomain(d.Domain) {
		c := &Conn{Inbound: "tproxy", Source: source, Host: d.Domain, Port: d.Port, DomainSrc: d.DomainSrc, ECH: d.ECH,
			RuleIndex: -1, Target: "reject", Reason: "DoH endpoint (dns.anti_bypass.block_doh)"}
		if d.IP.IsValid() {
			c.DestIP = d.IP.String()
		}
		t.Router.Tracker.add(c)
		t.Router.Tracker.bypass.dohBlocked.Add(1)
		t.Router.Tracker.finish(c, "blocked: public DoH endpoint")
		in.Close()
		return
	}
	target, c, err := t.Router.ConnectDest(ctx, "tproxy", source, d)
	if err != nil {
		in.Close()
		t.logf("tproxy: %s: %v", describe(c), err)
		return
	}
	t.Router.Relay(in, target, c)
}
