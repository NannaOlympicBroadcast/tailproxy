package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/socks5"
)

// SOCKS5 UDP ASSOCIATE (RFC 1928 §7): the client gets a UDP port on the
// listener's (loopback) address and sends datagrams with a SOCKS header
// naming each destination. Every destination is a flow routed like a
// CONNECT (Router.ConnectUDP); replies come back with the destination in
// the header. The association ends with its TCP connection.

// maxAssocFlows bounds the destinations of one association.
const maxAssocFlows = 512

type socksAssoc struct {
	s      *SOCKS
	pc     *net.UDPConn
	source string
	// Datagrams are accepted from clientIP only; the first one fixes the
	// port unless the request named it.
	clientIP netip.Addr
	client   atomic.Pointer[netip.AddrPort]

	mu    sync.Mutex
	flows map[string]*socksFlow
}

type socksFlow struct {
	host string
	port uint16
	// Set once by flow (under socksAssoc.mu); nil up: routing failed, and
	// datagrams are dropped until the flow expires.
	up   net.Conn
	c    *Conn
	last atomic.Int64
	once sync.Once
	fail time.Time
}

func (s *SOCKS) udpAssociate(ctx context.Context, client net.Conn, req socks5.Request) {
	defer client.Close()
	local, _ := client.LocalAddr().(*net.TCPAddr)
	remote, _ := client.RemoteAddr().(*net.TCPAddr)
	if local == nil || remote == nil {
		socks5.WriteReply(client, socks5.RepGeneralFailure, netip.AddrPort{})
		return
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP})
	if err != nil {
		socks5.WriteReply(client, socks5.RepGeneralFailure, netip.AddrPort{})
		s.logf("socks5: udp associate: %v", err)
		return
	}
	defer pc.Close()
	bound := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := socks5.WriteReply(client, socks5.RepSucceeded, bound); err != nil {
		return
	}
	client.SetDeadline(time.Time{})

	a := &socksAssoc{s: s, pc: pc, source: remote.String(), clientIP: remote.AddrPort().Addr().Unmap(), flows: map[string]*socksFlow{}}
	if ip, err := netip.ParseAddr(req.Host); err == nil && req.Port != 0 && !ip.IsUnspecified() {
		ap := netip.AddrPortFrom(ip.Unmap(), req.Port)
		a.client.Store(&ap)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The association lasts as long as the TCP connection (§7).
	go func() {
		io.Copy(io.Discard, client)
		cancel()
	}()
	go func() {
		<-ctx.Done()
		pc.Close()
		client.Close()
	}()
	go a.expire(ctx)
	a.serve(ctx)
	a.closeAll()
}

// serve reads client datagrams until the socket is closed.
func (a *socksAssoc) serve(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		n, from, err := a.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if from.Addr() != a.clientIP {
			continue // not the client that asked for the association
		}
		if want := a.client.Load(); want == nil {
			a.client.Store(&from)
		} else if *want != from {
			continue
		}
		host, port, data, err := socks5.ParseUDP(buf[:n])
		if err != nil {
			continue // fragments and malformed datagrams are dropped
		}
		f := a.flow(ctx, host, port)
		if f == nil || f.up == nil {
			continue
		}
		f.last.Store(time.Now().UnixNano())
		if _, err := f.up.Write(data); err != nil {
			a.finish(f, err)
			continue
		}
		f.c.up.Add(int64(len(data)))
	}
}

// flow returns the flow to host:port, routing it on first use.
func (a *socksAssoc) flow(ctx context.Context, host string, port uint16) *socksFlow {
	key := net.JoinHostPort(host, strconv.Itoa(int(port)))
	a.mu.Lock()
	f := a.flows[key]
	if f != nil || len(a.flows) >= maxAssocFlows {
		a.mu.Unlock()
		return f
	}
	f = &socksFlow{host: host, port: port}
	a.flows[key] = f
	a.mu.Unlock()

	d := Dest{Port: port}
	if ip, err := netip.ParseAddr(host); err == nil {
		d.IP = ip.Unmap()
	} else {
		d.Domain, d.DomainSrc = host, "socks"
	}
	up, c, err := a.s.Router.ConnectUDP(ctx, "socks5", a.source, d)
	f.last.Store(time.Now().UnixNano())
	a.mu.Lock()
	if err != nil {
		f.fail = time.Now()
	} else {
		f.up, f.c = up, c
	}
	a.mu.Unlock()
	if err != nil {
		a.s.logf("socks5 udp: %s: %v", describe(c), err)
		return f
	}
	go a.replies(f)
	return f
}

// replies copies the destination's datagrams back to the client.
func (a *socksAssoc) replies(f *socksFlow) {
	buf := make([]byte, 65535)
	for {
		n, err := f.up.Read(buf)
		if err != nil {
			a.finish(f, err)
			return
		}
		to := a.client.Load()
		if to == nil {
			continue
		}
		f.last.Store(time.Now().UnixNano())
		b := socks5.AppendUDPHeader(make([]byte, 0, 262+n), f.host, f.port)
		b = append(b, buf[:n]...)
		if _, err := a.pc.WriteToUDPAddrPort(b, *to); err != nil {
			a.finish(f, err)
			return
		}
		f.c.down.Add(int64(n))
	}
}

// finish ends a flow once; it is removed so the next datagram routes anew.
func (a *socksAssoc) finish(f *socksFlow, err error) {
	f.once.Do(func() {
		a.mu.Lock()
		for k, g := range a.flows {
			if g == f {
				delete(a.flows, k)
			}
		}
		up := f.up
		a.mu.Unlock()
		if up == nil {
			return
		}
		f.up.Close()
		if err != nil && (errors.Is(err, net.ErrClosed) || errors.Is(err, errIdle)) {
			err = nil
		}
		a.s.Router.Tracker.finish(f.c, errMsg(err))
	})
}

var errIdle = errors.New("idle")

// expire ends flows idle for DefaultUDPTimeout and forgets failed ones
// after failedFlowTTL.
func (a *socksAssoc) expire(ctx context.Context) {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			a.mu.Lock()
			var ended []*socksFlow
			for _, f := range a.flows {
				if f.up == nil && !f.fail.IsZero() && now.Sub(f.fail) > failedFlowTTL {
					ended = append(ended, f)
				} else if f.up != nil && now.Sub(time.Unix(0, f.last.Load())) > DefaultUDPTimeout {
					ended = append(ended, f)
				}
			}
			a.mu.Unlock()
			for _, f := range ended {
				a.finish(f, errIdle)
			}
		}
	}
}

func (a *socksAssoc) closeAll() {
	a.mu.Lock()
	flows := make([]*socksFlow, 0, len(a.flows))
	for _, f := range a.flows {
		flows = append(flows, f)
	}
	a.mu.Unlock()
	for _, f := range flows {
		a.finish(f, nil)
	}
}
