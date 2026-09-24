// Package relay is the VPS side of a relay egress (`tailproxy relay`): a
// SOCKS5 server that only listens on the machine's Tailscale address, only
// accepts tailnet sources, requires a token, and dials out from the VPS's own
// network. The client (tailproxy's main node) reaches it over the tailnet, so
// any number of egresses need only one tailnet device on the client side.
package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/socks5"
)

// DefaultPort is the relay's default TCP port on the Tailscale address.
const DefaultPort = 1081

// User is the SOCKS5 username clients send; the token is the password.
const User = "tailproxy"

var (
	tailnetV4 = netip.MustParsePrefix("100.64.0.0/10")
	tailnetV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// IsTailnet reports whether ip is a Tailscale address.
func IsTailnet(ip netip.Addr) bool {
	ip = ip.Unmap()
	return tailnetV4.Contains(ip) || tailnetV6.Contains(ip)
}

// TailscaleIPv4 finds this machine's Tailscale IPv4 address on its network
// interfaces (tailscaled must be running).
func TailscaleIPv4() (netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() && tailnetV4.Contains(p.Addr()) {
			return p.Addr(), nil
		}
	}
	return netip.Addr{}, errors.New("本机没有 Tailscale IPv4 地址（100.64.0.0/10）：请确认 tailscaled 已运行并已登录，或用 --listen 指定 Tailscale 地址")
}

// CheckListenAddr only allows Tailscale or loopback addresses: the relay
// must never be reachable from the public internet.
func CheckListenAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("--listen %s：必须是 IP 地址", addr)
	}
	if !IsTailnet(ip) && !ip.IsLoopback() {
		return fmt.Errorf("--listen %s：中继只能监听 Tailscale 地址（100.64.0.0/10、fd7a:115c:a1e0::/48）或回环地址，不能暴露到公网", addr)
	}
	return nil
}

// Server is a relay. Token must be set.
type Server struct {
	Token string
	// AllowPrivate permits destinations in loopback, private, link-local
	// (incl. cloud metadata 169.254.169.254), CGNAT/tailnet and similar
	// ranges. Off by default so a leaked token cannot reach the VPS's own
	// services or internal network.
	AllowPrivate bool
	Logf         func(string, ...any)
	Resolver     *net.Resolver // default net.DefaultResolver

	Active, Total, AuthFailures, Failures atomic.Int64
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// Serve accepts connections until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if len(s.Token) < 16 {
		return errors.New("relay: token must be at least 16 characters")
	}
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
		go s.handle(ctx, c)
	}
}

func (s *Server) handle(ctx context.Context, client net.Conn) {
	src, _ := netip.ParseAddrPort(client.RemoteAddr().String())
	if !IsTailnet(src.Addr()) && !src.Addr().Unmap().IsLoopback() {
		s.logf("relay: refused non-tailnet source %s", src)
		client.Close()
		return
	}
	s.Total.Add(1)
	client.SetDeadline(time.Now().Add(15 * time.Second))
	host, port, err := socks5.ServerHandshake(client, &socks5.Credentials{User: User, Password: s.Token})
	if err != nil {
		if errors.Is(err, socks5.ErrAuthFailed) {
			s.AuthFailures.Add(1)
			s.logf("relay: authentication failed from %s", src.Addr())
		}
		client.Close()
		return
	}
	target, code, err := s.dial(ctx, host, port)
	if err != nil {
		s.Failures.Add(1)
		socks5.WriteReply(client, code, netip.AddrPort{})
		client.Close()
		return
	}
	var bound netip.AddrPort
	if ta, ok := target.LocalAddr().(*net.TCPAddr); ok {
		bound = ta.AddrPort()
	}
	if err := socks5.WriteReply(client, socks5.RepSucceeded, bound); err != nil {
		target.Close()
		client.Close()
		return
	}
	client.SetDeadline(time.Time{})
	s.Active.Add(1)
	defer s.Active.Add(-1)
	pipe(client, target)
}

// dial resolves host on this machine (so answers match the VPS's location),
// drops disallowed addresses and connects to the first one that works.
func (s *Server) dial(ctx context.Context, host string, port uint16) (net.Conn, byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip.Unmap()}
	} else {
		r := s.Resolver
		if r == nil {
			r = net.DefaultResolver
		}
		if addrs, err = r.LookupNetIP(ctx, "ip", host); err != nil {
			return nil, socks5.RepHostUnreachable, err
		}
	}
	var allowed []netip.Addr
	for _, a := range addrs {
		if s.AllowPrivate || isPublic(a.Unmap()) {
			allowed = append(allowed, a.Unmap())
		}
	}
	if len(allowed) == 0 {
		return nil, socks5.RepNotAllowed, fmt.Errorf("destination %s is not a public address", host)
	}
	var d net.Dialer
	var lastErr error
	for _, a := range allowed {
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(a.String(), strconv.Itoa(int(port))))
		if err == nil {
			return c, 0, nil
		}
		lastErr = err
	}
	return nil, socks5.RepHostUnreachable, lastErr
}

// isPublic excludes addresses a relay should not reach on behalf of a
// remote client.
func isPublic(a netip.Addr) bool {
	return a.IsGlobalUnicast() && !a.IsPrivate() && !IsTailnet(a) &&
		!a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsMulticast() && !a.IsUnspecified()
}

// pipe copies both ways with half-close and returns when both are done.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}
