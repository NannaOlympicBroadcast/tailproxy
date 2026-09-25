package proxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/socks5"
)

// SOCKS5 (RFC 1928) inbound: no authentication, CONNECT only. It must listen
// on a loopback address, since anyone who can reach it can use the egresses.

// SOCKS is a SOCKS5 inbound.
type SOCKS struct {
	Router *Router
	Logf   func(string, ...any)
}

// ListenSOCKS binds addr, which must be a loopback address.
func ListenSOCKS(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("capture.socks_listen: %w", err)
	}
	if ip, err := netip.ParseAddr(host); host != "localhost" && (err != nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("capture.socks_listen %s：SOCKS5 入口没有认证，只能监听回环地址（如 127.0.0.1:1080）", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("socks5: %w", err)
	}
	return ln, nil
}

// Serve accepts connections until ctx is cancelled or ln is closed.
func (s *SOCKS) Serve(ctx context.Context, ln net.Listener) error {
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

func (s *SOCKS) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (s *SOCKS) handle(ctx context.Context, client net.Conn) {
	client.SetDeadline(time.Now().Add(15 * time.Second))
	host, port, err := socks5.ServerHandshake(client, nil)
	if err != nil {
		client.Close()
		return
	}
	target, c, err := s.Router.Connect(ctx, "socks5", client.RemoteAddr().String(), host, port)
	if err != nil {
		socks5.WriteReply(client, replyCode(err), netip.AddrPort{})
		client.Close()
		s.logf("socks5: %s: %v", describe(c), err)
		return
	}
	var bound netip.AddrPort
	if ta, ok := target.LocalAddr().(*net.TCPAddr); ok {
		bound = ta.AddrPort()
	}
	if err := socks5.WriteReply(client, socks5.RepSucceeded, bound); err != nil {
		target.Close()
		client.Close()
		s.Router.Tracker.finish(c, "reply: "+err.Error())
		return
	}
	client.SetDeadline(time.Time{})
	s.Router.Relay(client, target, c)
}

func replyCode(err error) byte {
	var ne net.Error
	var dnsErr *net.DNSError
	var relayErr *socks5.ReplyError
	switch {
	case errors.Is(err, ErrRejected):
		return socks5.RepNotAllowed
	case errors.As(err, &relayErr):
		return relayErr.Code // pass a relay's answer through
	case isConnRefused(err):
		return socks5.RepConnRefused
	case errors.As(err, &dnsErr):
		return socks5.RepHostUnreachable
	case errors.As(err, &ne) && ne.Timeout():
		return socks5.RepHostUnreachable
	}
	return socks5.RepGeneralFailure
}
