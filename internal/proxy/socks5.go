package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// SOCKS5 (RFC 1928) inbound: no authentication, CONNECT only. It must listen
// on a loopback address, since anyone who can reach it can use the egresses.

const (
	socksVer = 5

	cmdConnect = 1

	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4

	repSucceeded        = 0
	repGeneralFailure   = 1
	repNotAllowed       = 2
	repHostUnreachable  = 4
	repConnRefused      = 5
	repCmdNotSupported  = 7
	repAtypNotSupported = 8
)

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
	host, port, err := socksHandshake(client)
	if err != nil {
		client.Close()
		return
	}
	target, c, err := s.Router.Connect(ctx, "socks5", client.RemoteAddr().String(), host, port)
	if err != nil {
		socksReply(client, replyCode(err), nil)
		client.Close()
		s.logf("socks5: %s: %v", describe(c), err)
		return
	}
	var bound netip.AddrPort
	if ta, ok := target.LocalAddr().(*net.TCPAddr); ok {
		bound = ta.AddrPort()
	}
	if err := socksReply(client, repSucceeded, &bound); err != nil {
		target.Close()
		client.Close()
		s.Router.Tracker.finish(c, "reply: "+err.Error())
		return
	}
	client.SetDeadline(time.Time{})
	s.Router.Relay(client, target, c)
}

// socksHandshake performs method negotiation and reads a CONNECT request.
// Unsupported requests get an error reply before it returns an error.
func socksHandshake(rw io.ReadWriter) (host string, port uint16, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(rw, hdr[:]); err != nil {
		return
	}
	if hdr[0] != socksVer {
		return "", 0, fmt.Errorf("not SOCKS5 (version %d)", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err = io.ReadFull(rw, methods); err != nil {
		return
	}
	noAuth := false
	for _, m := range methods {
		noAuth = noAuth || m == 0
	}
	if !noAuth {
		rw.Write([]byte{socksVer, 0xFF})
		return "", 0, errors.New("client does not offer no-auth")
	}
	if _, err = rw.Write([]byte{socksVer, 0}); err != nil {
		return
	}

	var req [4]byte
	if _, err = io.ReadFull(rw, req[:]); err != nil {
		return
	}
	if req[0] != socksVer {
		return "", 0, fmt.Errorf("bad request version %d", req[0])
	}
	switch req[3] {
	case atypIPv4:
		var b [4]byte
		if _, err = io.ReadFull(rw, b[:]); err != nil {
			return
		}
		host = netip.AddrFrom4(b).String()
	case atypIPv6:
		var b [16]byte
		if _, err = io.ReadFull(rw, b[:]); err != nil {
			return
		}
		host = netip.AddrFrom16(b).Unmap().String()
	case atypDomain:
		var n [1]byte
		if _, err = io.ReadFull(rw, n[:]); err != nil {
			return
		}
		b := make([]byte, n[0])
		if _, err = io.ReadFull(rw, b); err != nil {
			return
		}
		host = string(b)
	default:
		socksReply(rw, repAtypNotSupported, nil)
		return "", 0, fmt.Errorf("address type %d not supported", req[3])
	}
	var p [2]byte
	if _, err = io.ReadFull(rw, p[:]); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(p[:])
	if req[1] != cmdConnect {
		socksReply(rw, repCmdNotSupported, nil)
		return "", 0, fmt.Errorf("command %d not supported (only CONNECT)", req[1])
	}
	if host == "" {
		socksReply(rw, repGeneralFailure, nil)
		return "", 0, errors.New("empty host")
	}
	return host, port, nil
}

func socksReply(w io.Writer, code byte, bound *netip.AddrPort) error {
	b := []byte{socksVer, code, 0}
	if bound != nil && bound.Addr().Unmap().Is4() {
		a := bound.Addr().Unmap().As4()
		b = append(b, atypIPv4)
		b = append(b, a[:]...)
	} else if bound != nil && bound.Addr().Is6() {
		a := bound.Addr().As16()
		b = append(b, atypIPv6)
		b = append(b, a[:]...)
	} else {
		b = append(b, atypIPv4, 0, 0, 0, 0)
	}
	var p [2]byte
	if bound != nil {
		binary.BigEndian.PutUint16(p[:], bound.Port())
	}
	_, err := w.Write(append(b, p[:]...))
	return err
}

func replyCode(err error) byte {
	var ne net.Error
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, ErrRejected):
		return repNotAllowed
	case errors.Is(err, syscall.ECONNREFUSED):
		return repConnRefused
	case errors.As(err, &dnsErr):
		return repHostUnreachable
	case errors.As(err, &ne) && ne.Timeout():
		return repHostUnreachable
	}
	return repGeneralFailure
}
