// Package dnsserver is tailproxy's DNS front end (DESIGN §4.2, §4.6, §4.8).
// In fakeip mode, names that some rule may send to an egress get an address
// from the FakeIP pool, so the connection that follows is captured and
// carries its name; every other query is forwarded to the upstream
// resolvers unchanged, so unmatched traffic never enters tailproxy.
package dnsserver

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/fakeip"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
)

// CanaryDomain makes Firefox turn off its default DoH when it gets NXDOMAIN
// (DESIGN §4.8 L1).
const CanaryDomain = "use-application-dns.net"

const (
	typeSVCB  dnsmessage.Type = 64
	typeHTTPS dnsmessage.Type = 65
)

// Server answers DNS over UDP and TCP.
type Server struct {
	// FakeIP enables fake answers; nil means real mode (forward everything).
	Pool  *fakeip.Pool
	Rules func() *rule.Engine
	// Upstreams are ip:port resolvers queried in order.
	Upstreams []string
	Canary    bool
	// Block, if set, makes listed names (public DoH endpoints, DESIGN §4.8
	// L2) answer NXDOMAIN.
	Block func(name string) bool
	// StripECH removes the ech parameter from forwarded HTTPS/SVCB answers
	// (DESIGN §4.8 L3), so clients send the real name in the SNI.
	StripECH bool
	// Observe, if set, sees the addresses of every forwarded A/AAAA answer
	// under the name the client asked for (DESIGN §4.8 L4: learning).
	Observe func(name string, addrs []netip.Addr, ttl time.Duration)
	// TTL of fake answers, in seconds (default 10). Short, so clients ask
	// again soon after a rule change.
	TTL uint32
	// Dialer reaches the upstreams; on Linux its Control sets the bypass
	// mark so capture rules leave these queries alone.
	Dialer net.Dialer
	Logf   func(string, ...any)

	Queries, Fake, Forwarded, Failed, CanaryHits, Blocked, ECHStripped atomic.Int64
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// Listen binds UDP and TCP on addr. With port 0, the port the system picks
// for UDP may be taken (or, on Windows, reserved) for TCP; another port is
// tried then.
func Listen(addr string) (net.PacketConn, net.Listener, error) {
	_, port, _ := net.SplitHostPort(addr)
	var err error
	for attempt := 0; attempt < 10; attempt++ {
		var pc net.PacketConn
		pc, err = net.ListenPacket("udp", addr)
		if err != nil {
			return nil, nil, fmt.Errorf("dns: %w", err)
		}
		var ln net.Listener
		ln, err = net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			return pc, ln, nil
		}
		pc.Close()
		if port != "0" {
			break
		}
	}
	return nil, nil, fmt.Errorf("dns: %w", err)
}

// Serve answers queries on pc and ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, pc net.PacketConn, ln net.Listener) error {
	if len(s.Upstreams) == 0 {
		return errors.New("dns: no upstream resolver")
	}
	go func() {
		<-ctx.Done()
		pc.Close()
		ln.Close()
	}()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.serveTCP(ctx, ln)
	}()
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			if resp := s.handle(ctx, q, false); resp != nil {
				pc.WriteTo(resp, from)
			}
		}()
	}
}

func (s *Server) serveTCP(ctx context.Context, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		go s.ServeConn(ctx, c)
	}
}

// ServeConn answers DNS over one TCP connection (length-prefixed messages)
// until the client closes it or is idle for 30 seconds; it closes c.
func (s *Server) ServeConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	for {
		c.SetDeadline(time.Now().Add(30 * time.Second))
		q, err := readTCPMsg(r)
		if err != nil {
			return
		}
		resp := s.handle(ctx, q, true)
		if resp == nil || writeTCPMsg(c, resp) != nil {
			return
		}
	}
}

// Answer returns the response to one DNS query received over UDP, or nil
// to drop it. It is Serve's per-packet path, for front ends that deliver
// packets themselves (the TUN stack).
func (s *Server) Answer(ctx context.Context, q []byte) []byte { return s.handle(ctx, q, false) }

func readTCPMsg(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err := io.ReadFull(r, b)
	return b, err
}

func writeTCPMsg(w io.Writer, b []byte) error {
	_, err := w.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...))
	return err
}

// handle returns the response to one query, or nil to drop it.
func (s *Server) handle(ctx context.Context, q []byte, tcp bool) []byte {
	s.Queries.Add(1)
	var p dnsmessage.Parser
	hdr, err := p.Start(q)
	if err != nil || hdr.Response {
		return nil
	}
	question, err := p.Question()
	if err != nil {
		return reply(hdr, nil, dnsmessage.RCodeFormatError, nil)
	}
	name := strings.TrimSuffix(strings.ToLower(question.Name.String()), ".")

	if s.Canary && name == CanaryDomain {
		s.CanaryHits.Add(1)
		return reply(hdr, &question, dnsmessage.RCodeNameError, nil)
	}
	if s.Block != nil && s.Block(name) {
		s.Blocked.Add(1)
		return reply(hdr, &question, dnsmessage.RCodeNameError, nil)
	}
	if s.Pool != nil && question.Class == dnsmessage.ClassINET && s.Rules != nil && s.Rules().DomainMayRoute(name) {
		switch question.Type {
		case dnsmessage.TypeA, dnsmessage.TypeAAAA, typeHTTPS, typeSVCB:
			s.Fake.Add(1)
			return reply(hdr, &question, dnsmessage.RCodeSuccess, s.fakeAnswer(question, name))
		}
	}
	resp, err := s.forward(ctx, q, tcp)
	if err != nil {
		s.Failed.Add(1)
		s.logf("dns: %s %v: %v", name, question.Type, err)
		return reply(hdr, &question, dnsmessage.RCodeServerFailure, nil)
	}
	s.Forwarded.Add(1)
	switch question.Type {
	case typeHTTPS, typeSVCB:
		if s.StripECH {
			if out, ok := stripECH(resp); ok {
				s.ECHStripped.Add(1)
				resp = out
			}
		}
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		if s.Observe != nil {
			if addrs, ttl := answerAddrs(resp); len(addrs) > 0 {
				s.Observe(name, addrs, ttl)
			}
		}
	}
	return resp
}

// stripECH removes the ech SvcParam from HTTPS/SVCB answers; ok is false
// when there was none (resp is then returned unchanged by the caller).
func stripECH(resp []byte) ([]byte, bool) {
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		return nil, false
	}
	changed := false
	for i := range m.Answers {
		switch b := m.Answers[i].Body.(type) {
		case *dnsmessage.HTTPSResource:
			changed = b.DeleteParam(dnsmessage.SVCParamECH) || changed
		case *dnsmessage.SVCBResource:
			changed = b.DeleteParam(dnsmessage.SVCParamECH) || changed
		}
	}
	if !changed {
		return nil, false
	}
	out, err := m.Pack()
	if err != nil {
		return nil, false
	}
	return out, true
}

// answerAddrs returns the A/AAAA addresses in resp and their smallest TTL.
func answerAddrs(resp []byte) ([]netip.Addr, time.Duration) {
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		return nil, 0
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, 0
	}
	var out []netip.Addr
	ttl := uint32(0)
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return out, time.Duration(ttl) * time.Second
			}
			out = append(out, netip.AddrFrom4(r.A))
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return out, time.Duration(ttl) * time.Second
			}
			out = append(out, netip.AddrFrom16(r.AAAA))
		default:
			if p.SkipAnswer() != nil {
				return out, time.Duration(ttl) * time.Second
			}
			continue
		}
		if ttl == 0 || h.TTL < ttl {
			ttl = h.TTL
		}
	}
	return out, time.Duration(ttl) * time.Second
}

// fakeAnswer is the answer section for a name that goes through tailproxy.
// HTTPS/SVCB get no records: their ipv4hint/ipv6hint would give clients
// the real address and let them bypass the FakeIP (DESIGN §4.7).
func (s *Server) fakeAnswer(q dnsmessage.Question, name string) []dnsmessage.Resource {
	ttl := s.TTL
	if ttl == 0 {
		ttl = 10
	}
	h := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: ttl}
	switch q.Type {
	case dnsmessage.TypeA:
		return []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AResource{A: s.Pool.V4(name).As4()}}}
	case dnsmessage.TypeAAAA:
		if a, ok := s.Pool.V6(name); ok {
			return []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AAAAResource{AAAA: a.As16()}}}
		}
	}
	return nil
}

func reply(q dnsmessage.Header, question *dnsmessage.Question, rcode dnsmessage.RCode, answers []dnsmessage.Resource) []byte {
	m := dnsmessage.Message{
		Header: dnsmessage.Header{ID: q.ID, Response: true, OpCode: q.OpCode, RecursionDesired: q.RecursionDesired,
			RecursionAvailable: true, RCode: rcode},
		Answers: answers,
	}
	if question != nil {
		m.Questions = []dnsmessage.Question{*question}
	}
	b, err := m.Pack()
	if err != nil {
		return nil
	}
	return b
}

// forward sends q to the upstreams in order and returns the first answer.
// UDP answers that come back truncated are retried over TCP.
func (s *Server) forward(ctx context.Context, q []byte, tcp bool) ([]byte, error) {
	var errs []error
	for _, up := range s.Upstreams {
		resp, err := s.exchange(ctx, up, q, tcp)
		if err == nil && !tcp && len(resp) > 2 && resp[2]&0x02 != 0 { // TC bit
			resp, err = s.exchange(ctx, up, q, true)
		}
		if err == nil {
			return resp, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", up, err))
	}
	return nil, errors.Join(errs...)
}

func (s *Server) exchange(ctx context.Context, upstream string, q []byte, tcp bool) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	network := "udp"
	if tcp {
		network = "tcp"
	}
	c, err := s.Dialer.DialContext(ctx, network, upstream)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if tcp {
		if err := writeTCPMsg(c, q); err != nil {
			return nil, err
		}
		return readTCPMsg(c)
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= 2 && n > 12 && buf[0] == q[0] && buf[1] == q[1] {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

// ParseUpstreams turns dns.direct_upstream into ip:port addresses: "system"
// (or empty) reads the system resolvers, otherwise a comma- or
// space-separated list of IP[:port]. Loopback resolvers are dropped for
// "system": they are usually a local stub (systemd-resolved, dnsmasq) whose
// own upstream queries capture sends back here, which would loop.
func ParseUpstreams(spec string) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "system" {
		ups := systemResolvers()
		if len(ups) == 0 {
			return nil, errors.New("dns.direct_upstream: system: no non-loopback resolver found in /run/systemd/resolve/resolv.conf or /etc/resolv.conf; set it explicitly, e.g. \"223.5.5.5, 119.29.29.29\"")
		}
		return ups, nil
	}
	var out []string
	for _, f := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' }) {
		if ap, err := netip.ParseAddrPort(f); err == nil {
			out = append(out, ap.String())
			continue
		}
		ip, err := netip.ParseAddr(strings.Trim(f, "[]"))
		if err != nil {
			return nil, fmt.Errorf("dns.direct_upstream: %q is not an IP or IP:port", f)
		}
		out = append(out, netip.AddrPortFrom(ip, 53).String())
	}
	if len(out) == 0 {
		return nil, errors.New("dns.direct_upstream is empty")
	}
	return out, nil
}

// resolvConfPaths lists where system resolvers are read from; systemd's
// file names the real upstreams behind the 127.0.0.53 stub.
var resolvConfPaths = []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"}

func systemResolvers() []string {
	for _, p := range resolvConfPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var out []string
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 || f[0] != "nameserver" {
				continue
			}
			ip, err := netip.ParseAddr(f[1]) // keeps a zone (fe80::1%eth0)
			if err != nil || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			out = append(out, netip.AddrPortFrom(ip, 53).String())
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

// Resolver returns a resolver that queries upstreams directly with dialer,
// for dialing direct targets by name without going through the FakeIP
// front end.
func Resolver(upstreams []string, dialer *net.Dialer) *net.Resolver {
	var i atomic.Uint32
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			up := upstreams[int(i.Add(1))%len(upstreams)]
			return dialer.DialContext(ctx, network, up)
		},
	}
}
