package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/socks5"
)

// udpAssociate does the SOCKS5 handshake and UDP ASSOCIATE on a new
// control connection and returns it with the relay address.
func udpAssociate(t *testing.T, socksAddr string) (net.Conn, netip.AddrPort) {
	t.Helper()
	c, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte{5, 1, 0})
	m := make([]byte, 2)
	if _, err := io.ReadFull(c, m); err != nil || m[1] != 0 {
		t.Fatalf("method reply %v %v", m, err)
	}
	c.Write([]byte{5, socks5.CmdUDPAssociate, 0, 1, 0, 0, 0, 0, 0, 0})
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil || rep[1] != socks5.RepSucceeded || rep[3] != 1 {
		t.Fatalf("UDP ASSOCIATE reply %v %v", rep, err)
	}
	c.SetDeadline(time.Time{})
	relay := netip.AddrPortFrom(netip.AddrFrom4([4]byte(rep[4:8])), uint16(rep[8])<<8|uint16(rep[9]))
	return c, relay
}

func TestSOCKSUDPAssociate(t *testing.T) {
	port := udpEcho(t).Port()
	// Names resolve to 127.0.0.1 only: "localhost" is ::1 first on some
	// systems, and a UDP dial takes the first address.
	addr, tr := startSOCKSWith(t, `
rules:
  - {domain_keyword: [blocked], egress: reject}
  - {final: direct}
`, func(r *Router) { r.Direct.Resolver = stubResolver(t, netip.MustParseAddr("127.0.0.1")) })
	ctrl, relay := udpAssociate(t, addr)
	if !relay.Addr().IsLoopback() {
		t.Fatalf("relay address %s is not the listener's loopback address", relay)
	}
	uc, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(relay))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()

	exchange := func(host, payload string) (string, error) {
		uc.Write(append(socks5.AppendUDPHeader(nil, host, port), payload...))
		uc.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 2048)
		n, err := uc.Read(buf)
		if err != nil {
			return "", err
		}
		h, p, data, err := socks5.ParseUDP(buf[:n])
		if err != nil {
			return "", err
		}
		if h != host || p != port {
			t.Errorf("reply header %s:%d, want %s:%d", h, p, host, port)
		}
		return string(data), nil
	}
	// By address, twice over one flow; then by name (a second flow).
	for _, msg := range []string{"one", "two"} {
		if got, err := exchange("127.0.0.1", msg); err != nil || got != "echo:"+msg {
			t.Fatalf("via 127.0.0.1: %q %v", got, err)
		}
	}
	if got, err := exchange("echo.test", "three"); err != nil || got != "echo:three" {
		t.Fatalf("via echo.test: %q %v", got, err)
	}
	// A rejected destination gets nothing back.
	if got, err := exchange("blocked.example", "x"); err == nil {
		t.Fatalf("rejected destination answered %q", got)
	}
	// A fragment (FRAG != 0) is dropped.
	frag := socks5.AppendUDPHeader(nil, "127.0.0.1", port)
	frag[2] = 1
	uc.Write(append(frag, "frag"...))
	uc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := uc.Read(make([]byte, 64)); err == nil {
		t.Fatalf("fragment answered (%d bytes)", n)
	}

	// Closing the control connection ends the association and its flows.
	ctrl.Close()
	s := waitFinished(t, tr, 3)
	var udp, rejected int
	for _, c := range s.Recent {
		if c.Network != "udp" || c.Inbound != "socks5" {
			t.Errorf("record %+v", c)
		}
		udp++
		if c.Target == "reject" {
			rejected++
		}
		if c.Target == "direct" && c.Up == 0 {
			t.Errorf("no upload counted: %+v", c)
		}
	}
	if udp != 3 || rejected != 1 {
		t.Fatalf("records: %+v", s.Recent)
	}
	uc.Write(append(socks5.AppendUDPHeader(nil, "127.0.0.1", port), "late"...))
	uc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := uc.Read(make([]byte, 64)); err == nil {
		t.Fatal("relay still answers after the control connection closed")
	}
}

// stubResolver answers every A query with ip and AAAA with no records.
func stubResolver(t *testing.T, ip netip.Addr) *net.Resolver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
			b.StartQuestions()
			b.Question(q)
			b.StartAnswers()
			if q.Type == dnsmessage.TypeA {
				b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: ip.As4()})
			}
			msg, _ := b.Finish()
			pc.WriteTo(msg, from)
		}
	}()
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", pc.LocalAddr().String())
	}}
}

// Datagrams from another address than the client's are ignored.
func TestSOCKSUDPOtherSender(t *testing.T) {
	port := udpEcho(t).Port()
	addr, _ := startSOCKS(t, "rules: [{final: direct}]\n")
	ctrl, relay := udpAssociate(t, addr)
	defer ctrl.Close()
	first, _ := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(relay))
	defer first.Close()
	hdr := socks5.AppendUDPHeader(nil, "127.0.0.1", port)
	first.Write(append(bytes.Clone(hdr), "a"...))
	first.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := first.Read(make([]byte, 64)); err != nil {
		t.Fatalf("client: %v", err)
	}
	// Same IP, other port: the association is bound to the first sender.
	other, _ := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(relay))
	defer other.Close()
	other.Write(append(bytes.Clone(hdr), "b"...))
	other.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := other.Read(make([]byte, 64)); err == nil {
		t.Fatal("datagram from another port was relayed")
	}
}

func TestParseUDPHeader(t *testing.T) {
	for _, host := range []string{"192.0.2.1", "2001:db8::1", "example.com"} {
		b := append(socks5.AppendUDPHeader(nil, host, 443), "data"...)
		h, p, d, err := socks5.ParseUDP(b)
		if err != nil || h != host || p != 443 || string(d) != "data" {
			t.Errorf("%s: %s %d %q %v", host, h, p, d, err)
		}
	}
	full := socks5.AppendUDPHeader(nil, "example.com", 443)
	for i := 0; i < len(full); i++ {
		if _, _, _, err := socks5.ParseUDP(full[:i]); err == nil {
			t.Errorf("truncated header (%d bytes) accepted", i)
		}
	}
	bad := socks5.AppendUDPHeader(nil, "192.0.2.1", 1)
	bad[3] = 9
	if _, _, _, err := socks5.ParseUDP(bad); err == nil || !strings.Contains(err.Error(), "address type") {
		t.Errorf("bad atyp: %v", err)
	}
}
