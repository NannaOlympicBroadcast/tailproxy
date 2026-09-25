package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/socks5"
)

const testToken = "relay-token-0123456789abcdef"

func startRelay(t *testing.T, allowPrivate bool) (string, *Server) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Token: testToken, AllowPrivate: allowPrivate, Logf: t.Logf}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Serve(ctx, ln)
	return ln.Addr().String(), s
}

func connect(t *testing.T, relay, token, host string, port uint16) (net.Conn, error) {
	t.Helper()
	c, err := net.Dial("tcp", relay)
	if err != nil {
		t.Fatal(err)
	}
	if err := socks5.ClientConnect(c, &socks5.Credentials{User: User, Password: token}, host, port); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func TestRelayForwards(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "via relay") }))
	defer origin.Close()
	ap := netip.MustParseAddrPort(strings.TrimPrefix(origin.URL, "http://"))
	relay, s := startRelay(t, true)
	c, err := connect(t, relay, testToken, "localhost", ap.Port())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET / HTTP/1.0\r\nHost: x\r\n\r\n")
	body, _ := io.ReadAll(c)
	if !strings.HasSuffix(string(body), "via relay") {
		t.Fatalf("got %q", body)
	}
	if s.Total.Load() != 1 {
		t.Fatalf("total %d", s.Total.Load())
	}
}

func TestRelayRejectsBadTokenAndPrivateDestinations(t *testing.T) {
	relay, s := startRelay(t, false)
	if _, err := connect(t, relay, "wrong-token-0123456789", "example.com", 443); !errors.Is(err, socks5.ErrAuthFailed) {
		t.Fatalf("wrong token: %v", err)
	}
	// The server counts the failure after the client already saw it.
	for deadline := time.Now().Add(2 * time.Second); s.AuthFailures.Load() != 1; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("auth failures %d, want 1", s.AuthFailures.Load())
		}
	}
	for _, host := range []string{"127.0.0.1", "169.254.169.254", "10.1.2.3", "100.98.60.52", "::1", "localhost"} {
		_, err := connect(t, relay, testToken, host, 80)
		var re *socks5.ReplyError
		if !errors.As(err, &re) || re.Code != socks5.RepNotAllowed {
			t.Fatalf("%s: got %v, want not-allowed", host, err)
		}
	}
}

func TestAddressChecks(t *testing.T) {
	for _, a := range []string{"8.8.8.8", "160.79.104.10", "2001:4860:4860::8888"} {
		if !isPublic(netip.MustParseAddr(a)) {
			t.Errorf("%s should be public", a)
		}
	}
	for _, a := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.169.254", "100.64.196.127", "0.0.0.0", "::1", "fe80::1", "fd7a:115c:a1e0::1", "224.0.0.1"} {
		if isPublic(netip.MustParseAddr(a)) {
			t.Errorf("%s should not be public", a)
		}
	}
	for _, ok := range []string{"100.98.60.52:1081", "[fd7a:115c:a1e0::1]:1081", "127.0.0.1:1081"} {
		if err := CheckListenAddr(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:1081", "203.0.113.5:1081", ":1081", "relay.example:1081"} {
		if err := CheckListenAddr(bad); err == nil {
			t.Errorf("%s should be refused", bad)
		}
	}
}

func TestShortTokenRefused(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	if err := (&Server{Token: "short"}).Serve(context.Background(), ln); err == nil {
		t.Fatal("short token accepted")
	}
}
