package sniff

import (
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// clientHello captures the ClientHello crypto/tls sends for cfg.
func clientHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		tls.Client(a, cfg).Handshake()
		a.Close()
	}()
	buf := make([]byte, maxPeek)
	b.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := io.ReadAtLeast(b, buf, 5)
	b.Close()
	return buf[:n]
}

func pipeWith(t *testing.T, data []byte, keepOpen bool) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		a.Write(data)
		if !keepOpen {
			a.Close()
		}
	}()
	t.Cleanup(func() { a.Close(); b.Close() })
	return b
}

func TestTLSServerName(t *testing.T) {
	hello := clientHello(t, &tls.Config{ServerName: "Chat.OpenAI.com", InsecureSkipVerify: true})
	c := pipeWith(t, hello, true)
	start := time.Now()
	res, wrapped := Peek(c, time.Second)
	if res.Protocol != "tls" || res.Host != "chat.openai.com" || res.ECH {
		t.Fatalf("got %+v", res)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("sniffing waited %v for a complete ClientHello", d)
	}
	// Every byte is replayed.
	got := make([]byte, len(hello))
	if _, err := io.ReadFull(wrapped, got); err != nil || string(got) != string(hello) {
		t.Fatalf("replay: %v", err)
	}
}

func TestTLSWithoutSNI(t *testing.T) {
	hello := clientHello(t, &tls.Config{InsecureSkipVerify: true}) // no ServerName
	res, _ := Peek(pipeWith(t, hello, true), time.Second)
	if res.Protocol != "tls" || res.Host != "" {
		t.Fatalf("got %+v", res)
	}
}

func TestECHExtensionDetected(t *testing.T) {
	// Minimal handcrafted ClientHello: server_name "public.example" and an
	// encrypted_client_hello extension (0xfe0d).
	sni := []byte("public.example")
	sn := append([]byte{0, byte(len(sni) + 3), 0, 0, byte(len(sni))}, sni...)
	ext := append([]byte{0, 0, 0, byte(len(sn))}, sn...)
	ext = append(ext, 0xfe, 0x0d, 0, 1, 0)
	body := make([]byte, 0, 128)
	body = append(body, 3, 3)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session id
	body = append(body, 0, 2, 0x13, 0x01)    // cipher suites
	body = append(body, 1, 0)                // compression
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	res, _ := Peek(pipeWith(t, rec, true), time.Second)
	if res.Host != "public.example" || !res.ECH {
		t.Fatalf("got %+v", res)
	}
}

func TestHTTPHost(t *testing.T) {
	req := "GET /x HTTP/1.1\r\nUser-Agent: t\r\nHost: Example.COM:8080\r\n\r\n"
	start := time.Now()
	res, wrapped := Peek(pipeWith(t, []byte(req), true), time.Second)
	if res.Protocol != "http" || res.Host != "example.com" {
		t.Fatalf("got %+v", res)
	}
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Fatalf("short request waited %v", d)
	}
	got := make([]byte, len(req))
	io.ReadFull(wrapped, got)
	if string(got) != req {
		t.Fatalf("replay %q", got)
	}
}

func TestHTTPHeadersInPieces(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() {
		a.Write([]byte("POST / HTTP/1.1\r\n"))
		time.Sleep(50 * time.Millisecond)
		a.Write([]byte("Host: api.example\r\n\r\n"))
	}()
	res, _ := Peek(b, time.Second)
	if res.Host != "api.example" {
		t.Fatalf("got %+v", res)
	}
}

func TestSilentClientAndOtherProtocols(t *testing.T) {
	start := time.Now()
	res, _ := Peek(pipeWith(t, nil, true), 100*time.Millisecond)
	if res != (Result{}) || time.Since(start) > time.Second {
		t.Fatalf("silent: %+v", res)
	}
	res, wrapped := Peek(pipeWith(t, []byte("SSH-2.0-OpenSSH_9.6\r\n"), false), time.Second)
	if res != (Result{}) {
		t.Fatalf("ssh: %+v", res)
	}
	b, _ := io.ReadAll(wrapped)
	if !strings.HasPrefix(string(b), "SSH-2.0") {
		t.Fatalf("replay %q", b)
	}
	if res, _ := Peek(pipeWith(t, []byte("GET / HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n"), true), time.Second); res.Host != "" {
		t.Fatalf("IP-literal host should be dropped: %+v", res)
	}
}
