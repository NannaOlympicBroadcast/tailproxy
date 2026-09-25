package main

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
)

func TestPipeSDDL(t *testing.T) {
	sid := "S-1-5-21-1004336348-1177238915-682003330-1001"
	got := pipeSDDL(sid)
	want := "O:" + sid + "G:" + sid + "D:P(A;;GA;;;" + sid + ")(A;;GA;;;SY)"
	if got != want {
		t.Fatalf("sddl %q", got)
	}
	// Never the builtin users / everyone / authenticated users groups.
	for _, broad := range []string{";BU)", ";WD)", ";AU)", ";IU)"} {
		if strings.Contains(got, broad) {
			t.Fatalf("sddl grants %s: %s", broad, got)
		}
	}
}

func TestProxyLocalAPI(t *testing.T) {
	// Upstream echo stands in for the LocalAPI.
	client, srv := net.Pipe()
	go proxyLocalAPI(context.Background(), srv, func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go func() { io.Copy(b, b) }()
		return a, nil
	})
	client.Write([]byte("GET /localapi/v0/status"))
	buf := make([]byte, 23)
	io.ReadFull(client, buf)
	client.Close()
	if string(buf) != "GET /localapi/v0/status" {
		t.Fatalf("echo %q", buf)
	}

	// Main node not running: an HTTP 503 the CLI can show.
	c2, s2 := net.Pipe()
	go proxyLocalAPI(context.Background(), s2, func(context.Context) (net.Conn, error) { return nil, errors.New("main node not running") })
	b, _ := io.ReadAll(c2)
	if !strings.HasPrefix(string(b), "HTTP/1.1 503") || !strings.Contains(string(b), "main node not running") {
		t.Fatalf("503: %q", b)
	}
}
