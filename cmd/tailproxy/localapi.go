package main

import (
	"context"
	"io"
	"net"
	"sync"
)

// proxyLocalAPI pipes one client connection (Unix socket or Windows named
// pipe) to the main node's in-memory LocalAPI.
func proxyLocalAPI(ctx context.Context, c net.Conn, dial func(context.Context) (net.Conn, error)) {
	defer c.Close()
	up, err := dial(ctx)
	if err != nil {
		// Answer like an HTTP server so the CLI shows a readable error.
		io.WriteString(c, "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\ntailproxy: "+err.Error()+"\n")
		return
	}
	defer up.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(up, c); closeWrite(up) }()
	go func() { defer wg.Done(); io.Copy(c, up); closeWrite(c) }()
	wg.Wait()
}

// closeWrite half-closes c, or closes it when half-close is not supported
// (byte-mode named pipes, for instance).
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok && cw.CloseWrite() == nil {
		return
	}
	c.Close()
}

// pipeSDDL is the security descriptor of the Windows LocalAPI pipe: owned
// by the user running tailproxy, and only that user and SYSTEM may open it
// ("P" blocks inherited entries). Tailscale's own pipe admits every user
// and checks each client's token; tailproxy does not, so it restricts the
// pipe itself.
func pipeSDDL(userSID string) string {
	return "O:" + userSID + "G:" + userSID + "D:P(A;;GA;;;" + userSID + ")(A;;GA;;;SY)"
}
