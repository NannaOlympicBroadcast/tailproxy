package egress

import (
	"context"
	"net"
	"strconv"
	"time"
)

// tailnetPoll is how often ServeTailnet checks the main node's state.
var tailnetPoll = 2 * time.Second

// ServeTailnet listens on port (TCP) on the main node's tailnet addresses
// while the node is connected to the tailnet and hands each listener to
// serve, which must return once the listener is closed. When the node
// disconnects or restarts (logout, a new auth key) the listener is closed
// and a new one is opened on the new node. It returns when ctx ends.
// Tailscale ACLs decide which devices can reach the port.
func (m *Manager) ServeTailnet(ctx context.Context, port uint16, serve func(net.Listener)) {
	serveNode(ctx, port, func() (any, func(network, addr string) (net.Listener, error)) {
		s := m.main
		srv := s.server()
		if srv == nil || !s.tailnetUp() {
			return nil, nil
		}
		return srv, srv.Listen
	}, serve, m.logf)
}

// serveNode is ServeTailnet over node, which reports the current node (nil
// when it is not on the tailnet) and how to listen on it.
func serveNode(ctx context.Context, port uint16, node func() (any, func(network, addr string) (net.Listener, error)), serve func(net.Listener), logf func(string, ...any)) {
	var cur any
	var ln net.Listener
	lastErr := ""
	stop := func() {
		if ln != nil {
			ln.Close()
		}
		ln, cur = nil, nil
	}
	defer stop()
	tick := time.NewTicker(tailnetPoll)
	defer tick.Stop()
	for {
		id, listen := node()
		if ln != nil && id != cur {
			stop()
		}
		if ln == nil && id != nil {
			l, err := listen("tcp", ":"+strconv.Itoa(int(port)))
			if err != nil {
				if err.Error() != lastErr {
					logf("tailproxy: panel on the tailnet: listen :%d: %v", port, err)
					lastErr = err.Error()
				}
			} else {
				lastErr = ""
				ln, cur = l, id
				go serve(l)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
