package egress

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestServeNode(t *testing.T) {
	old := tailnetPoll
	tailnetPoll = 10 * time.Millisecond
	defer func() { tailnetPoll = old }()

	type node struct{ name string }
	var mu sync.Mutex
	var cur *node
	failListen := false
	var addrs []string
	node1, node2 := &node{"one"}, &node{"two"}
	set := func(n *node, fail bool) {
		mu.Lock()
		cur, failListen = n, fail
		mu.Unlock()
	}
	nodeFn := func() (any, func(string, string) (net.Listener, error)) {
		mu.Lock()
		defer mu.Unlock()
		if cur == nil {
			return nil, nil
		}
		n, fail := cur, failListen
		return n, func(network, addr string) (net.Listener, error) {
			if fail {
				return nil, errors.New("port in use")
			}
			mu.Lock()
			addrs = append(addrs, n.name+addr)
			mu.Unlock()
			return net.Listen("tcp", "127.0.0.1:0")
		}
	}
	lns := make(chan net.Listener, 8)
	var open atomic.Int32
	serve := func(ln net.Listener) {
		open.Add(1)
		lns <- ln
		for {
			c, err := ln.Accept()
			if err != nil {
				open.Add(-1)
				return
			}
			c.Close()
		}
	}
	var logs atomic.Int32
	logf := func(string, ...any) { logs.Add(1) }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { serveNode(ctx, 7708, nodeFn, serve, logf); close(done) }()

	wait := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	// Not on the tailnet: nothing is served.
	time.Sleep(50 * time.Millisecond)
	if open.Load() != 0 {
		t.Fatal("served before the node was up")
	}
	// Up: one listener on the configured port.
	set(node1, false)
	ln1 := <-lns
	wait("serving on node one", func() bool { return open.Load() == 1 })
	// Down: the listener is closed.
	set(nil, false)
	wait("listener closed", func() bool { return open.Load() == 0 })
	if _, err := net.Dial("tcp", ln1.Addr().String()); err == nil {
		t.Fatal("closed listener still accepts")
	}
	// A restarted node: its listen fails first (logged once), then works.
	set(node2, true)
	time.Sleep(60 * time.Millisecond)
	if logs.Load() != 1 {
		t.Fatalf("listen error logged %d times, want once", logs.Load())
	}
	set(node2, false)
	<-lns
	wait("serving on node two", func() bool { return open.Load() == 1 })
	// Switching nodes directly closes the old listener first.
	set(node1, false)
	<-lns
	wait("one listener after switching", func() bool { return open.Load() == 1 })

	cancel()
	<-done
	wait("closed on ctx end", func() bool { return open.Load() == 0 })
	mu.Lock()
	defer mu.Unlock()
	if len(addrs) != 3 || addrs[0] != "one:7708" || addrs[1] != "two:7708" || addrs[2] != "one:7708" {
		t.Fatalf("listens: %v", addrs)
	}
}
