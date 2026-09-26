package proxy

import (
	"errors"
	"io"
	"net"
	"sync"
)

// Track wraps target, a connection from Connect / ConnectDest / ConnectUDP,
// for callers that use it directly instead of Relay (the SDK's Dial): its
// bytes are counted and c is recorded as finished when it is closed.
func (r *Router) Track(target net.Conn, c *Conn) net.Conn {
	return &trackedConn{Conn: target, r: r, c: c}
}

type trackedConn struct {
	net.Conn
	r    *Router
	c    *Conn
	once sync.Once
	mu   sync.Mutex
	err  error
}

func (t *trackedConn) note(err error) {
	var ne net.Error
	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) && !(errors.As(err, &ne) && ne.Timeout()) {
		t.mu.Lock()
		if t.err == nil {
			t.err = err
		}
		t.mu.Unlock()
	}
}

func (t *trackedConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	t.c.down.Add(int64(n))
	t.note(err)
	return n, err
}

func (t *trackedConn) Write(p []byte) (int, error) {
	n, err := t.Conn.Write(p)
	t.c.up.Add(int64(n))
	t.note(err)
	return n, err
}

func (t *trackedConn) Close() error {
	err := t.Conn.Close()
	t.once.Do(func() {
		t.mu.Lock()
		msg := errMsg(t.err)
		t.mu.Unlock()
		t.r.Tracker.finish(t.c, msg)
	})
	return err
}
