//go:build !linux

package capture

import (
	"errors"
	"net"
	"syscall"
)

// Supported reports whether transparent capture is available here.
const Supported = false

var errUnsupported = errors.New("capture: transparent capture (TPROXY) is only implemented on Linux; use capture.socks_listen")

// BypassControl is a no-op outside Linux.
func BypassControl(network, address string, c syscall.RawConn) error { return nil }

// ListenTProxy is Linux-only.
func ListenTProxy(port uint16) ([]net.Listener, error) { return nil, errUnsupported }

// Setup is Linux-only.
func Setup(o Options) error { return errUnsupported }

// Teardown is a no-op outside Linux.
func Teardown() error { return nil }
