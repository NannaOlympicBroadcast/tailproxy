//go:build !linux

package tunstack

import (
	"errors"
	"net/netip"
)

// Supported reports whether TUN capture can be set up on this system.
// macOS and Windows need their own route and DNS setup (not written yet).
const Supported = false

var errUnsupported = errors.New("tun: capture.mode tun is only implemented on Linux so far")

// Router is Linux-only for now.
type Router struct{}

// NewRouter is Linux-only for now.
func NewRouter(name string, addr netip.Prefix) (*Router, error) { return nil, errUnsupported }

// SetRoutes is Linux-only for now.
func (r *Router) SetRoutes(routes []netip.Prefix) error { return errUnsupported }

// Close is a no-op.
func (r *Router) Close() error { return nil }

// Cleanup is a no-op.
func Cleanup() error { return nil }
