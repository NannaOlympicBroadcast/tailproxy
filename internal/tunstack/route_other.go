//go:build !linux && !darwin && !windows

package tunstack

import (
	"errors"
	"net/netip"

	"github.com/tailscale/wireguard-go/tun"
)

// Supported reports whether TUN capture can be set up on this system.
const Supported = false

var errUnsupported = errors.New("tun: capture.mode tun is implemented on Linux, macOS and Windows only")

// Router is not available here.
type Router struct{}

// NewRouter is not available here.
func NewRouter(dev tun.Device, addr netip.Prefix) (*Router, error) { return nil, errUnsupported }

// SetRoutes is not available here.
func (r *Router) SetRoutes(routes []netip.Prefix) error { return errUnsupported }

// Close is a no-op.
func (r *Router) Close() error { return nil }

// Cleanup is a no-op.
func Cleanup() error { return nil }
