//go:build !android

package sdk

// setPlatformProtect: only Android needs the Tailscale nodes' sockets
// protected; elsewhere Options.Protect covers the engine's own dials.
func setPlatformProtect(func(fd int) bool) {}
