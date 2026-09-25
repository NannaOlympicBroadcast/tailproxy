//go:build !linux && !darwin && !windows

package tunstack

import "syscall"

// BypassControl is a no-op where TUN capture is not supported.
func BypassControl(network, address string, c syscall.RawConn) error { return nil }
