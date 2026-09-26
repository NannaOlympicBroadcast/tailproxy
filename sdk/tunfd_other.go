//go:build !linux && !darwin && !freebsd && !openbsd

package sdk

import (
	"context"
	"errors"
)

// ServeTUNFD is not available on this system; use ServeTUN with a device.
func (e *Engine) ServeTUNFD(ctx context.Context, fd int, mtu int, o TUNOptions) error {
	return errors.New("sdk: ServeTUNFD needs Linux / Android, macOS / iOS or BSD")
}
