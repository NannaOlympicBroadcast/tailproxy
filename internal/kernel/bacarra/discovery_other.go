//go:build !windows && !linux && !darwin

package bacarra

import (
	"context"
)

func discoverAdapterPlatform(ctx context.Context) (*AdapterInfo, error) {
	return nil, ErrTailscaleNotDetected
}
