//go:build !linux && !darwin && !windows

package browserpolicy

import "errors"

func targets(Options) ([]target, error) {
	return nil, errors.New("browser policies are supported on Linux, macOS and Windows")
}

func revertOne(u undo) error { return revertFile(u) }

// DefaultStatePath is where Apply records its changes.
func DefaultStatePath() string { return "/var/db/tailproxy/browser-policy.json" }
