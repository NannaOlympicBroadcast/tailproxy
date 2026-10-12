//go:build windows

package bacarra

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type windowsDriver struct {
	luid winipcfg.LUID
}

func newPlatformDriver(adapter *AdapterInfo) (RouteDriver, error) {
	if adapter == nil {
		return nil, errors.New("bacarra: adapter is nil")
	}
	return &windowsDriver{luid: adapter.LUID}, nil
}

func platformDriverForState(state *RouteState) (RouteDriver, error) {
	if state == nil {
		return nil, errors.New("bacarra: state is nil")
	}
	if state.AdapterIndex > 0 {
		luid, err := winipcfg.LUIDFromIndex(uint32(state.AdapterIndex))
		if err == nil {
			return &windowsDriver{luid: luid}, nil
		}
	}
	// Fallback to discovering active adapter
	adapter, err := DiscoverAdapter(context.Background())
	if err == nil {
		return &windowsDriver{luid: adapter.LUID}, nil
	}
	return nil, fmt.Errorf("bacarra: cannot locate adapter for stale teardown: %w", err)
}


func (d *windowsDriver) AddRoute(p netip.Prefix) error {
	nextHop := NextHopForPrefix(p)
	// Metric 0 or 1 for injected subnet routes
	err := d.luid.AddRoute(p, nextHop, 0)
	if err != nil {
		if isWindowsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("winipcfg add route: %w", err)
	}
	return nil
}

func (d *windowsDriver) DeleteRoute(p netip.Prefix) error {
	nextHop := NextHopForPrefix(p)
	err := d.luid.DeleteRoute(p, nextHop)
	if err != nil {
		if isWindowsNotFound(err) {
			return nil
		}
		return fmt.Errorf("winipcfg delete route: %w", err)
	}
	return nil
}

func isWindowsAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return true
	}
	var errno windows.Errno
	if errors.As(err, &errno) && (errno == 0x1392 || errno == 183) {
		return true
	}
	return false
}

func isWindowsNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, windows.ERROR_NOT_FOUND) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return true
	}
	var errno windows.Errno
	if errors.As(err, &errno) && (errno == 1168 || errno == 2) {
		return true
	}
	return false
}
