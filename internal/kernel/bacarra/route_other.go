//go:build !windows && !linux && !darwin

package bacarra

import (
	"errors"
	"net/netip"
)

type otherDriver struct{}

func newPlatformDriver(adapter *AdapterInfo) (RouteDriver, error) {
	return &otherDriver{}, nil
}

func platformDriverForState(state *RouteState) (RouteDriver, error) {
	return &otherDriver{}, nil
}

func (d *otherDriver) AddRoute(p netip.Prefix) error {
	return errors.New("bacarra: routing table manipulation unsupported on this platform")
}

func (d *otherDriver) DeleteRoute(p netip.Prefix) error {
	return errors.New("bacarra: routing table manipulation unsupported on this platform")
}
