//go:build darwin

package bacarra

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
)

type darwinDriver struct {
	ifName string
}

func newPlatformDriver(adapter *AdapterInfo) (RouteDriver, error) {
	if adapter == nil {
		return nil, errors.New("bacarra: adapter is nil")
	}
	return &darwinDriver{ifName: adapter.Name}, nil
}

func platformDriverForState(state *RouteState) (RouteDriver, error) {
	if state == nil {
		return nil, errors.New("bacarra: state is nil")
	}
	if state.AdapterName == "" {
		return nil, errors.New("bacarra: state has empty adapter name")
	}
	return &darwinDriver{ifName: state.AdapterName}, nil
}

func (d *darwinDriver) AddRoute(p netip.Prefix) error {
	fam := "-inet"
	if !p.Addr().Is4() {
		fam = "-inet6"
	}

	// Idempotency: quiet delete before add to clear any stale entries
	_ = exec.Command("/sbin/route", "-q", "-n", "delete", fam, p.String(), "-interface", d.ifName).Run()

	cmd := exec.Command("/sbin/route", "-q", "-n", "add", fam, p.String(), "-interface", d.ifName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("route add %s: %w: %s", p, err, string(out))
	}
	return nil
}

func (d *darwinDriver) DeleteRoute(p netip.Prefix) error {
	fam := "-inet"
	if !p.Addr().Is4() {
		fam = "-inet6"
	}

	// Idempotency: -q suppresses non-existent route errors
	_ = exec.Command("/sbin/route", "-q", "-n", "delete", fam, p.String(), "-interface", d.ifName).Run()
	return nil
}
