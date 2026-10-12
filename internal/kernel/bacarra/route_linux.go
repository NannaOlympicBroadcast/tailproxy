//go:build linux

package bacarra

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/jsimonetti/rtnetlink"
	"golang.org/x/sys/unix"
)

type linuxDriver struct {
	ifIndex int
}

func newPlatformDriver(adapter *AdapterInfo) (RouteDriver, error) {
	if adapter == nil {
		return nil, errors.New("bacarra: adapter is nil")
	}
	return &linuxDriver{ifIndex: adapter.Index}, nil
}

func platformDriverForState(state *RouteState) (RouteDriver, error) {
	if state == nil {
		return nil, errors.New("bacarra: state is nil")
	}
	if state.AdapterName != "" {
		ifc, err := net.InterfaceByName(state.AdapterName)
		if err == nil {
			return &linuxDriver{ifIndex: ifc.Index}, nil
		}
	}
	if state.AdapterIndex > 0 {
		ifc, err := net.InterfaceByIndex(state.AdapterIndex)
		if err == nil {
			return &linuxDriver{ifIndex: ifc.Index}, nil
		}
	}
	return nil, fmt.Errorf("bacarra: cannot resolve network interface %q / %d", state.AdapterName, state.AdapterIndex)
}

func routeMsg(p netip.Prefix, ifIndex int) *rtnetlink.RouteMessage {
	fam := uint8(unix.AF_INET)
	if !p.Addr().Is4() {
		fam = unix.AF_INET6
	}
	return &rtnetlink.RouteMessage{
		Family:    fam,
		DstLength: uint8(p.Bits()),
		Table:     unix.RT_TABLE_UNSPEC,
		Protocol:  unix.RTPROT_BOOT,
		Scope:     unix.RT_SCOPE_LINK,
		Type:      unix.RTN_UNICAST,
		Attributes: rtnetlink.RouteAttributes{
			Dst:      net.IP(p.Addr().AsSlice()),
			OutIface: uint32(ifIndex),
			Table:    unix.RT_TABLE_MAIN,
		},
	}
}

func (d *linuxDriver) AddRoute(p netip.Prefix) error {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("rtnetlink dial: %w", err)
	}
	defer conn.Close()

	msg := routeMsg(p, d.ifIndex)
	if err := conn.Route.Replace(msg); err != nil {
		if !p.Addr().Is4() && (errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EOPNOTSUPP)) {
			return nil
		}
		return fmt.Errorf("rtnetlink replace route: %w", err)
	}
	return nil
}

func (d *linuxDriver) DeleteRoute(p netip.Prefix) error {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("rtnetlink dial: %w", err)
	}
	defer conn.Close()

	msg := routeMsg(p, d.ifIndex)
	if err := conn.Route.Delete(msg); err != nil {
		if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("rtnetlink delete route: %w", err)
	}
	return nil
}
