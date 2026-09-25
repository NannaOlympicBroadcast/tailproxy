//go:build linux

package tunstack

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/jsimonetti/rtnetlink"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
)

// Routing: routes into the device live in their own table, consulted by a
// policy rule; a rule before it sends packets carrying the bypass mark
// (tailproxy's direct dials and upstream DNS, and tsnet's own sockets) to
// the main table, so they never loop back into the device. This is how
// Tailscale keeps its own traffic out of its routes (table 52).
const (
	RouteTable     = 7894
	bypassPriority = 9894 // fwmark bypass -> main
	tablePriority  = 9895 // -> RouteTable
	bypassMark     = 0x80000
	bypassMask     = 0xff0000
)

// Router sets the device's address and routes.
type Router struct {
	name string

	mu      sync.Mutex
	applied map[netip.Prefix]bool
	dnsSet  bool
}

// Supported reports whether TUN capture can be set up on this system.
const Supported = true

// NewRouter brings the device up with addr (e.g. 172.19.0.1/30) and adds
// the policy rules. Call Close to remove them.
func NewRouter(dev tun.Device, addr netip.Prefix) (*Router, error) {
	name, err := dev.Name()
	if err != nil {
		return nil, err
	}
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("tun: netlink: %w", err)
	}
	defer conn.Close()
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("tun: %w", err)
	}
	fam := uint8(unix.AF_INET)
	if !addr.Addr().Is4() {
		fam = unix.AF_INET6
	}
	ip := net.IP(addr.Addr().AsSlice())
	if err := conn.Address.New(&rtnetlink.AddressMessage{Family: fam, PrefixLength: uint8(addr.Bits()), Scope: unix.RT_SCOPE_UNIVERSE,
		Index: uint32(ifc.Index), Attributes: &rtnetlink.AddressAttributes{Address: ip, Local: ip}}); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("tun: address %s: %w", addr, err)
	}
	if err := conn.Link.Set(&rtnetlink.LinkMessage{Family: unix.AF_UNSPEC, Index: uint32(ifc.Index), Flags: unix.IFF_UP, Change: unix.IFF_UP}); err != nil {
		return nil, fmt.Errorf("tun: link up: %w", err)
	}
	r := &Router{name: name, applied: map[netip.Prefix]bool{}}
	if err := rules(true); err != nil {
		rules(false)
		return nil, err
	}
	return r, nil
}

// SetRoutes makes routes exactly the prefixes routed into the device.
func (r *Router) SetRoutes(routes []netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("tun: netlink: %w", err)
	}
	defer conn.Close()
	ifc, err := net.InterfaceByName(r.name)
	if err != nil {
		return fmt.Errorf("tun: %w", err)
	}
	want := map[netip.Prefix]bool{}
	for _, p := range routes {
		want[p.Masked()] = true
	}
	var errs []error
	for p := range want {
		if r.applied[p] {
			continue
		}
		if err := conn.Route.Replace(routeMsg(p, ifc.Index)); err != nil {
			if !p.Addr().Is4() && noIPv6(err) {
				continue
			}
			errs = append(errs, fmt.Errorf("tun: route %s: %w", p, err))
			continue
		}
		r.applied[p] = true
	}
	for p := range r.applied {
		if !want[p] {
			conn.Route.Delete(routeMsg(p, ifc.Index))
			delete(r.applied, p)
		}
	}
	return errors.Join(errs...)
}

// Close reverts system DNS and removes the policy rules. The device's
// routes go with the device.
func (r *Router) Close() error {
	r.revertDNS()
	return rules(false)
}

func routeMsg(p netip.Prefix, ifindex int) *rtnetlink.RouteMessage {
	fam := uint8(unix.AF_INET)
	if !p.Addr().Is4() {
		fam = unix.AF_INET6
	}
	return &rtnetlink.RouteMessage{Family: fam, DstLength: uint8(p.Bits()), Table: unix.RT_TABLE_UNSPEC, Protocol: unix.RTPROT_BOOT,
		Scope: unix.RT_SCOPE_LINK, Type: unix.RTN_UNICAST,
		Attributes: rtnetlink.RouteAttributes{Dst: net.IP(p.Addr().AsSlice()), OutIface: uint32(ifindex), Table: RouteTable}}
}

// rules adds or removes, for IPv4 and IPv6:
//
//	ip rule add fwmark 0x80000/0xff0000 lookup main priority 9894
//	ip rule add lookup 7894 priority 9895
func rules(add bool) error {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("tun: netlink: %w", err)
	}
	defer conn.Close()
	var errs []error
	for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
		mark, mask, main, bp := uint32(bypassMark), uint32(bypassMask), uint32(unix.RT_TABLE_MAIN), uint32(bypassPriority)
		table, tp := uint32(RouteTable), uint32(tablePriority)
		for _, rule := range []*rtnetlink.RuleMessage{
			{Family: fam, Table: unix.RT_TABLE_UNSPEC, Action: unix.FR_ACT_TO_TBL,
				Attributes: &rtnetlink.RuleAttributes{FwMark: &mark, FwMask: &mask, Table: &main, Priority: &bp}},
			{Family: fam, Table: unix.RT_TABLE_UNSPEC, Action: unix.FR_ACT_TO_TBL,
				Attributes: &rtnetlink.RuleAttributes{Table: &table, Priority: &tp}},
		} {
			if !add {
				for i := 0; i < 8 && conn.Rule.Delete(rule) == nil; i++ { // a crash may leave duplicates
				}
				continue
			}
			if err := conn.Rule.Add(rule); err != nil && !errors.Is(err, unix.EEXIST) {
				if fam == unix.AF_INET6 && noIPv6(err) {
					break
				}
				errs = append(errs, fmt.Errorf("tun: rule (family %d, priority %d): %w", fam, *rule.Attributes.Priority, err))
			}
		}
	}
	return errors.Join(errs...)
}

func noIPv6(err error) bool {
	return errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EOPNOTSUPP)
}

// Cleanup removes rules a crashed run may have left.
func Cleanup() error { return rules(false) }
