//go:build linux

package capture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"

	"github.com/jsimonetti/rtnetlink"
	"golang.org/x/sys/unix"
)

// Supported reports whether transparent capture is available here.
const Supported = true

// BypassControl marks a socket so capture leaves it alone. Use it as the
// Control of dialers for direct traffic and upstream DNS.
func BypassControl(network, address string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, BypassMark)
	}); err != nil {
		return err
	}
	return serr
}

// ListenTProxy listens for TPROXY-diverted TCP on 127.0.0.1:port and
// [::1]:port (IP_TRANSPARENT). Accepted connections' LocalAddr is the
// original destination.
func ListenTProxy(port uint16) ([]net.Listener, error) {
	var out []net.Listener
	for _, host := range []string{"127.0.0.1", "::1"} {
		v6 := host == "::1"
		lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			err := c.Control(func(fd uintptr) {
				if v6 {
					serr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
				} else {
					serr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
				}
			})
			if err != nil {
				return err
			}
			return serr
		}}
		ln, err := lc.Listen(context.Background(), "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
		if err != nil {
			if v6 && len(out) > 0 && (errors.Is(err, unix.EADDRNOTAVAIL) || errors.Is(err, unix.EAFNOSUPPORT)) {
				continue // IPv6 disabled or no ::1: IPv4 only
			}
			for _, l := range out {
				l.Close()
			}
			if errors.Is(err, unix.EPERM) {
				return nil, fmt.Errorf("capture: TPROXY needs root (CAP_NET_ADMIN): %w", err)
			}
			return nil, fmt.Errorf("capture: listen %s: %w", host, err)
		}
		out = append(out, ln)
	}
	return out, nil
}

// nftBinary is overridable for tests.
var nftBinary = "nft"

func runNft(script string) error {
	cmd := exec.Command(nftBinary, "-f", "-")
	cmd.Stdin = bytes.NewReader([]byte(script))
	out, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return fmt.Errorf("capture: nft not found; install nftables (OpenWrt: opkg install nftables / kmod-nft-tproxy)")
		}
		return fmt.Errorf("capture: nft: %v: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// Setup applies the ruleset and the policy routing. Call Teardown when
// done, also after a failed Setup.
func Setup(o Options) error {
	if os.Geteuid() != 0 {
		return errors.New("capture: transparent capture needs root")
	}
	script, err := Ruleset(o)
	if err != nil {
		return err
	}
	if err := routing(true); err != nil {
		return err
	}
	unreachable := o.FakeIP
	if o.UDP {
		unreachable = nil // UDP to FakeIPs is proxied
	}
	if err := fakeUDPUnreachable(unreachable); err != nil {
		return err
	}
	return runNft(script)
}

// Teardown removes the table and the policy routing; missing pieces are
// not an error.
func Teardown() error {
	return errors.Join(runNft(TeardownScript), routing(false), fakeUDPUnreachable(nil))
}

// UDPRulePriority is the priority of the "UDP to FakeIP: unreachable"
// rules, just before the TPROXY rule.
const UDPRulePriority = RulePriority - 1

// fakeUDPUnreachable replaces the policy rules that make UDP to the FakeIP
// pools unreachable: only TCP is proxied, and an immediate error makes
// clients (QUIC) fall back to TCP instead of timing out. Local senders get
// the error from send(); forwarded LAN traffic gets ICMP unreachable.
func fakeUDPUnreachable(pools []netip.Prefix) error {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("capture: netlink: %w", err)
	}
	defer conn.Close()
	// Remove ours: identified by priority and action.
	if rules, err := conn.Rule.List(); err == nil {
		for _, r := range rules {
			if r.Action == unix.FR_ACT_UNREACHABLE && r.Attributes != nil && r.Attributes.Priority != nil && *r.Attributes.Priority == UDPRulePriority {
				r := r
				conn.Rule.Delete(&r)
			}
		}
	}
	var errs []error
	for _, p := range pools {
		p = p.Masked()
		fam, dst := uint8(unix.AF_INET), net.IP(p.Addr().AsSlice())
		if p.Addr().Is6() {
			fam = unix.AF_INET6
		}
		prio, proto := uint32(UDPRulePriority), uint8(unix.IPPROTO_UDP)
		err := conn.Rule.Add(&rtnetlink.RuleMessage{Family: fam, DstLength: uint8(p.Bits()), Action: unix.FR_ACT_UNREACHABLE,
			Attributes: &rtnetlink.RuleAttributes{Dst: &dst, Priority: &prio, IPProto: &proto}})
		if err != nil && !errors.Is(err, unix.EEXIST) {
			if fam == unix.AF_INET6 && noIPv6(err) {
				continue
			}
			errs = append(errs, fmt.Errorf("capture: rule \"to %s ipproto udp unreachable\": %w", p, err))
		}
	}
	return errors.Join(errs...)
}

// routing adds or removes, for IPv4 and IPv6:
//
//	ip rule add fwmark RouteMark/RouteMark lookup RouteTable priority RulePriority
//	ip route add local default dev lo table RouteTable
func routing(add bool) error {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("capture: netlink: %w", err)
	}
	defer conn.Close()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return fmt.Errorf("capture: %w", err)
	}
	var errs []error
	for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
		mark, mask, table, prio := uint32(RouteMark), uint32(RouteMark), uint32(RouteTable), uint32(RulePriority)
		rule := &rtnetlink.RuleMessage{
			Family: fam, Table: unix.RT_TABLE_UNSPEC, Action: unix.FR_ACT_TO_TBL,
			Attributes: &rtnetlink.RuleAttributes{FwMark: &mark, FwMask: &mask, Table: &table, Priority: &prio},
		}
		dst := net.IPv4zero
		if fam == unix.AF_INET6 {
			dst = net.IPv6zero
		}
		route := &rtnetlink.RouteMessage{
			Family: fam, Table: unix.RT_TABLE_UNSPEC, Protocol: unix.RTPROT_BOOT,
			Scope: unix.RT_SCOPE_HOST, Type: unix.RTN_LOCAL,
			Attributes: rtnetlink.RouteAttributes{Dst: dst, OutIface: uint32(lo.Index), Table: table},
		}
		if add {
			if err := conn.Rule.Add(rule); err != nil && !errors.Is(err, unix.EEXIST) {
				if fam == unix.AF_INET6 && noIPv6(err) {
					continue
				}
				errs = append(errs, fmt.Errorf("capture: add rule (family %d): %w", fam, err))
				continue
			}
			if err := conn.Route.Replace(route); err != nil {
				errs = append(errs, fmt.Errorf("capture: add local route (family %d): %w", fam, err))
			}
			continue
		}
		// Delete every matching rule (a crash may have left duplicates).
		for i := 0; i < 8; i++ {
			if conn.Rule.Delete(rule) != nil {
				break
			}
		}
		conn.Route.Delete(route)
	}
	return errors.Join(errs...)
}

func noIPv6(err error) bool {
	return errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EOPNOTSUPP)
}
