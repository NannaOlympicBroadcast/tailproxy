//go:build !windows

package dnsserver

import "net/netip"

const systemResolverSource = "/run/systemd/resolve/resolv.conf or /etc/resolv.conf"

func systemResolvers(exclude []netip.Addr) []string { return resolvConfResolvers(exclude) }
