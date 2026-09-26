package sdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"

	"github.com/tailscale/wireguard-go/tun"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/dnsserver"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/fakeip"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/proxy"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/tunstack"
)

// TUNOptions configure ServeTUN.
type TUNOptions struct {
	// DNSAddr is the address the stack answers DNS on; hand it to the
	// system (VPN) as its DNS server and route it into the device.
	// Required, e.g. 172.19.0.2 with the device at 172.19.0.1/30.
	DNSAddr netip.Addr
	// DNSUpstreams ("ip" or "ip:port") answer names the rules do not send
	// to an egress. Default: dns.direct_upstream from the config;
	// "system" there reads resolv.conf, which Android does not have, so
	// mobile apps pass the network's DNS servers here.
	DNSUpstreams []string
}

// ServeTUN runs the user-space network stack on dev until ctx ends, then
// closes dev. Packets the system routes into the device are handled like
// tailproxy's TUN mode: DNS at DNSAddr (FakeIPs for names the rules
// route, when dns.mode is fakeip), TCP and UDP flows routed by the rules
// (sniffing TLS / HTTP / QUIC names), capture.udp: block refusing UDP to
// FakeIPs so clients fall back to TCP and sending other UDP direct.
// Routes and system DNS are the caller's (or the platform VPN's) job;
// with Options.Protect set, the engine's own sockets bypass the VPN.
// ServeTUN may run once per engine.
func (e *Engine) ServeTUN(ctx context.Context, dev tun.Device, o TUNOptions) error {
	defer dev.Close()
	if !o.DNSAddr.IsValid() {
		return errors.New("sdk: TUNOptions.DNSAddr is required")
	}
	cfg := e.Config()
	ups := o.DNSUpstreams
	var err error
	if len(ups) == 0 {
		if ups, err = dnsserver.ParseUpstreams(cfg.DNS.DirectUpstream, o.DNSAddr); err != nil {
			return fmt.Errorf("sdk: %w (set TUNOptions.DNSUpstreams)", err)
		}
	} else {
		for i, u := range ups {
			if ap, err := netip.ParseAddrPort(u); err == nil {
				ups[i] = ap.String()
			} else if ip, err := netip.ParseAddr(u); err == nil {
				ups[i] = netip.AddrPortFrom(ip, 53).String()
			} else {
				return fmt.Errorf("sdk: DNS upstream %q is not an IP or IP:port", u)
			}
		}
	}

	var pool *fakeip.Pool
	poolFile := filepath.Join(e.opts.StateDir, "fakeip.json")
	if cfg.DNS.Mode == "fakeip" {
		v4, v6 := fakeip.DefaultInet4, fakeip.DefaultInet6
		if cfg.DNS.FakeIP.Inet4 != "" {
			v4, _ = config.ParsePrefix(cfg.DNS.FakeIP.Inet4)
		}
		if cfg.DNS.FakeIP.Inet6 != "" {
			v6, _ = config.ParsePrefix(cfg.DNS.FakeIP.Inet6)
		}
		if pool, err = fakeip.New(v4, v6); err != nil {
			return err
		}
		if err := pool.Load(poolFile); err != nil {
			e.logf("sdk: %v (starting with an empty FakeIP table)", err)
		}
		defer func() {
			if err := pool.Save(poolFile); err != nil {
				e.logf("sdk: save FakeIP table: %v", err)
			}
		}()
	}
	// Direct dials resolve names with the upstreams, not the system
	// resolver, which now points at this stack.
	e.mu.Lock()
	e.router.Direct.Resolver = dnsserver.Resolver(ups, &e.dialer)
	e.mu.Unlock()

	dns := &dnsserver.Server{Pool: pool, Rules: e.currentRules, Upstreams: ups, Canary: cfg.DNS.AntiBypass.CanaryOn(),
		StripECH: cfg.DNS.AntiBypass.StripECHOn(cfg.DNS.Mode), Dialer: e.dialer, Logf: e.logf}
	udpProxy := cfg.Capture.UDP == config.UDPProxy
	st, err := tunstack.New(dev, tunstack.Options{DNSAddr: o.DNSAddr, DNS: dns, Logf: e.logf,
		RejectUDP: !udpProxy, RejectUDPTo: func(ip netip.Addr) bool { return pool != nil && pool.Contains(ip) }})
	if err != nil {
		return err
	}
	defer st.Close()
	in := &proxy.Transparent{Name: "tun", Router: e.router, Pool: pool, Logf: e.logf}
	udpIn := &proxy.TransparentUDP{Name: "tun", Router: e.router, Pool: pool, Reply: st.Reply, Logf: e.logf}
	if !udpProxy {
		udpIn.Bypass = func(netip.Addr) string { return "capture.udp: block（不代理 UDP）" }
	}
	errc := make(chan error, 2)
	go func() { errc <- in.Serve(ctx, st.Listener()) }()
	go func() { errc <- udpIn.Serve(ctx, st.UDPListener()) }()
	select {
	case <-ctx.Done():
		return nil
	case err := <-errc:
		if err == nil || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}
