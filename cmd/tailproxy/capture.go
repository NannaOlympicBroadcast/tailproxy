package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/antibypass"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/capture"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/dnsserver"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/fakeip"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/iplearn"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/proxy"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/tunstack"
	"github.com/tailscale/wireguard-go/tun"
)

// captureRuntime is transparent capture (capture.mode: tproxy): the DNS
// front end, the TPROXY listeners and the nftables rules.
type captureRuntime struct {
	opts      capture.Options
	pool      *fakeip.Pool
	poolFile  string
	dns       *dnsserver.Server
	dnsPC     net.PacketConn
	dnsLn     net.Listener
	tproxyLns []net.Listener
	in        *proxy.Transparent
	// UDP inbound (capture.udp: proxy, or TUN mode); nil otherwise.
	udpLns []*capture.UDPListener
	udpIn  *proxy.TransparentUDP
	// TUN mode (capture.mode: tun) instead of nftables TPROXY.
	tun       *tunstack.Stack
	tunRouter *tunstack.Router
	tunName   string
	tunDNS    netip.Addr
	rules     func() *rule.Engine
	// DoH block lists (nil when dns.anti_bypass.block_doh is off).
	doh      *antibypass.Lists
	dohFile  string
	dohURLs  []string
	dohHTTP  *http.Client
	dohDirty atomic.Bool // lists changed: re-apply nft
	// learn maps real addresses back to names (nil when learn_rule_ips is
	// off); resolver pre-resolves rule host names through the upstreams.
	learn        *iplearn.Table
	resolver     *net.Resolver
	learnGen     uint64 // table generation in the applied nft rules
	learnApplied time.Time

	mu      sync.Mutex
	applied []netip.Prefix // routed prefixes currently in nft
}

// setupCapture binds everything and installs the nft rules (tproxy) or
// the TUN device and its routes (tun). On error, whatever was set up is
// undone.
func setupCapture(cfg *config.Config, rules func() *rule.Engine, router *proxy.Router, stateDir string) (_ *captureRuntime, err error) {
	tunMode := cfg.Capture.Mode == config.CaptureTUN
	switch {
	case tunMode && !tunstack.Supported:
		return nil, errors.New("capture.mode tun is only implemented on Linux so far; use capture.socks_listen on this system")
	case !tunMode && !capture.Supported:
		return nil, errors.New("capture.mode tproxy is only supported on Linux; use capture.socks_listen on this system")
	}
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("capture.mode %s needs root (network device, routes and policy rules); run as root or use capture.socks_listen", cfg.Capture.Mode)
	}
	c := &captureRuntime{rules: rules}
	defer func() {
		if err != nil {
			c.Close()
		}
	}()

	var fakePrefixes []netip.Prefix
	if cfg.DNS.Mode == "fakeip" {
		v4, v6 := fakeip.DefaultInet4, fakeip.DefaultInet6
		if cfg.DNS.FakeIP.Inet4 != "" {
			v4, _ = config.ParsePrefix(cfg.DNS.FakeIP.Inet4)
		}
		if cfg.DNS.FakeIP.Inet6 != "" {
			v6, _ = config.ParsePrefix(cfg.DNS.FakeIP.Inet6)
		}
		if c.pool, err = fakeip.New(v4, v6); err != nil {
			return nil, err
		}
		c.poolFile = filepath.Join(stateDir, "fakeip.json")
		if err := c.pool.Load(c.poolFile); err != nil {
			log.Printf("tailproxy: %v (starting with an empty FakeIP table)", err)
		}
		fakePrefixes = c.pool.Prefixes()
	}

	upstreams, err := dnsserver.ParseUpstreams(cfg.DNS.DirectUpstream)
	if err != nil {
		return nil, err
	}
	bypass := net.Dialer{Control: capture.BypassControl}
	router.Direct = net.Dialer{Control: capture.BypassControl, Resolver: dnsserver.Resolver(upstreams, &bypass)}
	router.UnknownDomain = cfg.DNS.UnknownDomain

	c.dns = &dnsserver.Server{Pool: c.pool, Rules: rules, Upstreams: upstreams, Canary: cfg.DNS.AntiBypass.CanaryOn(), Dialer: bypass, Logf: log.Printf}
	ab := cfg.DNS.AntiBypass
	if ab.BlockDoHOn() {
		c.doh = antibypass.New(ab.DoHAllow)
		c.dohFile = filepath.Join(stateDir, "doh-lists.txt")
		if err := c.doh.LoadCache(c.dohFile); err != nil {
			log.Printf("tailproxy: DoH list cache: %v", err)
		}
		c.dohURLs = ab.DoHLists
		if len(c.dohURLs) == 0 {
			c.dohURLs = config.DefaultDoHLists
		}
		direct := router.Direct
		c.dohHTTP = &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{DialContext: direct.DialContext}}
		c.dns.Block = c.doh.BlockedDomain
	}
	c.dns.StripECH = ab.StripECHOn(cfg.DNS.Mode)
	if ab.LearnOn() {
		c.learn = iplearn.New()
		c.resolver = router.Direct.Resolver
		c.dns.Observe = func(name string, addrs []netip.Addr, ttl time.Duration) {
			if rules().DomainMayRoute(name) {
				c.learn.Add(name, addrs, ttl)
			}
		}
	}
	// A host DNS listener: always with tproxy (nft redirects port 53 to
	// it); with tun only if capture.dns_listen is set (the stack answers
	// DNS itself).
	var dnsAddr netip.AddrPort
	if !tunMode || cfg.Capture.DNSListen != "" {
		if c.dnsPC, c.dnsLn, err = dnsserver.Listen(cfg.Capture.DNSListen); err != nil {
			return nil, err
		}
		dnsAddr, _ = netip.ParseAddrPort(c.dnsPC.LocalAddr().String())
	}

	c.in = &proxy.Transparent{Router: router, Pool: c.pool, ListenPort: cfg.Capture.TProxyPort, Logf: log.Printf}
	udpProxy := cfg.Capture.UDP == config.UDPProxy
	if udpProxy {
		c.udpIn = &proxy.TransparentUDP{Router: router, Pool: c.pool, Logf: log.Printf}
	}
	if c.doh != nil {
		c.in.BlockDomain = c.doh.BlockedDomain
		if c.udpIn != nil {
			c.udpIn.BlockDomain = c.doh.BlockedDomain
		}
	}
	if c.learn != nil {
		c.in.Learned = c.learn.Lookup
		if c.udpIn != nil {
			c.udpIn.Learned = c.learn.Lookup
		}
	}

	if tunMode {
		tunstack.Cleanup() // policy rules left by a crash
		addr, _ := netip.ParsePrefix(cfg.Capture.TUNAddress)
		c.tunName, c.tunDNS = cfg.Capture.TUNName, cfg.Capture.TUNDNSAddr()
		dev, err := tun.CreateTUN(c.tunName, 1500)
		if err != nil {
			return nil, fmt.Errorf("capture: create TUN device %s: %w", c.tunName, err)
		}
		if c.tun, err = tunstack.New(dev, tunstack.Options{DNSAddr: c.tunDNS, DNS: c.dns, RejectUDP: !udpProxy, Logf: log.Printf}); err != nil {
			dev.Close()
			return nil, err
		}
		if c.tunRouter, err = tunstack.NewRouter(c.tunName, addr); err != nil {
			return nil, err
		}
		c.in.Name = "tun"
		if c.udpIn != nil {
			c.udpIn.Reply, c.udpIn.Name = c.tun.Reply, "tun"
		}
		c.opts = capture.Options{Scope: cfg.Capture.Scope, FakeIP: fakePrefixes}
		if err := c.apply(); err != nil {
			return nil, err
		}
		return c, nil
	}

	if c.tproxyLns, err = capture.ListenTProxy(cfg.Capture.TProxyPort); err != nil {
		return nil, err
	}
	if udpProxy {
		if c.udpLns, err = capture.ListenTProxyUDP(cfg.Capture.TProxyPort); err != nil {
			return nil, err
		}
		c.udpIn.Reply = func(orig, client netip.AddrPort) (net.Conn, error) { return capture.DialUDPReply(orig, client) }
	}

	var exclude []netip.Prefix
	for _, s := range cfg.Capture.ExcludeCIDR {
		p, _ := config.ParsePrefix(s)
		exclude = append(exclude, p)
	}
	c.opts = capture.Options{
		Scope: cfg.Capture.Scope, TProxyPort: cfg.Capture.TProxyPort,
		DNSPort: dnsAddr.Port(), HijackLANDNS: !dnsAddr.Addr().IsLoopback(),
		FakeIP: fakePrefixes, Exclude: exclude,
		BlockDoTDoQ: ab.BlockDoTDoQOn(),
		UDP:         c.udpIn != nil,
	}
	capture.Teardown() // leftovers from a crash
	if err := c.apply(); err != nil {
		return nil, err
	}
	return c, nil
}

// apply installs the rules with the current routed prefixes.
func (c *captureRuntime) apply() error {
	routed := c.rules().RoutedPrefixes()
	o := c.opts
	o.Route = append(slices.Clone(o.FakeIP), routed...)
	if c.doh != nil {
		v4, v6 := c.doh.Addrs()
		o.DoHAddrs = append(v4, v6...)
	}
	var gen uint64
	if c.learn != nil {
		// Learned addresses of routed names are captured too, so selective
		// mode also works with real-IP DNS and with apps using their own DoH.
		var addrs []netip.Addr
		addrs, gen = c.learn.Addrs(c.rules().DomainMayRoute)
		for _, a := range addrs {
			o.Route = append(o.Route, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	if c.tun != nil {
		// TUN: the same prefixes are routed into the device, plus the
		// stack's DNS address. DoH / DoT addresses are not blocked by IP
		// here (no nftables); their names still are, in DNS and SNI.
		routes := append(o.Route, netip.PrefixFrom(c.tunDNS, 32))
		if err := c.tunRouter.SetRoutes(routes); err != nil {
			return err
		}
	} else if err := capture.Setup(o); err != nil {
		return err
	}
	c.mu.Lock()
	c.applied, c.learnGen, c.learnApplied = routed, gen, time.Now()
	c.mu.Unlock()
	return nil
}

// learnChanged reports new learned addresses, at most every 10 seconds (each
// re-apply rewrites the whole table).
func (c *captureRuntime) learnChanged() bool {
	if c.learn == nil {
		return false
	}
	_, gen := c.learn.Addrs(func(string) bool { return false })
	c.mu.Lock()
	defer c.mu.Unlock()
	return gen != c.learnGen && time.Since(c.learnApplied) >= 10*time.Second
}

// preResolve resolves the host names written in routing rules now and
// every 10 minutes, so their addresses map back to a name (DESIGN §4.8 L4).
func (c *captureRuntime) preResolve(ctx context.Context) {
	for {
		for _, h := range c.rules().RoutedHosts() {
			rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			addrs, err := c.resolver.LookupNetIP(rctx, "ip", h)
			cancel()
			if err == nil {
				c.learn.Add(h, addrs, 15*time.Minute)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Minute):
		}
	}
}

// Serve runs the DNS front end and the TPROXY inbound until ctx ends, and
// re-applies the nft rules when a rule edit changes the routed prefixes.
func (c *captureRuntime) Serve(ctx context.Context) {
	if c.dnsPC != nil {
		go func() {
			if err := c.dns.Serve(ctx, c.dnsPC, c.dnsLn); err != nil {
				log.Printf("tailproxy: dns: %v", err)
			}
		}()
	}
	if c.tun != nil {
		go func() {
			if err := c.in.Serve(ctx, c.tun.Listener()); err != nil {
				log.Printf("tailproxy: tun: %v", err)
			}
		}()
		if c.udpIn != nil {
			go func() {
				if err := c.udpIn.Serve(ctx, c.tun.UDPListener()); err != nil {
					log.Printf("tailproxy: tun udp: %v", err)
				}
			}()
		}
	}
	for _, ln := range c.tproxyLns {
		go func() {
			if err := c.in.Serve(ctx, ln); err != nil {
				log.Printf("tailproxy: tproxy: %v", err)
			}
		}()
	}
	for _, ln := range c.udpLns {
		go func() {
			if err := c.udpIn.Serve(ctx, ln); err != nil {
				log.Printf("tailproxy: tproxy udp: %v", err)
			}
		}()
	}
	if c.doh != nil {
		go c.refreshDoH(ctx)
	}
	if c.learn != nil {
		go c.preResolve(ctx)
	}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	saved := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c.mu.Lock()
		changed := !slices.Equal(c.applied, c.rules().RoutedPrefixes()) || c.dohDirty.Swap(false)
		c.mu.Unlock()
		changed = changed || c.learnChanged()
		if changed {
			if err := c.apply(); err != nil {
				log.Printf("tailproxy: capture: updating nft rules after a rule change: %v", err)
			} else {
				log.Printf("tailproxy: capture: nft rules updated")
			}
		}
		if c.pool != nil && time.Since(saved) > time.Minute {
			c.pool.Save(c.poolFile)
			saved = time.Now()
		}
	}
}

// refreshDoH downloads the DoH lists now and every 12 hours; on failure
// the cached (or built-in) lists stay in use.
func (c *captureRuntime) refreshDoH(ctx context.Context) {
	for {
		err := c.doh.Update(ctx, c.dohHTTP, c.dohURLs, c.dohFile)
		d, i, src, _ := c.doh.Stats()
		if err != nil {
			log.Printf("tailproxy: DoH lists: %v (keeping %s list: %d names, %d addresses)", err, src, d, i)
		} else {
			log.Printf("tailproxy: DoH lists updated: %d names, %d addresses", d, i)
			c.dohDirty.Store(true)
		}
		wait := 12 * time.Hour
		if err != nil {
			wait = 30 * time.Minute
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// Close removes the rules (or the TUN device) and saves the FakeIP table.
func (c *captureRuntime) Close() {
	if c.tun != nil || c.tunRouter != nil {
		if c.tun != nil {
			c.tun.Close() // the device goes, and its routes with it
		}
		if c.tunRouter != nil {
			c.tunRouter.Close()
		}
	} else if err := capture.Teardown(); err != nil {
		log.Printf("tailproxy: capture teardown: %v", err)
	}
	for _, ln := range c.tproxyLns {
		ln.Close()
	}
	for _, ln := range c.udpLns {
		ln.Close()
	}
	if c.dnsPC != nil {
		c.dnsPC.Close()
		c.dnsLn.Close()
	}
	if c.pool != nil {
		if err := c.pool.Save(c.poolFile); err != nil {
			log.Printf("tailproxy: save FakeIP table: %v", err)
		}
	}
}

// Summary for the panel's component list.
func (c *captureRuntime) Summary() (capState, capDetail, dnsState, dnsDetail string) {
	capDetail = fmt.Sprintf("TPROXY :%d，范围 %s", c.opts.TProxyPort, c.opts.Scope)
	if c.tun != nil {
		capDetail = fmt.Sprintf("TUN %s，范围 %s，DNS %s", c.tunName, c.opts.Scope, c.tunDNS)
	}
	if c.udpIn != nil {
		capDetail += fmt.Sprintf("；UDP 代理，活动流 %d", c.udpIn.Flows())
	} else {
		capDetail += "；UDP：发往 FakeIP 的立即不可达"
	}
	d := c.dns
	mode := "real"
	if c.pool != nil {
		mode = "fakeip"
	}
	listen := "TUN 内 " + c.tunDNS.String() + ":53"
	if c.dnsPC != nil {
		listen = c.dnsPC.LocalAddr().String()
	}
	dnsDetail = fmt.Sprintf("%s 模式，监听 %s；查询 %d，FakeIP %d，转发 %d，失败 %d，canary %d，拦截 DoH %d", mode, listen,
		d.Queries.Load(), d.Fake.Load(), d.Forwarded.Load(), d.Failed.Load(), d.CanaryHits.Load(), d.Blocked.Load())
	if c.doh != nil {
		n, i, src, at := c.doh.Stats()
		srcText := map[string]string{"builtin": "内置", "cache": "缓存", "download": "已更新"}[src]
		if c.tun != nil {
			// No nftables in TUN mode: names are blocked, addresses are not.
			capDetail += fmt.Sprintf("；DoH 封堵：%d 个域名（按地址封堵仅 tproxy 模式；%s，%s）", n, srcText, at.Format("01-02 15:04"))
		} else {
			capDetail += fmt.Sprintf("；DoH 封堵：%d 个域名、%d 个地址（%s，%s）", n, i, srcText, at.Format("01-02 15:04"))
		}
	}
	if c.opts.BlockDoTDoQ && c.tun == nil {
		capDetail += "；DoT/DoQ 853 已封堵"
	}
	if c.learn != nil {
		capDetail += fmt.Sprintf("；已学习 %d 个地址", c.learn.Len())
	}
	if d.StripECH {
		dnsDetail += fmt.Sprintf("；剥离 ECH %d", d.ECHStripped.Load())
	}
	return "running", capDetail, "running", dnsDetail
}

// cmdCapture implements `tailproxy capture down`: remove leftover rules
// after a crash (also run by the systemd unit's ExecStopPost).
func cmdCapture(args []string) error {
	if len(args) != 1 || args[0] != "down" {
		return errors.New("用法：tailproxy capture down   # 删除 tailproxy 的 nftables 表和策略路由（崩溃后恢复网络用）")
	}
	if !capture.Supported {
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("tailproxy capture down 需要 root")
	}
	if err := errors.Join(capture.Teardown(), tunstack.Cleanup()); err != nil {
		return err
	}
	fmt.Println("已删除 nftables 表 inet " + capture.TableName + " 和策略路由（fwmark " + strconv.Itoa(capture.RouteMark) + " → table " + strconv.Itoa(capture.RouteTable) + "）")
	return nil
}
