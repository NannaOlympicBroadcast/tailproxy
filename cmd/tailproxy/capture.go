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
	"github.com/NannaOlympicBroadcast/tailproxy/internal/proxy"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
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
	rules     func() *rule.Engine
	// DoH block lists (nil when dns.anti_bypass.block_doh is off).
	doh      *antibypass.Lists
	dohFile  string
	dohURLs  []string
	dohHTTP  *http.Client
	dohDirty atomic.Bool // lists changed: re-apply nft

	mu      sync.Mutex
	applied []netip.Prefix // routed prefixes currently in nft
}

// setupCapture binds everything and installs the nft rules. On error,
// whatever was set up is undone.
func setupCapture(cfg *config.Config, rules func() *rule.Engine, router *proxy.Router, stateDir string) (_ *captureRuntime, err error) {
	if !capture.Supported {
		return nil, errors.New("capture.mode tproxy is only supported on Linux; use capture.socks_listen on this system")
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("capture.mode tproxy needs root (nftables TPROXY and policy routing); run as root or use capture.socks_listen")
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
	if c.dnsPC, c.dnsLn, err = dnsserver.Listen(cfg.Capture.DNSListen); err != nil {
		return nil, err
	}
	dnsAddr, _ := netip.ParseAddrPort(c.dnsPC.LocalAddr().String())

	if c.tproxyLns, err = capture.ListenTProxy(cfg.Capture.TProxyPort); err != nil {
		return nil, err
	}
	c.in = &proxy.Transparent{Router: router, Pool: c.pool, ListenPort: cfg.Capture.TProxyPort, Logf: log.Printf}
	if c.doh != nil {
		c.in.BlockDomain = c.doh.BlockedDomain
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
	if err := capture.Setup(o); err != nil {
		return err
	}
	c.mu.Lock()
	c.applied = routed
	c.mu.Unlock()
	return nil
}

// Serve runs the DNS front end and the TPROXY inbound until ctx ends, and
// re-applies the nft rules when a rule edit changes the routed prefixes.
func (c *captureRuntime) Serve(ctx context.Context) {
	go func() {
		if err := c.dns.Serve(ctx, c.dnsPC, c.dnsLn); err != nil {
			log.Printf("tailproxy: dns: %v", err)
		}
	}()
	for _, ln := range c.tproxyLns {
		go func() {
			if err := c.in.Serve(ctx, ln); err != nil {
				log.Printf("tailproxy: tproxy: %v", err)
			}
		}()
	}
	if c.doh != nil {
		go c.refreshDoH(ctx)
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

// Close removes the rules and saves the FakeIP table.
func (c *captureRuntime) Close() {
	if err := capture.Teardown(); err != nil {
		log.Printf("tailproxy: capture teardown: %v", err)
	}
	for _, ln := range c.tproxyLns {
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
	d := c.dns
	mode := "real"
	if c.pool != nil {
		mode = "fakeip"
	}
	dnsDetail = fmt.Sprintf("%s 模式，监听 %s；查询 %d，FakeIP %d，转发 %d，失败 %d，canary %d，拦截 DoH %d", mode, c.dnsPC.LocalAddr(),
		d.Queries.Load(), d.Fake.Load(), d.Forwarded.Load(), d.Failed.Load(), d.CanaryHits.Load(), d.Blocked.Load())
	if c.doh != nil {
		n, i, src, at := c.doh.Stats()
		srcText := map[string]string{"builtin": "内置", "cache": "缓存", "download": "已更新"}[src]
		capDetail += fmt.Sprintf("；DoH 封堵：%d 个域名、%d 个地址（%s，%s）", n, i, srcText, at.Format("01-02 15:04"))
	}
	if c.opts.BlockDoTDoQ {
		capDetail += "；DoT/DoQ 853 已封堵"
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
	if err := capture.Teardown(); err != nil {
		return err
	}
	fmt.Println("已删除 nftables 表 inet " + capture.TableName + " 和策略路由（fwmark " + strconv.Itoa(capture.RouteMark) + " → table " + strconv.Itoa(capture.RouteTable) + "）")
	return nil
}
