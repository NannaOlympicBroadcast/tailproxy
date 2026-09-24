package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/relay"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/service"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/token"
)

const relayUsage = `用法：
  tailproxy relay [--listen ADDR] [--allow-private] [--state-dir DIR]   在前台运行中继
  tailproxy relay token [--rotate] [--state-dir DIR]                    打印或更换中继令牌

中继运行在 VPS 等出口机器上（需要已安装并登录 Tailscale）。客户端的 tailproxy
经 tailnet 连接它，流量从这台机器的网络出去；客户端只需要一台 tailnet 设备，
不需要把这台机器设为出口节点。

  --listen ADDR     监听地址，只能是本机 Tailscale 地址或回环地址
                    （默认：自动检测本机 Tailscale IPv4，端口 1081）
  --allow-private   允许连接内网 / 回环 / 链路本地 / tailnet 地址（默认拒绝，
                    防止令牌泄露后被用来访问这台机器上的服务或云厂商元数据）
  --state-dir DIR   状态目录（默认 ~/.lighthousepro）；令牌保存在 relay.token（权限 600）

开机自启：sudo tailproxy service install --relay
`

func cmdRelay(args []string) error {
	if len(args) > 0 && args[0] == "token" {
		return cmdRelayToken(args[1:])
	}
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, relayUsage) }
	listen := fs.String("listen", "", "")
	allowPrivate := fs.Bool("allow-private", false, "")
	dir := fs.String("state-dir", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("多余的参数：%v", fs.Args())
	}
	if *listen != "" {
		if err := relay.CheckListenAddr(*listen); err != nil {
			return err
		}
	}
	paths, err := statePaths(*dir)
	if err != nil {
		return err
	}
	tok, created, err := token.LoadOrCreate(paths.RelayToken)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	addr := *listen
	if addr == "" {
		ip, err := waitTailscaleIP(ctx, time.Minute)
		if err != nil {
			return err
		}
		addr = netip.AddrPortFrom(ip, relay.DefaultPort).String()
	}
	if err := relay.CheckListenAddr(addr); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	addr = ln.Addr().String() // resolves port 0

	srv := &relay.Server{Token: tok, AllowPrivate: *allowPrivate, Logf: log.Printf}
	if service.UnderSystemd() {
		// stderr goes to the journal: never print the token there.
		log.Printf("tailproxy relay %s listening on %s (systemd); token: tailproxy relay token --state-dir %s", version, addr, paths.Dir)
		if err := service.Notify("READY=1\nSTATUS=relay listening on " + addr); err != nil {
			log.Printf("tailproxy relay: sd_notify: %v", err)
		}
	} else {
		printRelayBanner(addr, tok, paths.RelayToken, created, *allowPrivate)
	}
	go func() {
		<-ctx.Done()
		service.Notify("STOPPING=1")
	}()
	go logRelayStats(ctx, srv)
	if err := srv.Serve(ctx, ln); err != nil {
		return fmt.Errorf("relay: %w", err)
	}
	log.Printf("tailproxy relay: stopped")
	return nil
}

// waitTailscaleIP retries detection for a while: at boot tailscaled may not
// have brought the address up yet.
func waitTailscaleIP(ctx context.Context, timeout time.Duration) (netip.Addr, error) {
	deadline := time.Now().Add(timeout)
	for {
		ip, err := relay.TailscaleIPv4()
		if err == nil {
			return ip, nil
		}
		if time.Now().After(deadline) {
			return netip.Addr{}, err
		}
		select {
		case <-ctx.Done():
			return netip.Addr{}, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func logRelayStats(ctx context.Context, s *relay.Server) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	var last int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if total := s.Total.Load(); total != last {
			last = total
			log.Printf("tailproxy relay: %d active, %d total, %d failed, %d auth failures",
				s.Active.Load(), total, s.Failures.Load(), s.AuthFailures.Load())
		}
	}
}

func printRelayBanner(addr, tok, tokenFile string, created, allowPrivate bool) {
	fmt.Fprintf(os.Stderr, "\ntailproxy relay %s\n", version)
	fmt.Fprintf(os.Stderr, "  监听：%s（只接受 tailnet 内的连接）\n", addr)
	fmt.Fprintf(os.Stderr, "  令牌：%s\n", tok)
	if created {
		fmt.Fprintf(os.Stderr, "  令牌已生成并保存到 %s（权限 600），以后每次启动都沿用它\n", tokenFile)
	} else {
		fmt.Fprintf(os.Stderr, "  沿用保存的令牌：%s\n", tokenFile)
	}
	if allowPrivate {
		fmt.Fprintf(os.Stderr, "  注意：--allow-private 已开启，客户端可以访问这台机器所在的内网\n")
	}
	host, port, _ := net.SplitHostPort(addr)
	fmt.Fprintf(os.Stderr, "\n  在客户端 tailproxy 面板的「出口」页找到这台设备，点「添加为中继」，端口 %s，填入上面的令牌；\n", port)
	fmt.Fprintf(os.Stderr, "  或在配置文件里写：- {name: <名称>, relay: '%s'}\n\n", net.JoinHostPort(host, port))
}

func cmdRelayToken(args []string) error {
	fs := flag.NewFlagSet("relay token", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, relayUsage) }
	dir := fs.String("state-dir", "", "")
	rotate := fs.Bool("rotate", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	paths, err := statePaths(*dir)
	if err != nil {
		return err
	}
	if *rotate {
		tok, err := token.Rotate(paths.RelayToken)
		if err != nil {
			return err
		}
		fmt.Println(tok)
		fmt.Fprintf(os.Stderr, "已生成新的中继令牌并保存到 %s。重启中继后生效（systemd：systemctl restart %s），然后在客户端面板里更新令牌\n", paths.RelayToken, service.RelayUnitName)
		return nil
	}
	tok, err := token.ReadFile(paths.RelayToken)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("还没有中继令牌（%s）；第一次运行 tailproxy relay 时会自动生成", paths.RelayToken)
	}
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}

// relayListenDisplay is what `service install --relay` reports as the
// address clients use.
func relayListenDisplay(listen string) string {
	if listen != "" {
		return listen
	}
	if ip, err := relay.TailscaleIPv4(); err == nil {
		return net.JoinHostPort(ip.String(), strconv.Itoa(relay.DefaultPort))
	}
	return "<本机 Tailscale IP>:" + strconv.Itoa(relay.DefaultPort)
}
