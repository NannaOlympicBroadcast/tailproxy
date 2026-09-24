// Command tailproxy runs the tailproxy daemon. The current build serves the
// web panel (default 127.0.0.1:7708) backed by the config loader and rule
// engine; the egress manager and capture layers are not implemented yet.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/panel"
)

var version = "dev"

func main() {
	cfgPath := flag.String("c", "config.yaml", "path to the configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	p, err := panel.New(*cfgPath, version)
	if err != nil {
		log.Fatalf("tailproxy: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if p.TailnetRequested() {
		log.Printf("tailproxy: warning: panel.tailnet is not implemented yet (needs the ts egress slot); the panel only listens on %s", p.Addr())
	}
	printPanelBanner(os.Stderr, p)
	if err := p.ListenAndServe(ctx); err != nil {
		log.Fatalf("tailproxy: panel: %v", err)
	}
}

// printPanelBanner prints how to reach the panel. A generated token is shown
// in full because it is the only way to log in; a token taken from the
// environment is not echoed, since the operator already has it.
func printPanelBanner(w io.Writer, p *panel.Server) {
	fmt.Fprintf(w, "\ntailproxy %s\n", version)
	fmt.Fprintf(w, "  面板地址：%s（监听 %s）\n", p.URL(), p.Addr())
	if env := p.TokenEnv(); env != "" {
		fmt.Fprintf(w, "  访问令牌：来自环境变量 $%s（不在终端显示）\n\n", env)
		return
	}
	fmt.Fprintf(w, "  访问令牌：%s\n", p.Token())
	fmt.Fprintf(w, "  一键登录：%s\n", p.LoginURL())
	fmt.Fprintf(w, "  令牌在每次启动时随机生成，重启后失效；如需固定令牌，设置 panel.auth_token_env 指向的环境变量（至少 %d 个字符）。\n\n", panel.MinTokenLen)
}
