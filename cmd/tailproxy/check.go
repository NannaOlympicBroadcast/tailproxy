package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
)

// cmdCheck implements `tailproxy check [-c FILE]`: validate a
// configuration without starting anything (for scripts and agents that
// write config.yaml).
func cmdCheck(args []string) error { return check(args, os.Stdout) }

func check(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("c", "config.yaml", "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fmt.Fprintln(out, "用法：tailproxy check [-c FILE]   # 校验配置文件，不启动服务")
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		if err == nil {
			err = fmt.Errorf("unexpected argument %q", fs.Arg(0))
		}
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return fmt.Errorf("%s: %w", *path, err)
	}
	eng, err := rule.Compile(cfg.Rules)
	if err != nil {
		return fmt.Errorf("%s: %w", *path, err)
	}
	slots, groups := 0, 0
	for _, e := range cfg.Egress {
		if e.Type != "" {
			groups++
		} else {
			slots++
		}
	}
	socks := cfg.Capture.SocksListen
	if socks == "" {
		socks = "关闭"
	}
	fmt.Fprintf(out, "%s：配置有效\n  出口 %d 个、出口组 %d 个，规则 %d 条\n  捕获模式 %s（范围 %s），SOCKS5 %s，DNS %s\n  面板 %s\n",
		*path, slots, groups, eng.Len(), cfg.Capture.Mode, cfg.Capture.Scope, socks, cfg.DNS.Mode, cfg.Panel.Listen)
	return nil
}
