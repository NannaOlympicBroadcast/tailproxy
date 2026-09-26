package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/browserpolicy"
)

const doctorUsage = `用法：tailproxy doctor [参数]

浏览器策略（DESIGN §4.8 L5，只在明确执行时写入，可一键撤销）：
  --apply-browser-policy    关闭 Chrome / Chromium / Edge 的 DNS over HTTPS（DnsOverHttpsMode=off）
                            和 Firefox 的 DoH（DNSOverHTTPS: Enabled=false, Locked=true），
                            让浏览器使用系统 DNS（tailproxy）；写入前先列出所有改动并要求确认
  --disable-ech             同时关闭 Chrome / Chromium 的 Encrypted ClientHello（EncryptedClientHelloEnabled=false）
  --all-browsers            不检测是否安装，所有支持的浏览器都写入
  --yes                     不再询问确认
  --revert-browser-policy   撤销 tailproxy 写入的浏览器策略，恢复原来的值

不带参数时显示将写入的内容和当前是否已应用。需要 root / 管理员权限。
macOS 上 Chrome / Edge 的策略以「推荐」级别生效（用户仍可在设置里改回），强制级别需要 MDM 配置描述文件。
`

func cmdDoctor(args []string) error {
	return doctor(args, os.Stdin, os.Stdout, browserpolicy.DefaultStatePath(), isAdmin)
}

func doctor(args []string, stdin io.Reader, out io.Writer, statePath string, admin func() bool) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	apply := fs.Bool("apply-browser-policy", false, "")
	revert := fs.Bool("revert-browser-policy", false, "")
	noECH := fs.Bool("disable-ech", false, "")
	all := fs.Bool("all-browsers", false, "")
	yes := fs.Bool("yes", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fmt.Fprint(out, doctorUsage)
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		if err == nil {
			err = fmt.Errorf("unexpected argument %q", fs.Arg(0))
		}
		return err
	}
	if *apply && *revert {
		return errors.New("--apply-browser-policy 和 --revert-browser-policy 只能选一个")
	}
	opts := browserpolicy.Options{DisableECH: *noECH, All: *all}
	printChanges := func(title string, cs []browserpolicy.Change) {
		fmt.Fprintln(out, title)
		for _, c := range cs {
			fmt.Fprintf(out, "  %-8s %s\n           %s\n", c.Browser, c.Where, c.What)
		}
	}

	if *revert {
		if !admin() {
			return errors.New("撤销浏览器策略需要 root / 管理员权限")
		}
		cs, err := browserpolicy.Revert(statePath)
		if errors.Is(err, browserpolicy.ErrNotApplied) {
			fmt.Fprintln(out, "没有需要撤销的浏览器策略（tailproxy 没有写入过）。")
			return nil
		}
		if err != nil {
			return err
		}
		printChanges("已撤销以下浏览器策略，恢复为原来的值：", cs)
		fmt.Fprintln(out, "重启浏览器后生效。")
		return nil
	}

	plan, err := browserpolicy.Plan(opts)
	if err != nil {
		return err
	}
	_, statErr := os.Stat(statePath)
	applied := statErr == nil
	if !*apply {
		if applied {
			fmt.Fprintf(out, "浏览器策略：已应用（记录在 %s；撤销：tailproxy doctor --revert-browser-policy）\n", statePath)
		} else {
			fmt.Fprintln(out, "浏览器策略：未应用。")
		}
		if len(plan) == 0 {
			fmt.Fprintln(out, "没有检测到支持的浏览器（--all-browsers 可强制写入）。")
			return nil
		}
		printChanges("执行 tailproxy doctor --apply-browser-policy 将写入：", plan)
		return nil
	}
	if applied {
		return browserpolicy.ErrApplied
	}
	if len(plan) == 0 {
		return errors.New("没有检测到支持的浏览器（--all-browsers 可强制写入）")
	}
	if !admin() {
		return errors.New("写入浏览器策略需要 root / 管理员权限")
	}
	printChanges("将写入以下浏览器策略：", plan)
	if !*yes {
		fmt.Fprint(out, "输入 yes 确认写入：")
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		if strings.TrimSpace(line) != "yes" {
			return errors.New("已取消，没有写入任何内容")
		}
	}
	cs, err := browserpolicy.Apply(opts, statePath)
	if err != nil {
		return err
	}
	printChanges("已写入：", cs)
	fmt.Fprintf(out, "重启浏览器后生效；在 chrome://policy、edge://policy、about:policies 查看。撤销：tailproxy doctor --revert-browser-policy（记录在 %s）\n", statePath)
	return nil
}
