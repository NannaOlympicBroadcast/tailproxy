// Command tailproxy runs the tailproxy daemon. The current build serves the
// web panel (default 127.0.0.1:7708) backed by the config loader and rule
// engine; the egress manager and capture layers are not implemented yet.
//
//	tailproxy start  [-c config.yaml] [--ephemeral-token] [--state-dir DIR]  run in the background
//	tailproxy run    [-c config.yaml] [--ephemeral-token] [--state-dir DIR]  run in the foreground
//	tailproxy stop   [--state-dir DIR]
//	tailproxy status [--state-dir DIR]
//	tailproxy token  [--rotate] [--state-dir DIR]                            print or replace the token
//	tailproxy version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/egress"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/panel"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/proxy"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/service"
)

var version = "dev"

const usage = `用法：tailproxy <命令> [参数]

命令：
  start    在后台启动服务：打印面板地址和访问令牌后退出前台
  run      在前台运行（Ctrl-C 停止）
  stop     停止后台服务
  status   查看服务状态
  token    打印持久化保存的访问令牌；加 --rotate 生成新令牌（重启服务后生效）
  service  install / uninstall：安装为 systemd 服务并开机自启（见 tailproxy service -h）
  version  打印版本

start / run 的参数：
  -c FILE             配置文件（默认 config.yaml）
  --ephemeral-token   本次使用一次性令牌：不读取也不写入令牌文件，进程退出即失效
  --state-dir DIR     状态目录（默认 ~/.lighthousepro）

访问令牌默认持久化保存在 <state-dir>/tailproxy.token（权限 600）：
首次启动时生成，之后每次启动都沿用同一个令牌。

兼容旧用法：tailproxy -c config.yaml 等同于 tailproxy run -c config.yaml
`

func main() {
	log.SetFlags(log.LstdFlags)
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "start":
		err = cmdStart(args)
	case "run":
		err = cmdRun(args)
	case "stop":
		err = cmdStop(args)
	case "status":
		err = cmdStatus(args)
	case "token":
		err = cmdToken(args)
	case "service":
		err = cmdService(args)
	case "version", "--version", "-version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "tailproxy: 未知命令 %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "tailproxy: %v\n", err)
		os.Exit(1)
	}
}

type runFlags struct {
	config    string
	ephemeral bool // one-off token: neither read nor write the token file
	paths     service.Paths
	child     bool // started by `tailproxy start`
}

func parseRunFlags(name string, args []string) (runFlags, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	var f runFlags
	var dir string
	fs.StringVar(&f.config, "c", "config.yaml", "configuration file")
	fs.BoolVar(&f.ephemeral, "ephemeral-token", false, "use a one-off token instead of the persisted one")
	fs.Bool("save-token", true, "deprecated: the token is now persisted by default")
	fs.StringVar(&dir, "state-dir", "", "state directory (default ~/.lighthousepro)")
	fs.BoolVar(&f.child, "daemon-child", false, "internal: set by tailproxy start")
	if err := fs.Parse(args); err != nil {
		return f, err
	}
	if fs.NArg() > 0 {
		return f, fmt.Errorf("多余的参数：%v", fs.Args())
	}
	abs, err := filepath.Abs(f.config)
	if err != nil {
		return f, err
	}
	f.config = abs
	f.paths, err = statePaths(dir)
	return f, err
}

func statePaths(dir string) (service.Paths, error) {
	if dir == "" {
		d, err := service.DefaultDir()
		if err != nil {
			return service.Paths{}, err
		}
		dir = d
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return service.Paths{}, err
	}
	p := service.NewPaths(abs)
	return p, p.Ensure()
}

func stateDirOnly(name string, args []string) (service.Paths, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	dir := fs.String("state-dir", "", "state directory (default ~/.lighthousepro)")
	if err := fs.Parse(args); err != nil {
		return service.Paths{}, err
	}
	return statePaths(*dir)
}

func alreadyRunning(st *service.State) error {
	return fmt.Errorf("tailproxy 已在运行（pid %d，面板 %s）。查看令牌：tailproxy token；停止：tailproxy stop", st.PID, st.URL)
}

// cmdStart launches `tailproxy run --daemon-child` detached from the terminal,
// waits until its panel is listening, prints how to log in and returns.
func cmdStart(args []string) error {
	f, err := parseRunFlags("start", args)
	if err != nil {
		return err
	}
	if !service.Supported {
		_, err := service.Spawn("", nil, "", 0)
		return err
	}
	if st, err := f.paths.Running(); err != nil {
		return err
	} else if st != nil {
		return alreadyRunning(st)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	childArgs := []string{"run", "--daemon-child", "-c", f.config, "--state-dir", f.paths.Dir}
	if f.ephemeral {
		childArgs = append(childArgs, "--ephemeral-token")
	}
	ready, err := service.Spawn(exe, childArgs, f.paths.Log, 15*time.Second)
	if err != nil {
		return fmt.Errorf("后台启动失败：%w", err)
	}
	printBanner(os.Stdout, ready)
	fmt.Printf("  已在后台运行：pid %d，日志 %s\n  查看状态：tailproxy status    停止：tailproxy stop\n\n", ready.PID, ready.Log)
	return nil
}

// cmdRun serves in the foreground. With --daemon-child it is the background
// process started by cmdStart and reports readiness instead of printing.
func cmdRun(args []string) (err error) {
	f, err := parseRunFlags("run", args)
	if err != nil {
		return err
	}
	var readyW *os.File
	if f.child {
		readyW = service.ReadyWriter()
		if readyW == nil {
			return errors.New("--daemon-child is only for tailproxy start")
		}
		defer func() {
			if err != nil && readyW != nil {
				service.Report(readyW, service.Ready{Error: err.Error()})
			}
		}()
	}

	if st, err := f.paths.Running(); err != nil {
		return err
	} else if st != nil && st.PID != os.Getpid() {
		return alreadyRunning(st)
	}

	var opts panel.Options
	if !f.ephemeral {
		opts.TokenFile = f.paths.Token
	}
	p, err := panel.New(f.config, version, opts)
	if err != nil {
		return err
	}
	if p.TailnetRequested() {
		log.Printf("tailproxy: warning: panel.tailnet is not implemented yet (needs the ts egress slot); the panel only listens on %s", p.Addr())
	}
	ln, err := p.Listen()
	if err != nil {
		return err
	}
	defer ln.Close()

	// Egress slots and the SOCKS5 inbound. Listeners are bound before
	// readiness is reported, so a busy port fails `tailproxy start`.
	cfg := p.Config()
	mgr, err := egress.New(cfg, f.paths.Dir, log.Printf)
	if err != nil {
		return err
	}
	tracker := proxy.NewTracker()
	router := &proxy.Router{Rules: p.Engine, Egress: mgr, Tracker: tracker}
	rt := &runtimeView{egress: mgr, tracker: tracker}
	var socksLn net.Listener
	if cfg.Capture.SocksListen != "" {
		if socksLn, err = proxy.ListenSOCKS(cfg.Capture.SocksListen); err != nil {
			return err
		}
		defer socksLn.Close()
		rt.socksAddr = socksLn.Addr().String()
	}
	p.SetRuntime(rt)

	st := service.State{PID: os.Getpid(), URL: p.URL(), Config: f.config, TokenEnv: p.TokenEnv(), TokenFile: p.TokenFile(), Started: time.Now()}
	underSystemd := service.UnderSystemd()
	if underSystemd {
		st.Manager = "systemd"
		st.UserUnit = os.Getenv("TAILPROXY_USER_UNIT") == "1"
	}
	if f.child {
		st.Log = f.paths.Log
	}
	if err := f.paths.WriteState(st); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	defer f.paths.Cleanup(os.Getpid())

	ready := service.Ready{
		OK: true, PID: st.PID, URL: p.URL(), Listen: ln.Addr().String(), SOCKS: rt.socksAddr,
		TokenEnv: p.TokenEnv(), TokenFile: p.TokenFile(), TokenCreated: p.TokenCreated(), Log: st.Log,
	}
	if p.TokenEnv() == "" {
		ready.Token, ready.LoginURL = p.Token(), p.LoginURL()
	}
	if f.child {
		if err := service.Report(readyW, ready); err != nil {
			return fmt.Errorf("report readiness: %w", err)
		}
		readyW = nil
		// The token is deliberately not written to the log.
		log.Printf("tailproxy %s started in the background: pid %d, panel %s", version, st.PID, p.URL())
	} else if underSystemd {
		// stderr goes to the journal: never print the token there.
		log.Printf("tailproxy %s started by systemd: pid %d, panel %s; token: run `tailproxy token` as the service user", version, st.PID, p.URL())
		if err := service.Notify(fmt.Sprintf("READY=1\nSTATUS=panel %s", p.URL())); err != nil {
			log.Printf("tailproxy: sd_notify: %v", err)
		}
	} else {
		printBanner(os.Stderr, ready)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		service.Notify("STOPPING=1")
	}()
	mgr.Start(ctx)
	defer mgr.Close()
	if socksLn != nil {
		socks := &proxy.SOCKS{Router: router, Logf: log.Printf}
		go func() {
			if err := socks.Serve(ctx, socksLn); err != nil {
				log.Printf("tailproxy: socks5: %v", err)
			}
		}()
	}
	if err := p.Serve(ctx, ln); err != nil {
		return fmt.Errorf("panel: %w", err)
	}
	log.Printf("tailproxy: stopped (pid %d)", st.PID)
	return nil
}

func cmdStop(args []string) error {
	paths, err := stateDirOnly("stop", args)
	if err != nil {
		return err
	}
	st, err := paths.Running()
	if err != nil {
		return err
	}
	if st == nil {
		fmt.Println("tailproxy 未在运行")
		return nil
	}
	if st.Manager == "systemd" {
		return fmt.Errorf("tailproxy（pid %d）由 systemd 管理，请使用：%s stop %s", st.PID, systemctlCmd(st.UserUnit), service.UnitName)
	}
	if err := service.Terminate(st.PID); err != nil {
		return fmt.Errorf("停止 pid %d：%w", st.PID, err)
	}
	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		if now, _ := paths.Running(); now == nil || now.PID != st.PID {
			fmt.Printf("tailproxy 已停止（pid %d）\n", st.PID)
			return nil
		}
	}
	return fmt.Errorf("pid %d 在 10 秒内没有退出", st.PID)
}

func cmdStatus(args []string) error {
	paths, err := stateDirOnly("status", args)
	if err != nil {
		return err
	}
	st, err := paths.Running()
	if err != nil {
		return err
	}
	if st == nil {
		fmt.Println("tailproxy 未在运行")
		return nil
	}
	mode := "前台"
	switch {
	case st.Manager == "systemd":
		mode = "由 systemd 管理：" + systemctlCmd(st.UserUnit) + " status " + service.UnitName
	case st.Log != "":
		mode = "后台"
	}
	fmt.Printf("tailproxy 正在运行（%s）\n", mode)
	fmt.Printf("  pid       %d\n", st.PID)
	fmt.Printf("  面板地址  %s\n", st.URL)
	fmt.Printf("  已运行    %s（启动于 %s）\n", time.Since(st.Started).Round(time.Second), st.Started.Format(time.DateTime))
	fmt.Printf("  配置文件  %s\n", st.Config)
	if st.Log != "" {
		fmt.Printf("  日志      %s\n", st.Log)
	}
	switch {
	case st.TokenEnv != "":
		fmt.Printf("  访问令牌  来自环境变量 $%s\n", st.TokenEnv)
	case st.TokenFile != "":
		fmt.Printf("  访问令牌  持久化保存在 %s（tailproxy token 查看）\n", st.TokenFile)
	default:
		fmt.Printf("  访问令牌  一次性令牌（--ephemeral-token），只在启动时打印过\n")
	}
	return nil
}

func cmdToken(args []string) error {
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	dir := fs.String("state-dir", "", "state directory (default ~/.lighthousepro)")
	rotate := fs.Bool("rotate", false, "replace the persisted token with a new one")
	if err := fs.Parse(args); err != nil {
		return err
	}
	paths, err := statePaths(*dir)
	if err != nil {
		return err
	}
	st, err := paths.Running()
	if err != nil {
		return err
	}

	if *rotate {
		tok, err := panel.RotateToken(paths.Token)
		if err != nil {
			return err
		}
		fmt.Println(tok)
		if st != nil && st.TokenFile != "" {
			fmt.Fprintf(os.Stderr, "已生成新令牌并保存到 %s。正在运行的服务（pid %d）仍在使用旧令牌，重启后生效：tailproxy stop，然后 tailproxy start -c %s\n", paths.Token, st.PID, st.Config)
		} else {
			fmt.Fprintf(os.Stderr, "已生成新令牌并保存到 %s，下次启动时生效\n", paths.Token)
		}
		return nil
	}

	if st != nil && st.TokenEnv != "" {
		return fmt.Errorf("正在运行的服务使用环境变量 $%s 中的令牌，没有写入文件", st.TokenEnv)
	}
	if st != nil && st.TokenFile == "" {
		return errors.New("正在运行的服务使用一次性令牌（--ephemeral-token），只在启动时打印过，没有保存")
	}
	tok, err := panel.ReadTokenFile(paths.Token)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("还没有保存的令牌（%s）；第一次 tailproxy start 时会自动生成", paths.Token)
	}
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}

// printBanner prints how to reach the panel. A generated token is shown in
// full because it is the only way to log in; a token taken from the
// environment is not echoed, since the operator already has it.
func printBanner(w io.Writer, r service.Ready) {
	fmt.Fprintf(w, "\ntailproxy %s\n", version)
	fmt.Fprintf(w, "  面板地址：%s（监听 %s）\n", r.URL, r.Listen)
	if r.SOCKS != "" {
		fmt.Fprintf(w, "  SOCKS5： %s\n", r.SOCKS)
	}
	if r.TokenEnv != "" {
		fmt.Fprintf(w, "  访问令牌：来自环境变量 $%s（不在终端显示）\n\n", r.TokenEnv)
		return
	}
	fmt.Fprintf(w, "  访问令牌：%s\n", r.Token)
	fmt.Fprintf(w, "  一键登录：%s\n", r.LoginURL)
	switch {
	case r.TokenFile != "" && r.TokenCreated:
		fmt.Fprintf(w, "  令牌已生成并持久化保存到 %s（权限 600），以后每次启动都沿用它\n", r.TokenFile)
		fmt.Fprintf(w, "  查看令牌：tailproxy token    更换令牌：tailproxy token --rotate，然后重启服务\n\n")
	case r.TokenFile != "":
		fmt.Fprintf(w, "  沿用持久化保存的令牌：%s\n", r.TokenFile)
		fmt.Fprintf(w, "  查看令牌：tailproxy token    更换令牌：tailproxy token --rotate，然后重启服务\n\n")
	default:
		fmt.Fprintf(w, "  一次性令牌（--ephemeral-token）：没有保存，进程退出即失效\n\n")
	}
}

// systemctlCmd is the systemctl invocation for a system or user unit.
func systemctlCmd(userUnit bool) string {
	if userUnit {
		return "systemctl --user"
	}
	return "systemctl"
}
