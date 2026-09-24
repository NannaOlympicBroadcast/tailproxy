// Command tailproxy runs the tailproxy daemon. The current build serves the
// web panel (default 127.0.0.1:7708) backed by the config loader and rule
// engine; the egress manager and capture layers are not implemented yet.
//
//	tailproxy start  [-c config.yaml] [--save-token] [--state-dir DIR]  run in the background
//	tailproxy run    [-c config.yaml] [--save-token] [--state-dir DIR]  run in the foreground
//	tailproxy stop   [--state-dir DIR]
//	tailproxy status [--state-dir DIR]
//	tailproxy token  [--state-dir DIR]                                  print the saved token
//	tailproxy version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/panel"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/service"
)

var version = "dev"

const usage = `用法：tailproxy <命令> [参数]

命令：
  start    在后台启动服务：打印面板地址和访问令牌后退出前台
  run      在前台运行（Ctrl-C 停止）
  stop     停止后台服务
  status   查看服务状态
  token    打印已保存的访问令牌（需要启动时加 --save-token）
  version  打印版本

start / run 的参数：
  -c FILE           配置文件（默认 config.yaml）
  --save-token      把访问令牌保存到 <state-dir>/tailproxy.token（权限 600）
  --state-dir DIR   状态目录（默认 ~/.lighthousepro）

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
	saveToken bool
	paths     service.Paths
	child     bool // started by `tailproxy start`
}

func parseRunFlags(name string, args []string) (runFlags, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	var f runFlags
	var dir string
	fs.StringVar(&f.config, "c", "config.yaml", "configuration file")
	fs.BoolVar(&f.saveToken, "save-token", false, "save the panel token to <state-dir>/tailproxy.token")
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
	if f.saveToken {
		childArgs = append(childArgs, "--save-token")
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

	p, err := panel.New(f.config, version)
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

	st := service.State{PID: os.Getpid(), URL: p.URL(), Config: f.config, TokenEnv: p.TokenEnv(), Started: time.Now()}
	if f.child {
		st.Log = f.paths.Log
	}
	var tokenNote string
	if f.saveToken {
		if p.TokenEnv() != "" {
			tokenNote = "令牌来自环境变量，未写入文件"
		} else if err := f.paths.SaveToken(p.Token()); err != nil {
			return fmt.Errorf("save token: %w", err)
		} else {
			st.TokenFile = f.paths.Token
		}
	}
	if err := f.paths.WriteState(st); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	defer f.paths.Cleanup(os.Getpid())

	ready := service.Ready{
		OK: true, PID: st.PID, URL: p.URL(), Listen: ln.Addr().String(),
		TokenEnv: p.TokenEnv(), TokenFile: st.TokenFile, Log: st.Log,
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
	} else {
		printBanner(os.Stderr, ready)
	}
	if tokenNote != "" {
		log.Printf("tailproxy: --save-token: %s", tokenNote)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
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
	if st.Log != "" {
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
		fmt.Printf("  访问令牌  已保存到 %s（tailproxy token 查看）\n", st.TokenFile)
	default:
		fmt.Printf("  访问令牌  只在启动时打印过，没有保存\n")
	}
	return nil
}

func cmdToken(args []string) error {
	paths, err := stateDirOnly("token", args)
	if err != nil {
		return err
	}
	st, err := paths.Running()
	if err != nil {
		return err
	}
	if st == nil {
		return errors.New("tailproxy 未在运行")
	}
	if st.TokenEnv != "" {
		return fmt.Errorf("令牌来自环境变量 $%s，没有保存到文件", st.TokenEnv)
	}
	if st.TokenFile == "" {
		return errors.New("启动时没有加 --save-token，令牌只在启动时打印过；需要的话用 tailproxy stop 后再 tailproxy start --save-token")
	}
	tok, err := paths.ReadToken()
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
	if r.TokenEnv != "" {
		fmt.Fprintf(w, "  访问令牌：来自环境变量 $%s（不在终端显示）\n\n", r.TokenEnv)
		return
	}
	fmt.Fprintf(w, "  访问令牌：%s\n", r.Token)
	fmt.Fprintf(w, "  一键登录：%s\n", r.LoginURL)
	if r.TokenFile != "" {
		fmt.Fprintf(w, "  令牌已保存到 %s（权限 600），可用 tailproxy token 查看\n", r.TokenFile)
	}
	fmt.Fprintf(w, "  本进程运行期间令牌一直有效，不会过期；重启后会生成新令牌。如需固定令牌，设置 panel.auth_token_env 指向的环境变量（至少 %d 个字符）。\n\n", panel.MinTokenLen)
}
