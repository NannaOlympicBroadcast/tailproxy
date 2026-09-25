package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	tscli "tailscale.com/cmd/tailscale/cli"
)

// riskyTS are tailscale commands that change the main node tailproxy
// depends on (relays and the device list go through it).
var riskyTS = map[string]string{
	"down":   "会断开 tailproxy 的主节点：中继出口和 tailnet 访问都会中断，直到执行 tpctl ts up",
	"logout": "会注销 tailproxy 的主节点：需要重新登录（面板「出口」页或 tpctl ts up）",
	"switch": "会把主节点切换到另一个账号 / tailnet：出口配置里的设备名可能都找不到了",
	"up":     "会修改主节点的偏好设置；给主节点设出口节点会让中继流量也走那个出口",
	"set":    "会修改主节点的偏好设置；给主节点设出口节点会让中继流量也走那个出口",
}

// runTS runs the official tailscale CLI against tailproxy's main node.
func runTS(g globals, args []string) error {
	if len(args) > 0 {
		if warn, ok := riskyTS[args[0]]; ok && !g.yes && !isHelp(args) {
			return fmt.Errorf("tpctl ts %s %s；确认要执行请加 --yes：tpctl --yes ts %s", args[0], warn, strings.Join(args, " "))
		}
	}
	sock := g.paths.LocalAPI
	if st, err := g.paths.Running(); err == nil && st != nil && st.LocalAPI != "" {
		sock = st.LocalAPI
	} else if runtime.GOOS == "windows" {
		// The pipe name is random and only recorded in the state file.
		return fmt.Errorf("找不到 tailproxy 主节点的 LocalAPI 命名管道：tailproxy 没有运行，或状态目录不对（%s）", g.paths.Dir)
	}
	if !strings.HasPrefix(sock, `\\.\pipe\`) {
		if _, err := os.Stat(sock); err != nil {
			return fmt.Errorf("找不到 tailproxy 主节点的 LocalAPI 套接字 %s：tailproxy 没有运行，或不是以当前用户运行（%v）", sock, err)
		}
	}
	return tscli.Run(append([]string{"--socket=" + sock}, args...))
}

func isHelp(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "help" {
			return true
		}
	}
	return false
}
