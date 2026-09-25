package main

import (
	"fmt"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/schema"
)

// cmdSchema prints machine-readable descriptions. None of them needs a
// running tailproxy.
func cmdSchema(g globals, args []string) error {
	what := "commands"
	if len(args) > 0 {
		what = args[0]
	}
	switch what {
	case "config":
		return printJSON(schema.Config())
	case "api", "openapi":
		return printJSON(schema.API())
	case "commands":
		return printJSON(map[string]any{
			"tool":        "tpctl",
			"version":     version,
			"description": "操作本机 tailproxy；ts 子命令内置官方 tailscale 客户端，操作 tailproxy 的主节点",
			"global_flags": []Flag{
				{"state-dir", "string", "tailproxy 状态目录（默认 ~/.lighthousepro）"},
				{"json", "bool", "输出原始 JSON"},
				{"yes", "bool", "确认会影响主节点的 tailscale 操作"},
			},
			"commands": sortedCommands(),
			"secrets":  "中继令牌只从标准输入读取（egress add --token-stdin、egress relay-token），不接受命令行参数",
		})
	}
	return fmt.Errorf("tpctl schema config|api|commands（得到 %q）", what)
}
