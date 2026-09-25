package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
)

// Command describes one tpctl command. The same table drives dispatch,
// the usage text and `tpctl schema commands`.
type Command struct {
	Name     string   `json:"name"`
	Args     []string `json:"args,omitempty"`
	Flags    []Flag   `json:"flags,omitempty"`
	Summary  string   `json:"summary"`
	Mutates  bool     `json:"mutates"`             // changes tailproxy or the tailnet
	APIPaths []string `json:"api_paths,omitempty"` // REST endpoints it uses
	run      func(g globals, args []string) error
}

// Flag is one command flag.
type Flag struct {
	Name    string `json:"name"`
	Type    string `json:"type"` // string | bool
	Summary string `json:"summary"`
}

var commands []*Command

func init() {
	commands = []*Command{
		{Name: "status", Summary: "tailproxy 各组件状态（面板、规则、出口管理器、透明捕获、DNS…）", APIPaths: []string{"GET /api/v1/status"}, run: cmdStatus},
		{Name: "egress list", Summary: "已配置的出口及运行状态（出口节点 / 中继 / 出口组）", APIPaths: []string{"GET /api/v1/egress"}, run: cmdEgressList},
		{Name: "egress add", Args: []string{"<name>"}, Mutates: true, Summary: "新增出口（二选一：--exit-node 或 --relay）；中继令牌从标准输入读取",
			Flags:    []Flag{{"exit-node", "string", "出口节点：主机名 / MagicDNS 名 / 100.x IP / StableID"}, {"relay", "string", "中继地址 host:port（对方运行 tailproxy relay）"}, {"token-stdin", "bool", "从标准输入读中继令牌并保存"}},
			APIPaths: []string{"GET /api/v1/egress", "PUT /api/v1/egress", "PUT /api/v1/egress/{name}/relay-token"}, run: cmdEgressAdd},
		{Name: "egress set", Args: []string{"<name>"}, Mutates: true, Summary: "修改出口的出口节点或中继地址",
			Flags:    []Flag{{"exit-node", "string", "新的出口节点"}, {"relay", "string", "新的中继地址 host:port"}},
			APIPaths: []string{"GET /api/v1/egress", "PUT /api/v1/egress"}, run: cmdEgressSet},
		{Name: "egress rm", Args: []string{"<name>"}, Mutates: true, Summary: "删除出口（出口节点设备会注销；中继令牌会删除）；仍被规则引用时失败",
			APIPaths: []string{"GET /api/v1/egress", "PUT /api/v1/egress"}, run: cmdEgressRm},
		{Name: "egress relay-token", Args: []string{"<name>"}, Mutates: true, Summary: "从标准输入读取并保存中继出口的令牌（不经过命令行参数，避免出现在进程列表里）",
			APIPaths: []string{"PUT /api/v1/egress/{name}/relay-token"}, run: cmdRelayToken},
		{Name: "rules list", Summary: "规则列表（首条命中）", APIPaths: []string{"GET /api/v1/rules"}, run: cmdRulesList},
		{Name: "rules test", Args: []string{"<domain|ip>", "[port]"}, Summary: "测试一个域名或 IP（可带端口）会命中哪条规则、走哪个出口",
			APIPaths: []string{"POST /api/v1/rules/test"}, run: cmdRulesTest},
		{Name: "devices", Summary: "主节点看到的 tailnet 设备（在线状态、出口节点、被哪个出口使用）", APIPaths: []string{"GET /api/v1/tailnet"}, run: cmdDevices},
		{Name: "conns", Summary: "活动连接、最近连接和域名可见度统计", Flags: []Flag{{"all", "bool", "同时列出最近结束的连接"}},
			APIPaths: []string{"GET /api/v1/connections"}, run: cmdConns},
		{Name: "reload", Mutates: true, Summary: "重新加载配置文件（出口变更立即生效）", APIPaths: []string{"POST /api/v1/config/reload"}, run: cmdReload},
		{Name: "config", Summary: "当前生效的配置（JSON）", APIPaths: []string{"GET /api/v1/config"}, run: cmdConfig},
		{Name: "ts", Args: []string{"<tailscale 子命令...>"}, Summary: "内置的官方 tailscale 客户端，操作 tailproxy 的主节点（status / ping / ip / whois / netcheck / exit-node list …）；down / logout / up / set / switch 需要 --yes", run: runTS},
		{Name: "schema", Args: []string{"config|api|commands"}, Summary: "输出 JSON Schema（配置文件）、OpenAPI（REST API）或命令清单（JSON）", run: cmdSchema},
		{Name: "version", Summary: "版本", run: func(globals, []string) error { fmt.Println(version); return nil }},
	}
}

var version = "dev"

// lookup finds the longest command name matching the start of args.
func lookup(args []string) (*Command, []string) {
	var best *Command
	n := 0
	for _, c := range commands {
		parts := strings.Fields(c.Name)
		if len(parts) <= len(args) && len(parts) > n && strings.Join(args[:len(parts)], " ") == c.Name {
			best, n = c, len(parts)
		}
	}
	if best == nil && len(args) > 0 && args[0] == "egress" { // `tpctl egress` alone
		return lookup([]string{"egress", "list"})
	}
	if best == nil && len(args) > 0 && args[0] == "rules" {
		return lookup(append([]string{"rules", "list"}, args[1:]...))
	}
	if best == nil {
		return nil, args
	}
	return best, args[n:]
}

func usageText() string {
	var b strings.Builder
	b.WriteString("用法：tpctl [--state-dir DIR] [--json] [--yes] <命令> [参数]\n\n")
	b.WriteString("操作本机正在运行的 tailproxy；tpctl ts 内置官方 tailscale 客户端，直接操作 tailproxy 已登录的主节点，\n本机不需要再安装 tailscale（也不会多出一台 tailnet 设备）。\n\n命令：\n")
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	for _, c := range commands {
		fmt.Fprintf(w, "  %s %s\t%s\n", c.Name, strings.Join(c.Args, " "), c.Summary)
		for _, f := range c.Flags {
			fmt.Fprintf(w, "      --%s\t%s\n", f.Name, f.Summary)
		}
	}
	w.Flush()
	b.WriteString(`
全局参数：
  --state-dir DIR   tailproxy 的状态目录（默认 ~/.lighthousepro），用来找到面板地址、令牌和主节点套接字
  --json            输出原始 JSON（适合脚本和 AI 代理）
  --yes             确认会影响主节点的 tailscale 操作（down / logout / up / set / switch）

也可以把 tpctl 链接成 tailscale：ln -s tpctl tailscale，之后 tailscale status 等同于 tpctl ts status。
`)
	return b.String()
}

func parseFlags(c *Command, args []string) (*flag.FlagSet, map[string]*string, map[string]*bool, error) {
	fs := flag.NewFlagSet(c.Name, flag.ContinueOnError)
	strs, bools := map[string]*string{}, map[string]*bool{}
	for _, f := range c.Flags {
		if f.Type == "bool" {
			bools[f.Name] = fs.Bool(f.Name, false, f.Summary)
		} else {
			strs[f.Name] = fs.String(f.Name, "", f.Summary)
		}
	}
	// Allow flags after positional arguments (tpctl egress add us --relay …).
	var pos, flags []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			name := strings.TrimLeft(strings.SplitN(a, "=", 2)[0], "-")
			if _, isStr := strs[name]; isStr && !strings.Contains(a, "=") && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		pos = append(pos, a)
	}
	if err := fs.Parse(flags); err != nil {
		return nil, nil, nil, err
	}
	fs.Parse(append(fs.Args(), pos...)) // positional args end up in fs.Args()
	return fs, strs, bools, nil
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// rawOr prints the raw JSON answer with --json, else calls pretty.
func rawOr(g globals, path string, pretty func(json.RawMessage) error) error {
	c, err := newClient(g)
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.do("GET", path, nil, &raw); err != nil {
		return err
	}
	if g.json {
		os.Stdout.Write(raw)
		fmt.Println()
		return nil
	}
	return pretty(raw)
}

func table(rows [][]string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, r := range rows {
		fmt.Fprintln(w, strings.Join(r, "\t"))
	}
	w.Flush()
}

func cmdStatus(g globals, _ []string) error {
	return rawOr(g, "/api/v1/status", func(raw json.RawMessage) error {
		var s struct {
			Version    string `json:"version"`
			Uptime     int64  `json:"uptime_seconds"`
			ConfigPath string `json:"config_path"`
			Rules      int    `json:"rules"`
			Components []struct{ Name, State, Detail string }
		}
		if err := json.Unmarshal(raw, &s); err != nil {
			return err
		}
		fmt.Printf("tailproxy %s，已运行 %s，配置 %s，%d 条规则\n\n", s.Version, fmtDur(s.Uptime), s.ConfigPath, s.Rules)
		rows := [][]string{{"组件", "状态", "说明"}}
		for _, c := range s.Components {
			rows = append(rows, []string{c.Name, c.State, c.Detail})
		}
		table(rows)
		return nil
	})
}

func fmtDur(sec int64) string {
	switch {
	case sec >= 86400:
		return fmt.Sprintf("%d 天 %d 小时", sec/86400, sec%86400/3600)
	case sec >= 3600:
		return fmt.Sprintf("%d 小时 %d 分", sec/3600, sec%3600/60)
	case sec >= 60:
		return fmt.Sprintf("%d 分 %d 秒", sec/60, sec%60)
	}
	return fmt.Sprintf("%d 秒", sec)
}

type egressResp struct {
	Configured []config.Egress `json:"configured"`
	Runtime    []struct {
		Name     string `json:"name"`
		Kind     string `json:"kind"`
		State    string `json:"state"`
		Detail   string `json:"detail"`
		Relay    string `json:"relay"`
		Selected string `json:"selected"`
		ExitNode *struct {
			Name   string `json:"name"`
			Online bool   `json:"online"`
		} `json:"exit_node"`
	} `json:"runtime"`
	Revision string `json:"revision"`
}

func cmdEgressList(g globals, _ []string) error {
	return rawOr(g, "/api/v1/egress", func(raw json.RawMessage) error {
		var e egressResp
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		if len(e.Configured) == 0 {
			fmt.Println("还没有出口。添加：tpctl egress add <名称> --relay <host:port> --token-stdin，或 --exit-node <设备>")
			return nil
		}
		rows := [][]string{{"名称", "类型", "目标", "状态", "说明"}}
		for _, c := range e.Configured {
			kind, dest := "出口节点", c.ExitNode
			switch {
			case c.Type != "":
				kind, dest = "组:"+c.Type, strings.Join(c.Members, ",")
			case c.Relay != "":
				kind, dest = "中继", c.Relay
			}
			state, detail := "未运行", ""
			for _, r := range e.Runtime {
				if r.Name == c.Name {
					state, detail = r.State, r.Detail
					if r.Selected != "" {
						detail = "当前使用 " + r.Selected
					}
				}
			}
			rows = append(rows, []string{c.Name, kind, dest, state, detail})
		}
		table(rows)
		return nil
	})
}

// editEgress reads the egress section, applies f and writes it back with
// the revision it was read at (the panel refuses concurrent edits).
func editEgress(g globals, f func(list []config.Egress) ([]config.Egress, error)) error {
	c, err := newClient(g)
	if err != nil {
		return err
	}
	var e egressResp
	if err := c.do("GET", "/api/v1/egress", nil, &e); err != nil {
		return err
	}
	list, err := f(e.Configured)
	if err != nil {
		return err
	}
	var out struct {
		Warning string `json:"warning"`
	}
	if err := c.do("PUT", "/api/v1/egress", map[string]any{"revision": e.Revision, "egress": list}, &out); err != nil {
		return err
	}
	if out.Warning != "" {
		fmt.Fprintln(os.Stderr, "警告："+out.Warning)
	}
	return nil
}

func oneName(c *Command, args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("用法：tpctl %s <名称>", c.Name)
	}
	return args[0], nil
}

func cmdEgressAdd(g globals, args []string) error {
	c, _ := lookup([]string{"egress", "add"})
	fs, s, b, err := parseFlags(c, args)
	if err != nil {
		return err
	}
	name, err := oneName(c, fs.Args())
	if err != nil {
		return err
	}
	exit, relayAddr := *s["exit-node"], *s["relay"]
	if (exit == "") == (relayAddr == "") {
		return errors.New("请指定 --exit-node 或 --relay 其中一个")
	}
	var tok string
	if *b["token-stdin"] {
		if relayAddr == "" {
			return errors.New("--token-stdin 只用于 --relay")
		}
		if tok, err = readSecret(); err != nil {
			return err
		}
	}
	err = editEgress(g, func(list []config.Egress) ([]config.Egress, error) {
		for _, e := range list {
			if e.Name == name {
				return nil, fmt.Errorf("出口 %s 已存在（修改用 tpctl egress set）", name)
			}
		}
		return append(list, config.Egress{Name: name, ExitNode: exit, Relay: relayAddr}), nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("已添加出口 %s\n", name)
	if tok != "" {
		return saveRelayToken(g, name, tok)
	}
	if relayAddr != "" {
		fmt.Printf("还需要中继令牌：在中继机器上执行 tailproxy relay token，然后 tpctl egress relay-token %s（从标准输入读取）\n", name)
	}
	return nil
}

func cmdEgressSet(g globals, args []string) error {
	c, _ := lookup([]string{"egress", "set"})
	fs, s, _, err := parseFlags(c, args)
	if err != nil {
		return err
	}
	name, err := oneName(c, fs.Args())
	if err != nil {
		return err
	}
	exit, relayAddr := *s["exit-node"], *s["relay"]
	if (exit == "") == (relayAddr == "") {
		return errors.New("请指定 --exit-node 或 --relay 其中一个")
	}
	err = editEgress(g, func(list []config.Egress) ([]config.Egress, error) {
		for i, e := range list {
			if e.Name == name {
				if e.Type != "" {
					return nil, fmt.Errorf("%s 是出口组，请在配置文件里修改成员", name)
				}
				list[i].ExitNode, list[i].Relay = exit, relayAddr
				if relayAddr == "" {
					list[i].RelayTokenEnv = ""
				}
				return list, nil
			}
		}
		return nil, fmt.Errorf("没有名为 %s 的出口", name)
	})
	if err == nil {
		fmt.Printf("出口 %s 已更新\n", name)
	}
	return err
}

func cmdEgressRm(g globals, args []string) error {
	c, _ := lookup([]string{"egress", "rm"})
	name, err := oneName(c, args)
	if err != nil {
		return err
	}
	err = editEgress(g, func(list []config.Egress) ([]config.Egress, error) {
		out := list[:0]
		found := false
		for _, e := range list {
			if e.Name == name {
				found = true
				continue
			}
			out = append(out, e)
		}
		if !found {
			return nil, fmt.Errorf("没有名为 %s 的出口", name)
		}
		return out, nil
	})
	if err == nil {
		fmt.Printf("已删除出口 %s\n", name)
	}
	return err
}

// readSecret reads one line from stdin (a pipe or a terminal).
func readSecret() (string, error) {
	if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprint(os.Stderr, "中继令牌（输入后回车）：")
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	tok := strings.TrimSpace(line)
	if tok == "" {
		return "", errors.New("没有读到令牌")
	}
	return tok, nil
}

func saveRelayToken(g globals, name, tok string) error {
	c, err := newClient(g)
	if err != nil {
		return err
	}
	if err := c.do("PUT", "/api/v1/egress/"+name+"/relay-token", map[string]string{"token": tok}, nil); err != nil {
		return err
	}
	fmt.Printf("出口 %s 的中继令牌已保存，正在连接中继\n", name)
	return nil
}

func cmdRelayToken(g globals, args []string) error {
	c, _ := lookup([]string{"egress", "relay-token"})
	name, err := oneName(c, args)
	if err != nil {
		return err
	}
	tok, err := readSecret()
	if err != nil {
		return err
	}
	return saveRelayToken(g, name, tok)
}

func cmdRulesList(g globals, _ []string) error {
	return rawOr(g, "/api/v1/rules", func(raw json.RawMessage) error {
		var r struct {
			Rules []config.Rule `json:"rules"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		rows := [][]string{{"#", "匹配条件", "目标"}}
		for i, x := range r.Rules {
			var cond []string
			add := func(k string, v []string) {
				if len(v) > 0 {
					cond = append(cond, k+"="+strings.Join(v, ","))
				}
			}
			add("domain", x.Domain)
			add("domain_suffix", x.DomainSuffix)
			add("domain_keyword", x.DomainKeyword)
			add("ip_cidr", x.IPCIDR)
			if len(x.Port) > 0 {
				var ps []string
				for _, p := range x.Port {
					ps = append(ps, strconv.Itoa(int(p)))
				}
				add("port", ps)
			}
			if x.Final != "" {
				cond = append(cond, "final")
			}
			rows = append(rows, []string{strconv.Itoa(i), strings.Join(cond, " "), x.Target()})
		}
		rows = append(rows, []string{"-", "（未命中任何规则）", "direct"})
		table(rows)
		return nil
	})
}

func cmdRulesTest(g globals, args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.New("用法：tpctl rules test <域名|IP> [端口]")
	}
	q := map[string]any{}
	if strings.ContainsAny(args[0], ":") || strings.Trim(args[0], "0123456789.") == "" {
		q["ip"] = args[0]
	} else {
		q["domain"] = args[0]
	}
	if len(args) == 2 {
		p, err := strconv.ParseUint(args[1], 10, 16)
		if err != nil {
			return fmt.Errorf("端口 %q 无效", args[1])
		}
		q["port"] = p
	}
	c, err := newClient(g)
	if err != nil {
		return err
	}
	var res struct {
		RuleIndex int    `json:"rule_index"`
		Target    string `json:"target"`
		Reason    string `json:"reason"`
	}
	if err := c.do("POST", "/api/v1/rules/test", q, &res); err != nil {
		return err
	}
	if g.json {
		return printJSON(res)
	}
	if res.RuleIndex < 0 {
		fmt.Printf("%s → %s（未命中任何规则）\n", args[0], res.Target)
		return nil
	}
	fmt.Printf("%s → %s（规则 #%d：%s）\n", args[0], res.Target, res.RuleIndex, res.Reason)
	return nil
}

func cmdDevices(g globals, _ []string) error {
	return rawOr(g, "/api/v1/tailnet", func(raw json.RawMessage) error {
		var t struct {
			Account struct {
				Main struct {
					State     string `json:"state"`
					LoginName string `json:"login_name"`
					AuthURL   string `json:"auth_url"`
				} `json:"main"`
			} `json:"account"`
			Peers []struct {
				Name      string   `json:"name"`
				IPs       []string `json:"tailscale_ips"`
				OS        string   `json:"os"`
				Online    bool     `json:"online"`
				ExitNode  bool     `json:"exit_node_option"`
				Tailproxy string   `json:"tailproxy"`
				UsedBy    []string `json:"used_by"`
				RelayFor  []string `json:"relay_for"`
			} `json:"peers"`
			PeersError string `json:"peers_error"`
		}
		if err := json.Unmarshal(raw, &t); err != nil {
			return err
		}
		m := t.Account.Main
		if m.State != "ready" {
			fmt.Printf("主节点：%s", m.State)
			if m.AuthURL != "" {
				fmt.Printf("，登录：%s", m.AuthURL)
			}
			fmt.Println()
			return nil
		}
		fmt.Printf("主节点已登录：%s\n\n", m.LoginName)
		rows := [][]string{{"设备", "IP", "系统", "在线", "出口节点", "tailproxy 用途"}}
		for _, p := range t.Peers {
			ip := ""
			if len(p.IPs) > 0 {
				ip = p.IPs[0]
			}
			var use []string
			if p.Tailproxy != "" {
				use = append(use, "设备:"+p.Tailproxy)
			}
			if len(p.UsedBy) > 0 {
				use = append(use, "出口节点:"+strings.Join(p.UsedBy, ","))
			}
			if len(p.RelayFor) > 0 {
				use = append(use, "中继:"+strings.Join(p.RelayFor, ","))
			}
			rows = append(rows, []string{strings.SplitN(p.Name, ".", 2)[0], ip, p.OS, yesNo(p.Online), yesNo(p.ExitNode), strings.Join(use, " ")})
		}
		table(rows)
		if t.PeersError != "" {
			fmt.Fprintln(os.Stderr, "读取设备出错："+t.PeersError)
		}
		return nil
	})
}

func yesNo(b bool) string {
	if b {
		return "是"
	}
	return "-"
}

func cmdConns(g globals, args []string) error {
	c, _ := lookup([]string{"conns"})
	_, _, b, err := parseFlags(c, args)
	if err != nil {
		return err
	}
	return rawOr(g, "/api/v1/connections", func(raw json.RawMessage) error {
		type conn struct {
			Host      string `json:"host"`
			Port      int    `json:"port"`
			Inbound   string `json:"inbound"`
			DomainSrc string `json:"domain_source"`
			Target    string `json:"target"`
			Via       string `json:"via"`
			Up        int64  `json:"up"`
			Down      int64  `json:"down"`
			Error     string `json:"error"`
		}
		var s struct {
			Active []conn `json:"active"`
			Recent []conn `json:"recent"`
			Total  int    `json:"total"`
			Failed int    `json:"failed"`
			Bypass struct {
				Transparent, FakeIP, Sniffed, Learned, Unknown, ECH, DoHBlocked int64
			} `json:"bypass"`
		}
		if err := json.Unmarshal(raw, &s); err != nil {
			return err
		}
		fmt.Printf("活动 %d，累计 %d，失败 %d\n", len(s.Active), s.Total, s.Failed)
		if bp := s.Bypass; bp.Transparent > 0 {
			fmt.Printf("透明捕获 %d：FakeIP %d，SNI/Host %d，学习 %d，未知 %d；ECH %d，拦截 DoH %d\n", bp.Transparent, bp.FakeIP, bp.Sniffed, bp.Learned, bp.Unknown, bp.ECH, bp.DoHBlocked)
		}
		list := s.Active
		if *b["all"] {
			list = append(list, s.Recent...)
		}
		rows := [][]string{{"目的地", "入口", "目标", "经由", "上行", "下行", "错误"}}
		for _, x := range list {
			rows = append(rows, []string{fmt.Sprintf("%s:%d", x.Host, x.Port), x.Inbound, x.Target, x.Via, strconv.FormatInt(x.Up, 10), strconv.FormatInt(x.Down, 10), x.Error})
		}
		fmt.Println()
		table(rows)
		return nil
	})
}

func cmdReload(g globals, _ []string) error {
	c, err := newClient(g)
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.do("POST", "/api/v1/config/reload", nil, &raw); err != nil {
		return err
	}
	if g.json {
		os.Stdout.Write(raw)
		fmt.Println()
		return nil
	}
	fmt.Println("配置已重新加载")
	return nil
}

func cmdConfig(g globals, _ []string) error {
	return rawOr(g, "/api/v1/config", func(raw json.RawMessage) error {
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		return printJSON(v)
	})
}

// sortedCommands is for schema output.
func sortedCommands() []*Command {
	out := append([]*Command(nil), commands...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
