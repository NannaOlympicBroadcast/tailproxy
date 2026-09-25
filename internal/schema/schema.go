// Package schema describes tailproxy's interfaces for tools and agents: a
// JSON Schema of the config file, generated from the config structs (so it
// cannot drift from the parser), and an OpenAPI document of the REST API.
package schema

import (
	"reflect"
	"strings"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
)

// meta adds what reflection cannot know, keyed by dotted YAML path
// ("egress[].relay").
type meta struct {
	desc    string
	enum    []string
	format  string
	pattern string
	def     any
}

var fields = map[string]meta{
	"":                               {desc: "tailproxy 配置文件（YAML）。未知字段会被拒绝。"},
	"tailnet":                        {desc: "Tailscale 控制面与主节点"},
	"tailnet.hostname":               {desc: "主节点主机名", def: "tailproxy"},
	"tailnet.control_url":            {desc: "控制面地址（Headscale 等自建控制面时填写）", format: "uri"},
	"tailnet.auth_key_env":           {desc: "存放 auth key 的环境变量名（不把密钥写进文件）", def: "TS_AUTHKEY"},
	"tailnet.advertise_tags":         {desc: "新节点申请的 ACL 标签，如 tag:tailproxy"},
	"tailnet.state_dir":              {desc: "tsnet 状态目录（默认在 tailproxy 状态目录下）"},
	"egress":                         {desc: "出口：出口节点槽位、中继或出口组。名称可在规则里引用。"},
	"egress[].name":                  {desc: "出口名称（规则中的目标）", pattern: `^[a-z0-9][a-z0-9-]{0,39}$`},
	"egress[].exit_node":             {desc: "出口节点：主机名 / MagicDNS 名 / 100.x IP / StableID（与 relay 二选一）"},
	"egress[].relay":                 {desc: "中继地址 host:port（对方运行 tailproxy relay；与 exit_node 二选一）"},
	"egress[].relay_token_env":       {desc: "中继令牌的环境变量名；不设置时令牌保存在状态目录 relay/<name>.token"},
	"egress[].type":                  {desc: "设置后为出口组", enum: []string{"fallback", "latency"}},
	"egress[].members":               {desc: "出口组成员（出口节点槽位或中继的名称）"},
	"egress[].health_check":          {desc: "出口组健康检查"},
	"egress[].health_check.url":      {desc: "经成员访问的检查地址", format: "uri"},
	"egress[].health_check.interval": {desc: "检查间隔（Go duration，至少 5s）", pattern: `^[0-9]+(ms|s|m|h)$`},
	"egress[].doh":                   {desc: "该出口的 DoH 地址（必须是 https://<IP>/...），覆盖 dns.per_egress_doh", format: "uri"},
	"dns":                            {desc: "DNS（透明捕获时生效）"},
	"dns.mode":                       {desc: "fakeip：命中规则的域名返回 FakeIP；real：一律返回真实 IP", enum: []string{"fakeip", "real"}, def: "fakeip"},
	"dns.fakeip":                     {desc: "FakeIP 地址池"},
	"dns.fakeip.inet4":               {desc: "IPv4 地址池", def: "198.18.0.0/15"},
	"dns.fakeip.inet6":               {desc: "IPv6 地址池", def: "fc00::/18"},
	"dns.per_egress_doh":             {desc: "出口内解析域名用的 DoH（https://<IP>/...）", def: "https://1.1.1.1/dns-query", format: "uri"},
	"dns.direct_upstream":            {desc: "直连 / 转发用的上游：system（Linux/macOS 读 resolv.conf，Windows 读网卡 DNS），或逗号分隔的 IP[:port]", def: "system"},
	"dns.anti_bypass":                {desc: "DoH / ECH 旁路对策（DESIGN §4.8）"},
	"dns.anti_bypass.canary":         {desc: "use-application-dns.net 返回 NXDOMAIN（默认开）", def: true},
	"dns.anti_bypass.block_doh":      {desc: "封堵公开 DoH 端点：域名 NXDOMAIN、SNI 拒绝、IP 的 443 端口 RST（默认开）", def: true},
	"dns.anti_bypass.doh_lists":      {desc: "DoH 域名 / IP 名单地址（每 12 小时更新）"},
	"dns.anti_bypass.doh_allow":      {desc: "DoH 白名单（域名或 IP）"},
	"dns.anti_bypass.block_dot_doq":  {desc: "拒绝 TCP/UDP 853（DoT / DoQ，默认开）", def: true},
	"dns.anti_bypass.strip_ech":      {desc: "删除 HTTPS/SVCB 应答中的 ech 参数；auto 仅在 real 模式", enum: []string{"auto", "on", "off", "true", "false"}, def: "auto"},
	"dns.anti_bypass.learn_rule_ips": {desc: "规则域名预解析 + 从 DNS 应答学习地址（默认开）", def: true},
	"dns.unknown_domain":             {desc: "透明捕获时拿不到域名的连接：ip_rules_only、reject 或 egress:<名称>", pattern: `^(ip_rules_only|reject|egress:[a-z0-9-]+)$`, def: "ip_rules_only"},
	"capture":                        {desc: "流量入口"},
	"capture.mode":                   {desc: "auto / socks：只开 SOCKS5；tproxy：Linux nftables 透明捕获（需 root）；tun：TUN 设备 + 用户态协议栈（Linux / macOS / Windows，需 root / 管理员）", enum: []string{"auto", "socks", "tproxy", "tun"}, def: "auto"},
	"capture.scope":                  {desc: "捕获范围：selective 只接管 FakeIP 与规则 ip_cidr；all 接管全部流量（tproxy：全部 TCP；tun：默认路由进入 TUN），排除网段直连", enum: []string{"selective", "all"}, def: "selective"},
	"capture.tun_name":               {desc: "tun 模式的设备名", def: "tailproxy0"},
	"capture.tun_address":            {desc: "tun 设备地址（IPv4，/30 或更大）；下一个地址是协议栈内的 DNS，系统 DNS 指向它", def: "172.19.0.1/30"},
	"capture.tun_system_dns":         {desc: "tun 模式运行时把系统 DNS 指向协议栈内的 DNS，退出时恢复（Linux 用 systemd-resolved，macOS 用 networksetup，Windows 设置 TUN 网卡 DNS）；off 不改系统 DNS", enum: []string{"auto", "off"}, def: "auto"},
	"capture.udp":                    {desc: "tproxy 的 UDP：block 让发往 FakeIP 的 UDP 立即不可达，应用改用 TCP；proxy 按规则代理 UDP（如 QUIC），中继出口不能承载 UDP，这类流量会被丢弃", enum: []string{"block", "proxy"}, def: "block"},
	"capture.exclude_cidr":           {desc: "永不捕获的网段"},
	"capture.socks_listen":           {desc: "SOCKS5 入口（只能是回环地址），如 127.0.0.1:1080"},
	"capture.tproxy_port":            {desc: "TPROXY 端口", def: 7893},
	"capture.dns_listen":             {desc: "DNS 前端监听地址；非回环地址时同时劫持局域网 DNS", def: "127.0.0.1:1053"},
	"panel":                          {desc: "Web 面板与 REST API"},
	"panel.listen":                   {desc: "监听地址", def: "127.0.0.1:7708"},
	"panel.tailnet":                  {desc: "同时在主节点 tailnet 地址上开放面板（与 panel.listen 同端口，仍需令牌，受 Tailscale ACL 控制；修改需重启）"},
	"panel.auth_token_env":           {desc: "面板令牌的环境变量名；不设置时令牌持久化在状态目录"},
	"wireguard_ports":                {desc: "tsnet WireGuard 端口范围（保留）"},
	"rules":                          {desc: "规则，按顺序首条命中；未命中时 direct。同一条规则内域名类条件与 ip_cidr 为「或」，port 为「且」。"},
	"rules[].domain":                 {desc: "完整域名"},
	"rules[].domain_suffix":          {desc: "域名后缀（含自身）"},
	"rules[].domain_keyword":         {desc: "域名包含的关键词"},
	"rules[].ip_cidr":                {desc: "IP 网段"},
	"rules[].outer_sni":              {desc: "ECH 外层 SNI（服务商公共名，如 cloudflare-ech.com），后缀匹配。只在 ClientHello 带 ECH、又查不到真实域名时参与匹配；普通域名条件不会匹配外层名（DESIGN §4.8 L4）"},
	"rules[].port":                   {desc: "目的端口"},
	"rules[].egress":                 {desc: "目标：出口名称，或 direct / reject / tailnet（与 final 二选一）"},
	"rules[].final":                  {desc: "兜底目标，只能出现在最后一条"},
}

// Config returns the JSON Schema (draft 2020-12) of the config file.
func Config() map[string]any {
	s := typeSchema(reflect.TypeOf(config.Config{}), "")
	s["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	s["$id"] = "https://github.com/NannaOlympicBroadcast/tailproxy/schema/config.json"
	s["title"] = "tailproxy config"
	// Cross-field rules the parser also enforces.
	eg := s["properties"].(map[string]any)["egress"].(map[string]any)["items"].(map[string]any)
	eg["required"] = []string{"name"}
	eg["not"] = map[string]any{"required": []string{"exit_node", "relay"}}
	ru := s["properties"].(map[string]any)["rules"].(map[string]any)["items"].(map[string]any)
	ru["oneOf"] = []any{
		map[string]any{"required": []string{"egress"}},
		map[string]any{"required": []string{"final"}},
	}
	return s
}

func typeSchema(t reflect.Type, path string) map[string]any {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	s := map[string]any{}
	switch t.Kind() {
	case reflect.Struct:
		props := map[string]any{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if name == "" || name == "-" || !f.IsExported() {
				continue
			}
			p := name
			if path != "" {
				p = path + "." + name
			}
			props[name] = typeSchema(f.Type, p)
		}
		s["type"] = "object"
		s["properties"] = props
		s["additionalProperties"] = false
	case reflect.Slice:
		s["type"] = "array"
		s["items"] = typeSchema(t.Elem(), path+"[]")
	case reflect.String:
		s["type"] = "string"
	case reflect.Bool:
		s["type"] = "boolean"
	case reflect.Uint16:
		s["type"], s["minimum"], s["maximum"] = "integer", 0, 65535
	case reflect.Int, reflect.Int64, reflect.Uint32:
		s["type"] = "integer"
	}
	m := fields[strings.TrimSuffix(path, "[]")]
	if m.desc != "" {
		s["description"] = m.desc
	}
	if m.enum != nil {
		s["enum"] = m.enum
	}
	if m.format != "" {
		s["format"] = m.format
	}
	if m.pattern != "" {
		s["pattern"] = m.pattern
	}
	if m.def != nil {
		s["default"] = m.def
	}
	return s
}

// Documented reports whether every config field has a description (tests).
func undocumented(t reflect.Type, path string, out *[]string) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
		if t.Kind() == reflect.Slice {
			path += "[]"
		}
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		p := name
		if path != "" {
			p = path + "." + name
		}
		key := p
		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if _, ok := fields[strings.TrimSuffix(key, "[]")]; !ok {
			*out = append(*out, key)
		}
		undocumented(f.Type, p, out)
	}
}
