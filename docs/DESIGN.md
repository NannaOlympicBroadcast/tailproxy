# tailproxy 设计文档（v0.1 草案）

> 目标：基于 Tailscale 的跨平台透明代理插件。按**域名关键词 / 域名后缀 / IP 地址（CIDR）**匹配规则，把每条连接分流到**不同的 Tailscale 出口节点（exit node）**，其余流量直连或走默认出口。

**标注约定**
- `[来源 Sx]`：该论点来自文末「参考来源」表中的公开资料（官方文档、源码或 GitHub issue）。
- `〔无来源·设计决策〕`：本方案自身的设计选择，没有外部来源支撑。
- `〔无来源·待验证〕`：尚未查到可靠公开资料的技术假设，必须在 PoC 阶段验证后才能采纳。

---

## 1. 背景与问题

### 1.1 Tailscale 原生能力的限制

| 事实 | 来源 |
|---|---|
| 使用出口节点相当于把默认路由（`0.0.0.0/0`、`::/0`）交给该节点，行为和传统全局 VPN 一样 | [来源 S1] |
| 官方文档在各平台都只描述选择「一个」出口节点，**没有**同时使用多个出口节点的机制 | [来源 S1] |
| 想只分流部分流量，官方给出的方案是子网路由器（subnet router）或 App Connector，而不是多出口节点 | [来源 S1] |
| 客户端使用出口节点前，ACL 必须授予 `autogroup:internet`；只放行到出口节点设备本身的连接，**不等于**允许把它当作上网网关 | [来源 S1] |
| 社区多次提出「按域名/IP 走不同出口」「同时用多个出口节点」的功能请求：#3648（已关闭，标签为低可能性 L1、低优先级 P1）、#7766、#15521、#18669、#19901 | [来源 S8][来源 S9] |

### 1.2 App Connector 为什么不够用

| 事实 | 来源 |
|---|---|
| App Connector 先用 DoH 把配置的域名解析成 IP，再把这些 IP 作为路由通告到 tailnet | [来源 S3] |
| 连接器必须是一台 Linux 设备，需要公网 IP、开启 IP 转发，并在策略文件中打好标签 | [来源 S3] |
| 如果多个 FQDN 解析到同一 IP，只要其中一个是连接器目标，这些 FQDN 的连接**全都**会经过该连接器（存在误伤） | [来源 S3] |
| 官方文档没有提到通配符或关键词匹配 | [来源 S3] |

结论：App Connector 做的是「管理员集中配置的域名 → 某台连接器」，不支持客户端自己定义关键词规则，也不能选择任意出口节点。这正是本项目要补上的部分。〔无来源·设计决策〕

### 1.3 可行性的关键依据

| 事实 | 来源 |
|---|---|
| `tsnet` 是 Go 库，在进程内运行完整的 Tailscale 节点，使用 gVisor 用户态 TCP/IP 栈，**不需要 root**，一个二进制里可以运行**多个相互独立的节点** | [来源 S2][来源 S4] |
| 每个 `tsnet.Server` 都是独立节点，需要各自的 `Dir` 和 `Hostname` | [来源 S2][来源 S4] |
| 通过 `Server.LocalClient()` 的 `EditPrefs` 设置 `ExitNodeID` 后，这个 tsnet 节点 `Server.Dial` 到 tailnet 之外地址的流量会走该出口节点，tailnet 内部连接不受影响 | [来源 S4] |
| sing-box（1.12.0 起）已经有 `tailscale` endpoint，支持 `exit_node`、`state_directory`、`udp_timeout`（默认 5m）等字段；它的实现就是用 tsnet 加 `EditPrefs` 设置出口节点 | [来源 S5][来源 S6] |

**核心思路**：一个出口节点对应一个进程内的 tsnet 节点（下称「Egress 槽位」）。有 N 个出口，就在同一进程里跑 N 个 tsnet 节点，每个节点固定一个 `ExitNodeID`。这样就绕过了「每台设备同时只能用一个出口节点」的限制，再由本地的规则引擎决定每条连接交给哪个槽位。〔无来源·设计决策，技术基础见上表〕

---

## 2. 目标与非目标

**目标**〔无来源·设计决策〕
1. 规则类型：`domain_keyword`（子串）、`domain_suffix`（按标签边界匹配后缀）、`domain`（完全匹配）、`domain_regex`（可选）、`ip_cidr`（IPv4/IPv6）、`port`。
2. 规则目标：某个出口节点、出口组（故障转移或延迟优选）、`direct`（直连）、`tailnet`（交给系统 Tailscale）、`reject`（拒绝）。
3. 透明代理：应用无需配置代理。同时提供 SOCKS5/HTTP 入口作为兜底和调试手段。
4. 支持 Linux（含 OpenWrt 等路由器）、macOS、Windows、Android、iOS。
5. 防止 DNS 泄漏：命中某个出口的域名，也通过同一出口解析。

**非目标**（v1 不做）〔无来源·设计决策〕
- 修改 Tailscale 官方客户端或控制平面。
- 让本机充当出口节点（advertise exit node）。
- 按进程分流（放到 v2，各平台 API 差异较大）。

---

## 3. 总体架构

```
┌──────────────────────── tailproxy 进程 ─────────────────────────┐
│                                                                  │
│  ① 捕获层 Capture            ② 连接元数据        ③ 规则引擎       │
│  ┌──────────────────┐        ┌────────────┐     ┌────────────┐   │
│  │ TUN (gVisor栈)   │──────▶│ 嗅探 SNI/   │───▶│ keyword AC  │   │
│  │ Linux TPROXY     │ TCP/UDP│ Host/QUIC   │     │ suffix trie │   │
│  │ SOCKS5 / HTTP    │  流    │ FakeIP 反查 │     │ CIDR 前缀树 │   │
│  └──────────────────┘        │ DNS 缓存    │     └─────┬──────┘   │
│           ▲                  └────────────┘           │ 目标       │
│           │ DNS 劫持                                    ▼           │
│  ┌──────────────────┐                        ④ 出口管理器 Egress   │
│  │ ⑤ DNS 模块        │◀──── 按出口解析 ─────  ┌──────────────────┐ │
│  │ FakeIP / 分流解析 │                        │ slot "jp" tsnet#1│─┼─▶ 出口节点 A ─▶ Internet
│  └──────────────────┘                        │ slot "us" tsnet#2│─┼─▶ 出口节点 B ─▶ Internet
│                                               │ slot "ts" tsnet#0│─┼─▶ tailnet 内部（可选）
│  ⑥ 控制面：配置/热重载/本地 API/CLI/指标       │ direct 系统拨号   │─┼─▶ 本地网络
│                                               └──────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### 3.1 一条 TCP 连接的完整路径（FakeIP 模式）〔无来源·设计决策〕
1. 应用查询 `chat.openai.com`，查询被 DNS 模块劫持，返回一个 FakeIP（如 `198.18.0.7`），同时记录 `198.18.0.7 ↔ chat.openai.com`。
2. 应用连接 `198.18.0.7:443`。TUN 把这个 SYN 交给用户态 gVisor 栈，栈在本地完成握手，得到一个 `net.Conn`。
3. 元数据阶段：通过 FakeIP 反查得到域名，读取首包嗅探 TLS SNI 进行校验或覆盖。
4. 规则引擎按顺序匹配，`domain_keyword: openai` 命中，目标为 `us`。
5. 出口管理器用 `us` 槽位对应的 tsnet 节点，经由这个出口做 DoH，把 `chat.openai.com` 解析为真实 IP，然后调用 `Dial` 发起连接。因为这个节点设置了 `ExitNodeID`，流量从出口节点 B 出去 [来源 S4]。
6. 双向拷贝数据，记录统计信息。

---

## 4. 模块设计

### 4.1 捕获层（Capture）

| 平台 | 主方案 | 依据 / 约束 |
|---|---|---|
| Linux / OpenWrt | nftables TPROXY（可以拿到原始目的地址，不依赖 NAT）；TUN 作为备选 | TPROXY 依赖 `IP_TRANSPARENT` 套接字选项和 fwmark 策略路由，iptables 与 nftables 都支持 [来源 S10] |
| Windows | Wintun TUN | Wintun 是 Windows 内核下的极简 TUN 驱动，最初为 WireGuard 开发；源码是 GPL-2.0，预编译的签名 DLL 使用更宽松的许可 [来源 S11] |
| macOS | 以 root 守护进程运行 utun TUN（开发者版）；上架版本使用 `NEPacketTunnelProvider` | `NEPacketTunnelProvider` 通过 `packetFlow` 提供虚拟网卡，并能设置需要进入隧道和排除在隧道外的网段 [来源 S12]；`NETransparentProxyProvider` 按 flow 接管流量，但会忽略它自身设置里的 DNS 配置 [来源 S13]，因此不作为主方案〔无来源·设计决策〕 |
| Android | `VpnService` | 同一时间只能有一个 VPN 连接，新 VPN 建立时旧的会被停用 [来源 S14]；Tailscale 官方也说明 iOS/Android 同时只能运行一个 VPN [来源 S7] |
| iOS | `NEPacketTunnelProvider` | 同上 [来源 S7][来源 S12] |
| 所有平台 | SOCKS5 / HTTP 本地代理入口 | 用于非透明场景、调试和 CI〔无来源·设计决策〕 |

**与系统 Tailscale 客户端共存（桌面端）**
- 排除 tailnet 网段：`100.64.0.0/10` 和 `fd7a:115c:a1e0::/48` 不进入捕获，继续交给系统 Tailscale 处理 [来源 S7]。
- 系统 Tailscale **不能**同时开启出口节点：官方说明出口节点的工作方式和传统 VPN 一样，只支持同时运行一个 VPN [来源 S7]。
- 移动端：因为只能有一个 VPN [来源 S7][来源 S14]，tailproxy 本身**替代**官方 App，由内置的 `ts` 槽位（不设置出口的 tsnet 节点）提供 tailnet 访问。〔无来源·设计决策〕

**防止回环（关键）**：tsnet 节点底层的 WireGuard 和 DERP 流量不能再次被 TUN 或 TPROXY 捕获。
- Linux：Tailscale 自己的 `netns` 包会给套接字打 `SO_MARK` 绕行标记（`LinuxBypassMark = 0x80000`），不支持时退回 `SO_BINDTODEVICE` [来源 S15][来源 S16]。nft 规则直接放行带这个标记的包。〔无来源·待验证：在 tsnet 进程内是否同样生效〕
- macOS / Windows：把底层套接字绑定到物理网卡（`IP_BOUND_IF` / `IP_UNICAST_IF`）。〔无来源·待验证〕
- 风险：sing-box 使用的是自己的 Tailscale 分支（`github.com/sagernet/tailscale`），并向 tsnet 注入了自定义的底层 `DialContext` [来源 S6]。上游 tsnet 可能没有这个注入点，届时需要维护一个小补丁或 fork。〔无来源·待验证〕

### 4.2 连接元数据（域名获取）

域名来源按优先级排列〔无来源·设计决策〕：
1. **协议嗅探**：TLS ClientHello 中的 SNI、HTTP `Host` 头、QUIC Initial 中的 SNI（sing-box 采用同样的嗅探思路 [来源 S17]）。
2. **FakeIP 反查**：默认地址池 `198.18.0.0/15` 与 sing-box 相同 [来源 S18]，这个网段是 RFC 2544 保留的基准测试地址 [来源 S19]；IPv6 地址池使用 `fc00::/18` [来源 S18]。
3. **DNS 应答缓存（真实 IP 模式）**：拦截 DNS 应答，建立 `IP → 域名` 的 LRU 映射。多个域名共用一个 IP 时存在歧义（和 App Connector 的共享 IP 问题同源 [来源 S3]），因此嗅探结果优先。

嗅探超时（例如 300ms）后仍拿不到域名，就只按 IP 规则匹配。〔无来源·设计决策〕

### 4.3 规则引擎〔无来源·设计决策〕

- **语义**：按配置顺序**首条命中**，最后以 `final` 兜底。
- **匹配数据结构**：
  - `domain_keyword`：把所有关键词编进一个 Aho-Corasick 自动机，匹配复杂度 O(|域名|)，与关键词数量无关。
  - `domain_suffix`：把域名按标签反转后放入 trie，例如 `com.openai`。`openai.com` 能命中 `api.openai.com`，但不会命中 `notopenai.com`。
  - `ip_cidr`：最长前缀匹配树，可选用 MIT 许可的 `gaissmai/bart` [来源 S20]。
- **编译期优化**：连续的同类规则合并成一个匹配器，但仍然保留「首条命中」的语义（记录每个模式对应的规则序号，取最小值）。
- **规则集（Rule Provider）**：支持本地文件或远程 URL（带定时刷新和校验），这是本项目「插件化」的第一个扩展点。
- 关键词统一在小写化、去掉末尾 `.` 后的 FQDN 上匹配，Punycode 按原样匹配。

### 4.4 出口管理器（Egress）

- **槽位 = 一个 tsnet 节点 + 一个固定的出口节点**。启动时 `Up()`，再通过 `LocalClient().EditPrefs` 设置 `ExitNodeID` [来源 S4]；sing-box 的做法是先校验对端的 `ExitNodeOption`，再写入偏好 [来源 S6]，本项目沿用。
- 出口节点可以用主机名、`100.x` IP 或 StableID 指定，启动时从 `Status().Peer` 解析成 StableID。
- **出口组**：`fallback`（健康检查失败时切换到下一个）和 `latency`（选延迟最低的）。
- **每个槽位各自的 DNS**：命中某槽位的域名，通过该槽位的 `Dial` 访问 DoH（如 `https://1.1.1.1/dns-query`），保证解析结果和出口地理位置一致，也避免 DNS 泄漏。〔无来源·设计决策〕
- **UDP**：每个槽位维护一张 NAT 表，超时参考 sing-box 默认的 5m [来源 S5]。可选择阻断 UDP/443（QUIC），迫使应用回落到 TCP，以便稳定拿到 SNI。〔无来源·设计决策〕
- **资源开销**：每个槽位都是一个完整的 gVisor 栈加一个 WireGuard 引擎。v1 限制槽位数量（例如 ≤8），并支持懒启动（首次命中时才连接）。〔无来源·设计决策〕

### 4.5 tailnet 侧配置要求

| 项目 | 说明 | 来源 |
|---|---|---|
| 出口节点 | 必须 `--advertise-exit-node` 并获批准 | [来源 S1] |
| ACL | 给 `tag:tailproxy` 授予 `autogroup:internet` | [来源 S1] |
| 节点身份 | 每个槽位是 tailnet 中一个独立设备 | [来源 S2][来源 S4] |
| 配额 | Personal 套餐包含 50 个 tagged 资源，ephemeral 资源为每月 1000 分钟；因此推荐**持久化状态的非 ephemeral tagged 节点**，每个槽位占 1 个 tagged 配额 | [来源 S21] |
| 自建控制面 | tsnet 支持 `ControlURL`，理论上可以对接 Headscale | tsnet 字段见 [来源 S4]；Headscale 对出口节点的兼容性〔无来源·待验证〕 |

### 4.6 控制面与「插件」接口〔无来源·设计决策〕

- **配置文件**：YAML，支持热重载（规则和出口组可以热更新；槽位增删会触发对应 tsnet 节点的启停）。
- **本地 API**：Unix socket 或 Windows 命名管道提供 REST 接口，用于查询连接列表、命中规则、槽位状态，以及临时切换出口。
- **CLI**：`tailproxy up|down|status|test <domain|ip>`，其中 `test` 用于演练某个域名或 IP 会命中哪条规则。
- **扩展点**：① Rule Provider；② Capture 后端接口（`Capture` interface，新平台只需实现它）；③ 可选的「sing-box 配置导出」后端，用作 PoC 或对照。
- **移动端**：Go 核心通过 gomobile 编译为 Android AAR / iOS xcframework，外层是平台原生 UI。〔无来源·待验证：iOS Network Extension 的内存上限能否容纳多个 tsnet 节点〕

---

## 5. 配置示例

```yaml
tailnet:
  control_url: https://controlplane.tailscale.com
  auth_key_env: TS_AUTHKEY          # 不把密钥写进文件
  advertise_tags: [tag:tailproxy]
  state_dir: /var/lib/tailproxy     # 每个槽位使用子目录

egress:
  - name: jp
    exit_node: tokyo-vps            # 主机名 / 100.x IP / StableID
  - name: us
    exit_node: 100.101.102.103
  - name: auto
    type: fallback
    members: [us, jp]
    health_check: { url: https://www.gstatic.com/generate_204, interval: 60s }

dns:
  mode: fakeip                      # fakeip | real
  fakeip: { inet4: 198.18.0.0/15, inet6: fc00::/18 }
  per_egress_doh: https://1.1.1.1/dns-query
  direct_upstream: system

capture:
  mode: auto                        # auto | tun | tproxy | socks
  exclude_cidr: [100.64.0.0/10, fd7a:115c:a1e0::/48, 192.168.0.0/16]
  socks_listen: 127.0.0.1:1080

rules:
  - { domain_keyword: [openai, anthropic, claude], egress: us }
  - { domain_suffix: [.jp, nicovideo.jp],         egress: jp }
  - { ip_cidr: [203.0.113.0/24],                  egress: jp }
  - { domain_suffix: [.ts.net], ip_cidr: [100.64.0.0/10], egress: tailnet }
  - { final: direct }
```

---

## 6. 选型对比

| 方案 | 优点 | 缺点 |
|---|---|---|
| A. 官方客户端 + 单个出口节点 | 零开发 | 同一时间只有一个出口 [来源 S1] |
| B. App Connector | 官方支持，按域名分流 | 需要 Linux 连接器和公网 IP；共享 IP 会误伤；没有关键词匹配 [来源 S3] |
| C. 直接使用 sing-box（多个 tailscale endpoint + `domain_keyword`/`ip_cidr` 路由规则） | 成熟，已具备 TUN、嗅探、FakeIP [来源 S5][来源 S17][来源 S18] | GPL-3.0 许可 [来源 S22]；依赖其 Tailscale fork [来源 S6] |
| **D. 自研核心（推荐）**：上游 tsnet（BSD-3-Clause [来源 S23]）+ wireguard-go/tun（MIT [来源 S24]）+ gVisor（Apache-2.0 [来源 S25]） | 许可灵活；规则、槽位和 API 按本需求定制 | 开发量大；需要自己解决回环和平台适配 |

**建议路线**：先用方案 C 在 1～2 天内完成 **PoC**，验证「多个 tsnet 节点对应多个出口」在目标平台可行（这是整个设计的前提），然后按方案 D 实现正式核心。〔无来源·设计决策〕

---

## 7. 里程碑〔无来源·设计决策〕

| 阶段 | 内容 | 验收 |
|---|---|---|
| M0 PoC | 两个 tsnet 槽位加 SOCKS5 入口，支持 keyword/CIDR 规则 | 通过两个槽位访问 IP 回显服务，返回的是两个不同出口的公网 IP |
| M1 Linux | nft TPROXY、FakeIP DNS、SNI/HTTP 嗅探、回环防护、CLI | 路由器（OpenWrt）上透明分流，没有 DNS 泄漏 |
| M2 桌面 | Windows Wintun、macOS utun、与系统 Tailscale 共存 | 官方客户端保持 tailnet 访问，tailproxy 负责出口分流 |
| M3 移动 | Android VpnService、iOS NEPacketTunnelProvider（gomobile） | 单个 VPN 同时提供 tailnet 访问和多出口分流 |
| M4 生态 | Rule Provider、出口组健康检查、指标、GUI | — |

## 8. 测试策略〔无来源·设计决策〕
- 单元测试：规则匹配（边界：`notopenai.com`、大小写、末尾点号、IPv4-mapped IPv6）、SNI/QUIC 解析（使用固定抓包样本）。
- 集成测试：自建控制面（Headscale，兼容性待验证）加容器内的两个出口节点，端到端校验出口 IP。
- 性能基准：单槽位和多槽位的吞吐、内存占用，与 sing-box 同配置对照。

## 9. 风险与待决问题

| # | 风险 | 状态 |
|---|---|---|
| R1 | 上游 tsnet 没有底层拨号器注入点，桌面 TUN 模式下可能出现回环 | 〔无来源·待验证〕；sing-box 通过 fork 解决 [来源 S6] |
| R2 | iOS Network Extension 内存上限与多个 tsnet 节点的开销 | 〔无来源·待验证〕 |
| R3 | 每个槽位占用 1 个 tagged 配额 | 已知，Personal 套餐包含 50 个 [来源 S21] |
| R4 | QUIC/ECH 普及后 SNI 嗅探失效，只能依赖 FakeIP | 〔无来源·待验证〕 |
| R5 | Windows 上 TUN 默认路由与出口节点冲突 | sing-box 社区 fork 有相关报告 [来源 S26]，需要在 M2 回归测试 |

---

## 参考来源

| ID | 来源 |
|---|---|
| S1 | Tailscale Docs – Exit nodes：https://tailscale.com/kb/1103/exit-nodes |
| S2 | Tailscale Docs – tsnet：https://tailscale.com/kb/1244/tsnet |
| S3 | Tailscale Docs – App connectors：https://tailscale.com/kb/1281/app-connectors |
| S4 | tsnet 源码包文档（Using an exit node / Running multiple nodes）：https://github.com/tailscale/tailscale/blob/main/tsnet/tsnet.go ；https://pkg.go.dev/tailscale.com/tsnet |
| S5 | sing-box Docs – Tailscale endpoint：https://sing-box.sagernet.org/configuration/endpoint/tailscale/ |
| S6 | sing-box 源码 `protocol/tailscale/endpoint.go` 与 `go.mod`：https://github.com/SagerNet/sing-box/blob/main/protocol/tailscale/endpoint.go |
| S7 | Tailscale Docs – Can I use Tailscale alongside other VPNs?：https://tailscale.com/kb/1105/other-vpns |
| S8 | tailscale/tailscale#3648 FR: policy routing through multiple exit nodes：https://github.com/tailscale/tailscale/issues/3648 |
| S9 | tailscale/tailscale#7766、#15521、#18669、#19901：https://github.com/tailscale/tailscale/issues/7766 ；https://github.com/tailscale/tailscale/issues/15521 ；https://github.com/tailscale/tailscale/issues/18669 ；https://github.com/tailscale/tailscale/issues/19901 |
| S10 | Linux kernel docs – Transparent proxy support：https://docs.kernel.org/networking/tproxy.html |
| S11 | Wintun：https://www.wintun.net/ |
| S12 | Apple – NEPacketTunnelProvider：https://developer.apple.com/documentation/networkextension/nepackettunnelprovider |
| S13 | Apple – NETransparentProxyProvider：https://developer.apple.com/documentation/networkextension/netransparentproxyprovider |
| S14 | Android – VpnService：https://developer.android.com/reference/android/net/VpnService |
| S15 | Tailscale 源码 `net/netns/netns_linux.go`：https://github.com/tailscale/tailscale/blob/main/net/netns/netns_linux.go |
| S16 | Tailscale 源码 `tsconst/linuxfw.go`：https://github.com/tailscale/tailscale/blob/main/tsconst/linuxfw.go |
| S17 | sing-box Docs – Protocol Sniff：https://sing-box.sagernet.org/configuration/route/sniff/ |
| S18 | sing-box Docs – FakeIP：https://sing-box.sagernet.org/configuration/dns/fakeip/ |
| S19 | RFC 6890（198.18.0.0/15 Benchmarking, RFC 2544）：https://www.rfc-editor.org/rfc/rfc6890 |
| S20 | gaissmai/bart（MIT）：https://github.com/gaissmai/bart |
| S21 | Tailscale Pricing：https://tailscale.com/pricing |
| S22 | sing-box LICENSE（GPL-3.0）：https://github.com/SagerNet/sing-box/blob/main/LICENSE |
| S23 | Tailscale LICENSE（BSD-3-Clause）：https://github.com/tailscale/tailscale/blob/main/LICENSE |
| S24 | wireguard-go LICENSE（MIT）：https://github.com/WireGuard/wireguard-go/blob/master/LICENSE |
| S25 | gVisor LICENSE（Apache-2.0）：https://github.com/google/gvisor/blob/master/LICENSE |
| S26 | LIghtJUNction/sing-box#380（社区 fork 的 issue）：https://github.com/LIghtJUNction/sing-box/issues/380 |
