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
- **TLS 中间人解密（MITM）**：永远不做，原因见 4.7。

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
| macOS | 签名/上架版本使用 `NETransparentProxyProvider`；开发者版可以用 root 守护进程运行 utun TUN | Apple TN3120 明确要求：不要用 packet tunnel provider「选择性接管流量、其余转发到别处」，macOS 上推荐的替代方案是 `NETransparentProxyProvider` [来源 S27]；在该 provider 中，对某个 flow 返回 `false`，这个 flow 就会直接连往目的地 [来源 S13]，正好对应「未命中规则 → 走系统默认路径」。该 provider 会忽略自身设置里的 DNS 配置 [来源 S13]，因此 macOS 上获取域名主要靠嗅探〔无来源·设计决策〕 |
| Android | `VpnService` | 同一时间只能有一个 VPN 连接，新 VPN 建立时旧的会被停用 [来源 S14]；Tailscale 官方也说明 iOS/Android 同时只能运行一个 VPN [来源 S7] |
| iOS | `NEPacketTunnelProvider`，只通过 `includedRoutes` 接管 FakeIP 地址池和 IP 规则中的网段（选择性路由模式，见 4.6） | TN3120 对 iOS 的建议是用 per-app VPN，或者用 `includedRoutes` 按目的 IP 接管流量 [来源 S27]；同一时间只能运行一个 VPN [来源 S7] |
| 所有平台 | SOCKS5 / HTTP 本地代理入口 | 用于非透明场景、调试和 CI〔无来源·设计决策〕 |

**与系统 Tailscale 客户端共存（桌面端）**
- 排除 tailnet 网段：`100.64.0.0/10` 和 `fd7a:115c:a1e0::/48` 不进入捕获，继续交给系统 Tailscale 处理 [来源 S7]。
- 系统 Tailscale **不能**同时开启出口节点：官方说明出口节点的工作方式和传统 VPN 一样，只支持同时运行一个 VPN [来源 S7]。
- 移动端：因为只能有一个 VPN [来源 S7][来源 S14]，tailproxy 本身**替代**官方 App，由内置的 `ts` 槽位（不设置出口的 tsnet 节点）提供 tailnet 访问。〔无来源·设计决策〕

**防止回环（关键）**：tsnet 节点底层的 WireGuard 和 DERP 流量不能再次被 TUN 或 TPROXY 捕获。
- Linux：Tailscale 自己的 `netns` 包会给套接字打 `SO_MARK` 绕行标记（`LinuxBypassMark = 0x80000`），不支持时退回 `SO_BINDTODEVICE` [来源 S15][来源 S16]。nft 规则直接放行带这个标记的包。**已核实**：tsnet 进程内同样生效。`netns` 默认开启，`controlC` 对非本机地址的套接字调用 `setBypassMark`；非 root 时会忽略设置失败，所以透明捕获要求 root [来源 S51]。tailproxy 的直连和上游 DNS 查询也打同一个标记。
- macOS / Windows：把底层套接字绑定到物理网卡（`IP_BOUND_IF` / `IP_UNICAST_IF`）。〔无来源·待验证〕
- 风险：sing-box 使用的是自己的 Tailscale 分支（`github.com/sagernet/tailscale`），并向 tsnet 注入了自定义的底层 `DialContext` [来源 S6]。上游 tsnet 可能没有这个注入点，届时需要维护一个小补丁或 fork。〔无来源·待验证〕

### 4.2 连接元数据（域名获取）

域名来源按优先级排列〔无来源·设计决策〕：
1. **协议嗅探**：TLS ClientHello 中的 SNI、HTTP `Host` 头、QUIC Initial 中的 SNI（sing-box 采用同样的嗅探思路 [来源 S17]）。
2. **FakeIP 反查**：默认地址池 `198.18.0.0/15` 与 sing-box 相同 [来源 S18]，这个网段是 RFC 2544 保留的基准测试地址 [来源 S19]；IPv6 地址池使用 `fc00::/18` [来源 S18]。
3. **DNS 应答缓存（真实 IP 模式）**：拦截 DNS 应答，建立 `IP → 域名` 的 LRU 映射。多个域名共用一个 IP 时存在歧义（和 App Connector 的共享 IP 问题同源 [来源 S3]），因此嗅探结果优先（ECH 例外，见 4.7）。

嗅探超时（例如 300ms）后仍拿不到域名，就只按 IP 规则匹配。〔无来源·设计决策〕

### 4.3 规则引擎〔无来源·设计决策〕

- **语义**：按配置顺序**首条命中**，最后以 `final` 兜底；配置中没有写 `final` 时，等同于 `final: direct`（见 4.6）。
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
  - **实现说明**：NAT 表放在捕获层而不是槽位里：每个「客户端 × 原目的地址」一条流，第一包按规则选出口（FakeIP 反查 / QUIC Initial SNI / 学到的域名 / IP），出口节点用 tsnet 的 `Dial("udp")`（与 TCP 同一条 netstack 路径），空闲 5 分钟结束。回包用一个绑定到原目的地址（`IP_TRANSPARENT`）并 connect 到客户端的套接字发出，所以源地址正确；TPROXY 查找套接字时先找已连接的，同一条流后续的包可能直接送到这个套接字，两条路径都会转发。默认仍是阻断（`capture.udp: block`）。〔无来源·设计决策〕
- **资源开销**：每个槽位都是一个完整的 gVisor 栈加一个 WireGuard 引擎。v1 限制槽位数量（例如 ≤8），并支持懒启动（首次命中时才连接）。〔无来源·设计决策〕
- **中继出口（relay）**：因为一台设备只能用一个出口节点 [来源 S1]，「一个出口一台设备」是出口节点方案的固有成本。中继出口不用出口节点：出口机器上运行 `tailproxy relay`（SOCKS5 CONNECT + 用户名 / 密码认证 [来源 S48][来源 S49]），客户端经主节点的 `Dial` 连到它的 Tailscale 地址（普通 tailnet 流量，不需要 `autogroup:internet`），域名由中继在出口机器上解析。客户端只有主节点一台设备，出口机器也不需要 `--advertise-exit-node`。〔无来源·设计决策〕
  - 中继只监听 Tailscale 地址或回环地址，只接受 tailnet 或回环来源，必须带令牌；默认拒绝内网、回环、链路本地（含云元数据 169.254.169.254 [来源 S50]）和 tailnet 目的地址，`--allow-private` 才放开。〔无来源·设计决策〕
  - 代价：中继是 TCP 代理，不转发 UDP（目前客户端也只支持 TCP）；出口机器多一个进程。与出口节点可以混用，也可以同在一个出口组里。〔无来源·设计决策〕

### 4.5 tailnet 侧配置要求

| 项目 | 说明 | 来源 |
|---|---|---|
| 出口节点 | 必须 `--advertise-exit-node` 并获批准 | [来源 S1] |
| ACL | 给 `tag:tailproxy` 授予 `autogroup:internet` | [来源 S1] |
| 节点身份 | 每个槽位是 tailnet 中一个独立设备 | [来源 S2][来源 S4] |
| 配额 | Personal 套餐包含 50 个 tagged 资源，ephemeral 资源为每月 1000 分钟；因此推荐**持久化状态的非 ephemeral tagged 节点**，每个槽位占 1 个 tagged 配额 | [来源 S21] |
| 自建控制面 | tsnet 支持 `ControlURL`，理论上可以对接 Headscale | tsnet 字段见 [来源 S4]；Headscale 对出口节点的兼容性〔无来源·待验证〕 |

### 4.6 未命中规则的流量（默认出站）

**默认行为**：`final` 缺省为 `direct`，也就是由操作系统按**当前默认路由**把流量送出去。通常就是默认物理网卡，但如果默认路由指向别的 VPN，流量也会跟着走那个 VPN。〔无来源·设计决策〕

未命中规则的流量有两种走法：

| 走法 | 适用场景 | 机制 |
|---|---|---|
| **A. 根本不进入 tailproxy** | `capture.exclude_cidr` 中的网段；Linux 上 nft 不匹配的流量；iOS / 选择性路由模式下不在 `includedRoutes` 里的目的地 | 流量不经过任何代理代码，直接走系统路由表〔无来源·设计决策〕；iOS 以 `includedRoutes` 按目的 IP 接管的做法见 [来源 S27] |
| **B. 被截获后，由 `direct` 出站重新拨号** | 需要先看到 SNI 才能判断规则的流量（全量 TUN / TPROXY 模式） | 重新拨号的套接字必须绕开自己的 TUN，否则会回环：Linux 打 `SO_MARK` 绕行标记，让它走 main 路由表 [来源 S15][来源 S16]；Android 调用 `VpnService.protect()`，受保护的套接字直接走底层网络，不经过 VPN [来源 S14]；macOS 透明代理对 flow 返回 `false`，让系统直连 [来源 S13]；Windows / macOS-utun 绑定物理网卡（Windows `IP_UNICAST_IF`、macOS `IP_BOUND_IF`，已在 CI 集成测试中验证）〔无来源·实现验证〕 |

**选择性路由模式（推荐的默认模式）**〔无来源·设计决策〕：DNS 模块只给**命中域名规则的域名**返回 FakeIP，其余域名返回真实 IP；TUN 或隧道只接管 FakeIP 地址池和 IP 规则中的网段。这样未命中的流量走的是 A 路径，完全不经过 tailproxy。代价有两个：域名规则只能在 DNS 阶段判定，拿不到 SNI 校验；应用如果自带 DoH，会绕过 DNS 规则。

**注意事项**
- 系统里的官方 Tailscale 客户端如果开启了出口节点，默认路由会指向 Tailscale，这时 `direct` 的流量实际上也会从那个出口节点出去 [来源 S1][来源 S7]。所以设计要求官方客户端不要开启出口节点。
- **出口故障时不自动回落到 `direct`**：已经命中某个出口的流量，如果该出口不可用，默认直接拒绝，以免本该走出口的流量从本地网卡泄漏；用户可以用 `on_egress_down: direct` 显式开启回落。〔无来源·设计决策〕
- 想要「未命中一律不出网」的用户，可以配置 `final: reject`。〔无来源·设计决策〕

### 4.7 HTTPS / TLS 处理：只读握手、不解密

**原则**：tailproxy 不终止、也不解密 TLS。规则匹配只需要域名，而域名可以从握手的明文部分读到；决定出口之后，加密字节原样转发。证书校验仍然发生在应用和源站之间，所以**不会产生证书问题，也不需要安装任何 CA**。〔无来源·设计决策〕

| 场景 | 处理方式 | 依据 |
|---|---|---|
| TLS（TCP） | 读取 ClientHello 中的 `server_name` 扩展（SNI） | SNI 由客户端在 ClientHello 中告诉服务器要访问的主机名 [来源 S28] |
| QUIC / HTTP3 | 解开 Initial 包读取 SNI，不需要任何私钥 | Initial 包的密钥由客户端首个 Initial 包中的 Destination Connection ID 派生，并不是用保密密钥保护的 [来源 S29] |
| ECH（加密 ClientHello） | 外层 SNI 只是提供方的 `public_name`（如 CDN 的公共名），不是真实站点。**客户端带有 ECH 扩展、外层 SNI 与 FakeIP / DNS 映射得到的域名不一致时，以 FakeIP / DNS 映射为准** | ECH 加密真实 SNI，外层 `server_name` 建议填 `ECHConfig.public_name` [来源 S30]；没有 ECH 配置的客户端会发 GREASE ECH，这时外层 SNI 仍是真实域名 [来源 S30] |
| DNS HTTPS/SVCB 记录 | 对命中规则的域名，改写或剔除 `ipv4hint`/`ipv6hint`，防止客户端拿提示里的真实 IP 直连、绕开 FakeIP；可选 `dns.strip_ech` 剔除 `ech` 参数（默认关闭） | 客户端「可以」使用 hint 中的地址连接服务 [来源 S31]；ECH 配置通过 SVCB/HTTPS 记录下发 [来源 S30] |
| tailnet 内 `*.ts.net` HTTPS | 交给系统 Tailscale 或 `tailnet` 出站，原样透传 | Tailscale 的 HTTPS 证书由 Let's Encrypt 签发，私钥保存在本机 [来源 S32] |

**为什么不做 MITM 解密**
- 需要让用户安装并信任自签根 CA；而 targetSdk 为 Android 6.0（API 23）及以下的应用才默认信任用户添加的 CA，更新的应用默认只信任系统 CA [来源 S33]，所以在 Android 上对大多数现代 App 都不起作用。
- 做了证书固定（pinning）的 App 会直接断连；解密还会让 tailproxy 成为高价值攻击目标。〔无来源·设计决策〕
- 业务上没有收益：规则只到域名这一级，不需要 URL 路径或报文内容。〔无来源·设计决策〕

### 4.8 DoH / ECH 旁路对策

**问题**：应用自己用 DoH/DoT 解析域名时，DNS 查询不经过 tailproxy，FakeIP 拿不到域名；如果连接同时使用了 ECH，SNI 也读不到真实域名，最后只能按 IP 规则匹配。

**关键判断**：只要 DNS 查询回到 tailproxy，FakeIP 就能拿到域名，**不管连接是否使用 ECH**（4.2 中 FakeIP 优先于 ECH 外层 SNI）。所以对策的重心是**把 DNS 拉回来**，而不是对付 ECH 本身。另外，Firefox 的 ECH 必须在配置了 DoH 时才启用，并且遵守 canary、偏好设置和企业策略这些 DoH 退出机制 [来源 S34]，因此关掉 Firefox 的 DoH 也就同时关掉了它的 ECH。〔判断本身：无来源·设计决策〕

分五层处理，前一层失效时由后一层兜底：

| 层 | 措施 | 依据 | 默认 |
|---|---|---|---|
| L0 可观测 | 统计「域名未知」的连接、带 ECH 扩展且外层 SNI 与映射域名不一致的连接、命中 DoH/DoT 端点的连接；`tailproxy status --bypass` 输出按应用和目的地汇总的结果 | 〔无来源·设计决策〕：把「影响有多大」从未验证变成可以直接测量 | 开 |
| L1 网络信号（零配置） | ① 让 `use-application-dns.net` 返回 NXDOMAIN；② tailproxy 自己作为系统 DNS | ① Firefox 解析 canary 域名得到 NXDOMAIN、其他错误码，或者 NOERROR 但没有 A/AAAA 记录时，就会关闭**默认开启的** DoH；但对用户手动开启的 DoH 无效 [来源 S35]。② Chrome 在未设置策略时，只会把 DoH 请求发给「与系统解析器相关联」的解析器 [来源 S36]，tailproxy 的本地解析器不属于这种情况〔无来源·待验证：本地地址不会被识别为已知 DoH 提供方〕 | 开 |
| L2 封堵加密 DNS 通道 | ① DoH 端点：按域名列表（DNS 阶段直接返回 NXDOMAIN，SNI 阶段拒绝连接）和 IP 列表（只拦 443 端口）拦截，拒绝时回 TCP RST / ICMP 不可达，让客户端尽快回落；② DoT 的 TCP 853 和 DoQ 的 UDP 853 同样拒绝 | ① Chrome 的 automatic 模式遇到错误时「可能回落到非加密查询」，secure 模式则直接解析失败 [来源 S36]；Firefox 有 `Fallback` 策略控制是否回落到系统 DNS [来源 S37]；公开的 DoH 域名和 IP 列表每小时自动更新 [来源 S38]。② DoT 使用 TCP 853 端口 [来源 S39]，DoQ 使用 UDP 853 端口 [来源 S40] | 开，允许加白名单 |
| L3 剥离 ECH 配置 | 删除 HTTPS/SVCB 应答中的 `ech` 参数，只在 `dns.mode: real` 时默认开启 | Chrome 在使用非加密 DNS 时也会查询 HTTPS（type 65）记录 [来源 S41]；ECH 配置通过 SVCB/HTTPS 记录下发，没有配置的客户端只发 GREASE ECH，外层 SNI 仍是真实域名 [来源 S30]；但客户端可能已经缓存了 ECH 配置 [来源 S42]。FakeIP 模式下有了域名就不需要 SNI，所以不必剥离〔无来源·设计决策〕 | real 模式开，FakeIP 模式关 |
| L4 域名未知时兜底 | ① 规则域名预解析：对 `domain` / `domain_suffix` 中明确列出的主机名定期解析（**实现说明**：用的是本地上游，而不是对应出口。自带 DoH 的应用在本地解析，拿到的是按本地位置调度的 CDN 地址，用本地上游解析才能对上这些地址〔无来源·设计决策〕），把得到的 IP 放进带 TTL 的动态 IP 集合，同时从所有经过的 DNS 应答中学习；② 可选规则 `outer_sni`：按 ECH 外层 SNI（如 CDN 公共名）粗粒度分流；③ `unknown_domain` 策略：默认只按 IP 规则匹配，也可以指定出口或拒绝 | ① 与 App Connector 用 DoH 解析域名再通告 IP 是同一思路，也有同样的共享 IP 误伤问题 [来源 S3]；`domain_keyword` 无法预解析〔无来源·设计决策〕 | ① 开；②③ 按需配置 |
| L5 托管模式（需用户明确执行） | `tailproxy doctor --apply-browser-policy`：写入 Chrome/Edge 的 `DnsOverHttpsMode=off`（可选 `EncryptedClientHelloEnabled=false`），以及 Firefox 的 `DNSOverHTTPS {Enabled:false, Locked:true}`；执行前打印即将写入的内容，并支持一键撤销 | Chrome 的 `DnsOverHttpsMode` 取 `off` 时关闭 DoH [来源 S36]；`EncryptedClientHelloEnabled` 设为 false 时 Chrome 不启用 ECH [来源 S43]；Firefox `DNSOverHTTPS` 策略支持 `Enabled` / `Locked` / `Fallback` [来源 S37] | 关 |

**剩余风险**：应用把 DoH 服务器的 IP 写死在代码里（不在公开列表中），同时连接又使用了 ECH，这种情况在不解密的前提下无法识别域名，只能按 IP 规则或 `unknown_domain` 策略处理；影响范围由 L0 统计给出。〔无来源·设计决策〕

**Android 注意**：Chrome 策略文档写明，Android 9 及以上系统启用 DNS-over-TLS（私人 DNS）时，Chrome 不会发送非加密 DNS 请求 [来源 S36]。私人 DNS 在 VpnService 下的实际行为，以及 L2 封堵 853 端口后是否会回落，〔无来源·待验证〕，列入 M3 测试矩阵。

**验证计划（M1 必做）**：Chrome / Edge / Firefox / Safari × DoH 设置（默认 / automatic / secure / 手动指定提供方）× 目标站点是否启用 ECH，逐项记录 L0 统计中的「域名未知率」。〔无来源·设计决策〕

### 4.9 控制面与「插件」接口〔无来源·设计决策〕

- **配置文件**：YAML，支持热重载（规则和出口组可以热更新；槽位增删会触发对应 tsnet 节点的启停）。
- **本地 API**：由 Web 面板端口（默认 7708）上的 REST 接口提供，所有请求都需要访问令牌。可以查询状态、配置、出口（含运行状态）、tailnet 设备、连接和规则；可以保存出口和规则、保存中继令牌和 auth key、重新加载配置。机器可读的描述由 `tpctl schema api`（OpenAPI 3.1）给出。
- **主节点 LocalAPI**：tailproxy 运行时，把主节点的 tsnet LocalAPI（官方 tailscale CLI 使用的接口）转发到状态目录里的 Unix 套接字 `tailscaled.sock`（目录 700、套接字 600）。
- **CLI**：
  - `tailproxy start|run|stop|status|token|relay|service|capture`：进程生命周期、中继、systemd 和透明捕获清理。`start` 以后台进程运行，面板就绪后打印地址和令牌再退出前台；状态文件、日志和持久化的令牌文件放在 `~/.lighthousepro`。
  - `tpctl`：日常操作，包括状态、出口增删改、规则测试、设备、连接和重新加载。`tpctl ts …` 内置官方 tailscale CLI，操作上面的主节点，所以本机不需要另装 tailscale，也不会多出一台设备。`tpctl schema config|api|commands` 输出配置 JSON Schema（由结构体反射生成）、OpenAPI 文档和命令清单。
- **扩展点**：① Rule Provider；② Capture 后端接口（`Capture` interface，新平台只需实现它）；③ 可选的「sing-box 配置导出」后端，用作 PoC 或对照。
- **嵌入式 SDK**：`sdk` 包让其他 Go 程序内嵌 tailproxy（经规则拨号、SOCKS5 入口、接管 VPN 的 TUN），`sdk/mobile` 是它的 gomobile 绑定形式。
- **移动端**（TODO）：Go 核心通过 gomobile（`sdk/mobile`）编译为 Android AAR / iOS xcframework，外层是平台原生 UI；应用本身尚未开始。〔无来源·待验证：iOS Network Extension 的内存上限能否容纳多个 tsnet 节点〕

### 4.10 端口规划

**监听端口**

| 端口 | 协议 | 用途 | 是否必需 | 默认绑定 | 依据 |
|---|---|---|---|---|---|
| **7708** | TCP | Web 面板，同时提供 REST API 和 `/metrics`（合并在一个端口，不另开 API / 指标端口） | 桌面 / 路由器：是；移动端使用原生 UI，不监听 | `127.0.0.1:7708`，端口可配置；可选通过 `ts` 槽位的 tsnet `Listen` 只对 tailnet 开放，由 ACL 控制访问 | 大于 1024，不需要特权端口权限；IANA 登记表中 7708 已登记给 `scinet`（scientia.net）[来源 S44]，本机没有运行该服务时不冲突，冲突时通过 `panel.listen` 改端口；tsnet 支持 `Listen` [来源 S2][来源 S4]；绑定方式〔无来源·设计决策〕 |
| 53 | UDP+TCP | 给局域网客户端的 DNS（FakeIP / 分流解析） | 仅路由器 / TPROXY 模式需要；TUN 模式在虚拟网卡内部劫持 DNS，不占主机端口 | 实际监听 `127.0.0.1:1053`，由 nft 把 53 重定向过来；路由器模式可直接监听 LAN 接口的 53 | 桌面 Linux 上 systemd-resolved 已占用 `127.0.0.53` / `127.0.0.54` 的 53 端口 [来源 S46]；IANA 53 = domain [来源 S44]；绑定方式〔无来源·设计决策〕 |
| 7893 | TCP+UDP | TPROXY 透明代理入口 | 仅 Linux TPROXY 模式 | 只接收 nft 标记后送来的流量，不对外暴露 | TPROXY 需要一个设置了 `IP_TRANSPARENT` 的监听套接字 [来源 S10]；端口号〔无来源·设计决策〕 |
| 1080 | TCP+UDP | SOCKS5 / HTTP 兜底入口 | 可选，默认关闭 | `127.0.0.1:1080` | IANA 1080 = socks [来源 S44] |
| 1081 | TCP | **VPS 上的** `tailproxy relay`（中继出口的服务端，SOCKS5 + 用户名 / 密码认证） | 仅使用中继出口时 | 只绑定本机 Tailscale IP（或回环），拒绝 `0.0.0.0` | 协议 [来源 S48][来源 S49]；端口号取 1080 的下一个，避免与本机 SOCKS 入口冲突〔无来源·设计决策〕 |
| 41642–41649 | UDP | 各 tsnet 槽位的 WireGuard 端口，每个槽位一个 | 否：默认 `Port=0` 自动选择；只有在需要固定防火墙规则时才启用这个范围 | 所有接口 | tsnet `Port` 为 0 时自动选择 [来源 S4]；系统 tailscaled 默认使用 41641，所以从 41642 开始，避免冲突 [来源 S47] |
| —— | 状态文件 + 信号 | 本地 CLI（`stop` / `status` / `token`）通过 `~/.lighthousepro` 下的状态文件和 SIGTERM 控制服务 | 是 | 仅本机 | 〔无来源·设计决策〕，不占 TCP 端口 |

**入站**：正常情况下 Tailscale **不需要开放任何入站端口**，依靠 NAT 穿透即可；只有在网络环境比较差、直连失败时，才建议放行 WireGuard UDP 端口的入站，以减少走 DERP 中继的情况 [来源 S47]。

**出站**（防火墙必须放行）：TCP 443（控制面和 DERP 中继）、UDP 3478（STUN）、WireGuard UDP 源端口；TCP 80 可选（控制面回退、强制门户检测）[来源 S47]。

**Web 面板安全**〔无来源·设计决策〕：所有 API 和 `/metrics` 始终需要访问令牌。未通过 `panel.auth_token_env` 指定令牌时，首次启动生成 32 字节随机令牌并持久化到 `~/.lighthousepro/tailproxy.token`（0600，之后每次启动沿用，`tailproxy token --rotate` 更换；`--ephemeral-token` 使用一次性令牌），并在终端打印面板地址、令牌和一键登录链接（令牌放在 URL 的 `#` 片段里，不会发送到服务器）；来自环境变量的令牌不在终端回显。默认只监听回环地址，并校验 `Host` 头以防 DNS 重绑定；写操作拒绝跨站请求。更推荐只通过 tailnet 访问，这样可以复用 Tailscale 的身份认证和 ACL。

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
  anti_bypass:                      # 见 4.8
    canary: true                    # use-application-dns.net → NXDOMAIN
    block_doh: true                 # 公开 DoH 域名 / IP 列表，定时更新
    doh_lists:
      - https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-domains.txt
      - https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv4.txt
      - https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv6.txt
    doh_allow: []                   # 白名单
    block_dot_doq: true             # TCP/UDP 853
    strip_ech: auto                 # auto = 仅 real 模式开启
    learn_rule_ips: true            # 规则域名预解析 + 应答学习
  unknown_domain: ip_rules_only     # ip_rules_only | egress:<name> | reject

capture:
  mode: auto                        # auto | tun | tproxy | socks
  exclude_cidr: [100.64.0.0/10, fd7a:115c:a1e0::/48, 192.168.0.0/16]
  socks_listen: 127.0.0.1:1080      # 可选，默认关闭
  tproxy_port: 7893                 # 仅 Linux TPROXY
  dns_listen: 127.0.0.1:1053        # 仅路由器 / TPROXY 模式

panel:
  listen: 127.0.0.1:7708            # Web 面板 + REST API + /metrics
  tailnet: false                    # true：同时在主节点 tailnet 地址的同一端口开放（仍需令牌，受 ACL 控制）
  auth_token_env: TAILPROXY_PANEL_TOKEN   # 可选：用环境变量指定令牌（≥16 字符）；未设置时使用 ~/.lighthousepro/tailproxy.token

wireguard_ports: auto               # auto | 41642-41649

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
| M0 PoC | 两个 tsnet 槽位加 SOCKS5 入口，支持 keyword/CIDR 规则 | 通过两个槽位访问 IP 回显服务，返回的是两个不同出口的公网 IP。**状态：已验收（2026-09-24）**：在真实 tailnet 上，同一客户端经中国、美国两个出口分别得到 106.52.30.242 和 186.244.245.39（出口节点和中继两种方式都验证过，见 README） |
| M1 Linux | nft TPROXY、FakeIP DNS、SNI/HTTP 嗅探、回环防护、CLI | 路由器（OpenWrt）上透明分流，没有 DNS 泄漏。**状态**：TPROXY（selective / all）、策略路由（netlink）、FakeIP + 分流 DNS、DNS 劫持、canary、SNI/Host 嗅探、防回环、`capture down`、L2 DoH/DoT/DoQ 封堵、L3 ECH 剥离、L4 规则域名预解析与应答学习、L0 可见度统计都已实现，并在网络命名空间里做了集成测试；L4 的 `outer_sni` 规则已实现（外层 SNI 只由 `outer_sni` 匹配，不再当作域名）；UDP 代理已实现（`capture.udp: proxy`，经出口节点 / 直连，中继不承载 UDP；QUIC Initial SNI 嗅探支持 v1 / v2，跨数据报合并 ClientHello），在网络命名空间里做了集成测试；L5 浏览器策略已实现（`tailproxy doctor --apply-browser-policy` / `--revert-browser-policy`：Chrome/Chromium/Edge `DnsOverHttpsMode=off`、可选 Chrome `EncryptedClientHelloEnabled=false`、Firefox `DNSOverHTTPS {Enabled:false, Locked:true}`，Linux 策略文件 / macOS defaults（推荐级别）/ Windows 注册表，逐项记录原值可撤销）[来源 S55][来源 S56][来源 S57][来源 S58][来源 S59]，三平台写入与撤销在 CI 中测试，尚未在真实浏览器中确认生效；验收项需要真实路由器，尚未完成 |
| M2 桌面 | Windows Wintun、macOS utun、与系统 Tailscale 共存 | 官方客户端保持 tailnet 访问，tailproxy 负责出口分流。**状态**：TUN 引擎（`internal/tunstack`：gVisor netstack + wireguard-go `tun.Device`，TCP/UDP 交给与 TPROXY 相同的入口，协议栈内 DNS）已实现，跨平台编译；`capture.mode: tun` 已在三个平台接入：Linux 用独立路由表 + 绕行标记优先查 main 表；macOS utun 用 ifconfig/route，防回环用 `IP_BOUND_IF` 绑定默认路由网卡；Windows Wintun 用 IP Helper API，防回环用 `IP_UNICAST_IF`。三个平台都在 CI 里用真实 TUN 设备跑通集成测试。系统 DNS 自动设置与恢复（`capture.tun_system_dns`）：Linux systemd-resolved 仅路由域 `~.`（据 systemd-resolved 文档，其他网卡不再参与这些查询，除非它们也配置了 `~.`）[来源 S52]，macOS networksetup（同 wg-quick）[来源 S53]，Windows 网卡 DNS + 跃点数 0（同 wireguard-windows）[来源 S54]，三个平台在 CI 中用系统解析器验证。`capture.scope: all` 也已支持：默认路由拆成两半进入 TUN，排除网段在 Linux 用 throw 路由、在 macOS / Windows 由入口绑定物理网卡直连。尚未实现：与系统 Tailscale 共存的实测（其 MagicDNS 若也设 `~.` 会并行查询）、Windows 默认路由冲突（R5）回归 |
| M3 移动 | Android VpnService、iOS NEPacketTunnelProvider（gomobile） | 单个 VPN 同时提供 tailnet 访问和多出口分流。**状态**：只提供 SDK——`sdk`（Go 嵌入接口：经规则拨号、SOCKS5、`ServeTUN` / `ServeTUNFD`、`Protect` 回调，Android 上经 `netns.SetAndroidProtectFunc` 让 Tailscale 节点的套接字也绕过 VPN）和 `sdk/mobile`（gomobile 绑定），CI 交叉编译 Android / iOS 并用 gobind 生成绑定；**Android / iOS 应用为 TODO**，未在真机运行 |
| M4 生态 | Rule Provider、出口组健康检查、指标、GUI | —。**已有**：`tpctl` 命令行（内置官方 tailscale CLI，操作 tailproxy 主节点，本机无需另装 tailscale；`tpctl schema` 输出配置 JSON Schema、OpenAPI、命令清单） |

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
| R4 | QUIC/ECH 普及后 SNI 嗅探失效，只能依赖 FakeIP | 见 R7 与 4.8 |
| R5 | Windows 上 TUN 默认路由与出口节点冲突 | sing-box 社区 fork 有相关报告 [来源 S26]，需要在 M2 回归测试 |
| R6 | Apple 平台的审核与 API 约束：packet tunnel 不应用于选择性代理 | 已据 TN3120 调整 macOS / iOS 方案 [来源 S27] |
| R7 | ECH 普及后 SNI 不可信；浏览器自带 DoH 时 FakeIP 也拿不到域名 | 已有 L0–L5 分层对策（见 4.8）；剩余风险为写死 DoH IP 且同时使用 ECH 的应用，影响范围由 L0 统计给出 |

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
| S28 | RFC 6066 §3 Server Name Indication：https://www.rfc-editor.org/rfc/rfc6066 |
| S29 | RFC 9001 §5.2 Initial Secrets、§9 安全考量：https://www.rfc-editor.org/rfc/rfc9001 |
| S30 | RFC 9849 TLS Encrypted Client Hello：https://www.rfc-editor.org/rfc/rfc9849 |
| S31 | RFC 9460 §7.3 ipv4hint / ipv6hint：https://www.rfc-editor.org/rfc/rfc9460 |
| S32 | Tailscale Docs – Enabling HTTPS：https://tailscale.com/kb/1153/enabling-https |
| S33 | Android – Network security configuration：https://developer.android.com/privacy-and-security/security-config |
| S34 | Mozilla dev-platform – Intent to experiment and ship: Encrypted Client Hello：https://groups.google.com/a/mozilla.org/g/dev-platform/c/uv7PNrHUagA |
| S35 | Mozilla Support – Canary domain use-application-dns.net：https://support.mozilla.org/en-US/kb/canary-domain-use-application-dnsnet |
| S36 | Chromium 策略定义 DnsOverHttpsMode：https://chromium.googlesource.com/chromium/src/+/main/components/policy/resources/templates/policy_definitions/Miscellaneous/DnsOverHttpsMode.yaml |
| S37 | Mozilla policy-templates – DNSOverHTTPS：https://github.com/mozilla/policy-templates/blob/master/docs/index.md#dnsoverhttps |
| S38 | dibdot/DoH-IP-blocklists：https://github.com/dibdot/DoH-IP-blocklists |
| S39 | RFC 7858 DNS over TLS：https://www.rfc-editor.org/rfc/rfc7858 |
| S40 | RFC 9250 DNS over Dedicated QUIC：https://www.rfc-editor.org/rfc/rfc9250 |
| S41 | Chromium 策略定义 AdditionalDnsQueryTypesEnabled：https://chromium.googlesource.com/chromium/src/+/main/components/policy/resources/templates/policy_definitions/Miscellaneous/AdditionalDnsQueryTypesEnabled.yaml |
| S42 | Zscaler – Encrypted Client Hello Is Here to Stay：https://www.zscaler.com/blogs/product-insights/encrypted-client-hello-ech-here-stay |
| S43 | Chromium 策略定义 EncryptedClientHelloEnabled：https://chromium.googlesource.com/chromium/src/+/main/components/policy/resources/templates/policy_definitions/Miscellaneous/EncryptedClientHelloEnabled.yaml |
| S44 | IANA Service Name and Transport Protocol Port Number Registry：https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml |
| S46 | systemd-resolved.service(8)：https://man7.org/linux/man-pages/man8/systemd-resolved.service.8.html |
| S47 | Tailscale Docs – What firewall ports should I open：https://tailscale.com/kb/1082/firewall-ports |
| S48 | RFC 1928 SOCKS Protocol Version 5：https://www.rfc-editor.org/rfc/rfc1928 |
| S49 | RFC 1929 Username/Password Authentication for SOCKS V5：https://www.rfc-editor.org/rfc/rfc1929 |
| S50 | AWS EC2 – Access instance metadata（IMDS 地址 169.254.169.254）：https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html |
| S51 | tailscale.com v1.102.4 源码 `net/netns/netns_linux.go`（`controlC`、`setBypassMark`、`UseSocketMark`）：https://github.com/tailscale/tailscale/blob/v1.102.4/net/netns/netns_linux.go |
| S52 | systemd-resolved.service(8)（查询路由：仅路由域 `~.`）：https://www.freedesktop.org/software/systemd/man/latest/systemd-resolved.service.html |
| S53 | wireguard-tools `src/wg-quick/darwin.bash`（`networksetup -getdnsservers/-setdnsservers` 保存与恢复）：https://github.com/WireGuard/wireguard-tools/blob/master/src/wg-quick/darwin.bash |
| S54 | wireguard-windows v0.5.3 `tunnel/addressconfig.go`（`UseAutomaticMetric = false`、`Metric = 0`、`luid.SetDNS`）：https://git.zx2c4.com/wireguard-windows/tree/tunnel/addressconfig.go?h=v0.5.3 |
| S55 | Chromium 策略定义 `DnsOverHttpsMode`（string-enum off/automatic/secure，Chrome 78+）与 `EncryptedClientHelloEnabled`（boolean，Chrome 105+）：https://github.com/chromium/chromium/tree/main/components/policy/resources/templates/policy_definitions/Miscellaneous |
| S56 | Chromium Linux Quick Start（`/etc/opt/chrome/policies/managed`、`/etc/chromium/policies`、Ubuntu `/etc/chromium-browser/policies`）：https://www.chromium.org/administrators/linux-quick-start/ ；Mac Quick Start（`defaults` 写入为推荐级别）：https://www.chromium.org/administrators/mac-quick-start/ |
| S57 | Microsoft Edge 策略 DnsOverHttpsMode（`SOFTWARE\Policies\Microsoft\Edge`，REG_SZ）：https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/dnsoverhttpsmode ；Edge Linux 策略目录 `/etc/opt/edge/policies/managed` 仅有 Microsoft Q&A 社区回答：https://learn.microsoft.com/en-us/answers/questions/2005942 |
| S58 | Firefox 企业策略 DNSOverHTTPS（Windows GPO 注册表路径、Linux `/etc/firefox/policies`、macOS `Firefox.app/Contents/Resources/distribution`）：https://mozilla.github.io/policy-templates/ |
| S59 | Google：用 Windows 注册表管理 Chrome 策略：https://support.google.com/chrome/a/answer/9131254 |
| S27 | Apple TN3120 – Expected use cases for Network Extension packet tunnel providers：https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers |
