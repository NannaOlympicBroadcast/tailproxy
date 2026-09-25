# tailproxy

基于 Tailscale 的跨平台透明代理插件：按域名关键词 / 后缀 / IP CIDR 规则，把流量分流到不同的 Tailscale 出口节点。

- 设计文档：[docs/DESIGN.md](docs/DESIGN.md)

## 当前进度

| 模块 | 状态 |
|---|---|
| 配置加载与校验（`internal/config`） | 已实现 |
| 规则引擎（`internal/rule`，首条命中；keyword / suffix / domain / ip_cidr / port） | 已实现 |
| Web 面板 + REST API + `/metrics`（`internal/panel`，端口 7708） | 已实现 |
| 命令行 start / stop / status / token、systemd 开机自启 | 已实现 |
| 出口管理器（`internal/egress`）：每个出口一个内嵌 tsnet 节点、固定出口节点、经出口的 DoH 解析、故障转移 / 延迟优选组与健康检查 | 已实现；出口节点出口已在真实 tailnet 上验证（见下文），出口组尚未在真实环境验证 |
| SOCKS5 入口（`internal/proxy`，仅 CONNECT、仅回环地址）+ 连接追踪 | 已实现 |
| 中继出口（`tailproxy relay` + `internal/relay`）：客户端只用一台 tailnet 设备就能有多个出口 | 已实现；已在真实 tailnet（中国 + 美国 VPS）上端到端验证 |
| Linux 透明捕获（`capture.mode: tproxy`）：nftables TPROXY + 策略路由、FakeIP / 分流 DNS、SNI / HTTP Host 嗅探、DNS 劫持、防回环 | 已实现；在网络命名空间里做了端到端集成测试，**尚未在真实路由器 / OpenWrt 上验证** |
| `tpctl` 本机命令行：管理 tailproxy + 内置官方 tailscale 客户端（操作主节点）+ schema | 已实现（`tpctl ts` 暂不支持 Windows） |
| TUN（Windows / macOS / Android / iOS）、UDP 代理 | 未实现 |

## 启动与管理

需要 Go 1.26.6 及以上版本（`tailscale.com` v1.102.4 的要求）。本地 Go 较旧时，可以用 `GOTOOLCHAIN=go1.26.6 go build ...` 自动下载对应的工具链。

```sh
go build -o tailproxy ./cmd/tailproxy
./tailproxy start -c config.example.yaml
```

`start` 会在后台启动服务，等面板真正开始监听后打印地址和令牌，然后退出前台：

```
tailproxy dev
  面板地址：http://127.0.0.1:7708/（监听 127.0.0.1:7708）
  访问令牌：<43 个字符的随机令牌>
  一键登录：http://127.0.0.1:7708/#token=<43 个字符的随机令牌>
  令牌已生成并持久化保存到 ~/.lighthousepro/tailproxy.token（权限 600），以后每次启动都沿用它
  查看令牌：tailproxy token    更换令牌：tailproxy token --rotate，然后重启服务

  已在后台运行：pid 15734，日志 ~/.lighthousepro/tailproxy.log
  查看状态：tailproxy status    停止：tailproxy stop
```

| 命令 | 作用 |
|---|---|
| `tailproxy start [-c FILE] [--ephemeral-token]` | 后台启动。启动失败（配置错误、端口被占用、令牌文件权限过宽等）时直接在终端报错，退出码为 1 |
| `tailproxy run [-c FILE] [--ephemeral-token]` | 前台运行，Ctrl-C 停止。旧用法 `tailproxy -c FILE` 等同于它 |
| `tailproxy status` | 是否在运行、pid、面板地址、运行时长、配置文件、日志、令牌来源 |
| `tailproxy token` | 打印持久化保存的令牌，服务停止时也能用 |
| `tailproxy token --rotate` | 生成新令牌写入文件（stdout 只输出新令牌，方便脚本使用）；正在运行的服务重启后才改用新令牌 |
| `tailproxy stop` | 发送 SIGTERM 让服务正常退出，最多等 10 秒 |

**令牌默认持久化保存**：第一次启动时生成 32 字节随机令牌，写入 `~/.lighthousepro/tailproxy.token`（权限 600）；之后每次启动（包括 stop 后再 start、机器重启后再 start）都沿用同一个令牌，书签里的一键登录链接和脚本一直有效，不会过期。只有执行 `tailproxy token --rotate` 并重启服务后，旧令牌才失效。

令牌的来源按以下顺序决定：

1. `panel.auth_token_env` 指向的环境变量（设置且非空时）。这种令牌不在终端显示，也不写入文件。
2. 令牌文件 `~/.lighthousepro/tailproxy.token`，不存在就生成。如果文件对组或其他用户可读（权限不是 600 这类），会拒绝启动并提示 `chmod 600`；内容少于 16 个字符也会拒绝。
3. 使用 `--ephemeral-token` 时：生成一次性令牌，不读取也不写入令牌文件，进程退出即失效。

**状态目录**默认是 `~/.lighthousepro`（权限 700），可用 `--state-dir` 修改：

| 文件 | 内容 | 生命周期 |
|---|---|---|
| `tailproxy.json` | 运行中实例的 pid、面板地址、配置路径等 | 进程退出时删除 |
| `tailproxy.token` | 持久化的访问令牌（权限 600） | **一直保留**，直到 `token --rotate` 或手动删除 |
| `tailproxy.log` | 后台进程的输出（**不含令牌**） | 持续追加，目前没有自动轮转 |

同一个状态目录下同时只能运行一个实例，重复 `start` 会提示已在运行。进程被 `kill -9` 或崩溃后留下的状态文件，会在下一次 `status` / `start` / `token` 时识别为失效并清理（令牌文件保留）。

后台进程脱离终端运行：独立会话（setsid）、没有控制终端、stdin 指向 `/dev/null`、工作目录为 `/`（因此配置文件路径会先转成绝对路径）。

**平台**：后台模式支持 Linux 和 macOS。Windows 目前只支持 `tailproxy run`（前台）；`tailproxy start` 在 Windows 上会明确报错，以后应改为注册成 Windows 服务。Linux 可以用 systemd 开机自启（见下文）；macOS 的 launchd 尚未提供。

### 开机自启（systemd）

```sh
# 系统服务（推荐）：开机自动启动，需要 root；默认以 sudo 调用者的身份运行
sudo ./tailproxy service install -c /path/to/config.yaml

# 或者：用户服务（不需要 root），并尝试 loginctl enable-linger 让它开机即启动
./tailproxy service install --user -c /path/to/config.yaml

# 只看生成的单元文件，不安装
./tailproxy service install --print -c /path/to/config.yaml

# 卸载（停止、取消开机自启、删除单元文件；令牌文件保留）
sudo ./tailproxy service uninstall        # 用户服务加 --user
```

`install` 会写入单元文件（系统服务：`/etc/systemd/system/tailproxy.service`；用户服务：`~/.config/systemd/user/tailproxy.service`），执行 `daemon-reload` 和 `enable --now`，等服务就绪后在终端打印面板地址和访问令牌。

- 单元文件使用 `Type=notify`：tailproxy 在面板真正开始监听后才通知 systemd 已就绪；退出时发送 `STOPPING=1`。`Restart=on-failure`，崩溃 3 秒后自动重启。
- 单元文件里写的都是绝对路径：二进制本身、配置文件、状态目录。移动了二进制或配置文件后，要重新执行 `install`。
- 单元文件带有 `EnvironmentFile=-<state-dir>/tailproxy.env`：`TS_AUTHKEY` 这类密钥放在这里（权限 600），不要写进单元文件本身。
- 由 systemd 运行时，**令牌不会写进 journald**，日志里只提示用 `tailproxy token` 查看。令牌仍持久化在运行用户的 `~/.lighthousepro/tailproxy.token`，开机和重启后都不变。
- 系统服务带有沙箱加固：`ProtectSystem=strict`、`ProtectHome=read-only`、`NoNewPrivileges` 等。只有状态目录和配置文件所在目录可写，因为面板保存规则时要写回配置文件。
- 由 systemd 管理时，`tailproxy stop` 会提示改用 `systemctl stop tailproxy.service`；`tailproxy status` / `tailproxy token` 照常可用。系统服务的状态和令牌属于运行用户，以其他用户身份查看时需要加 `--state-dir` 指向该目录。
- 已验证：生成的系统单元文件能通过 `systemd-analyze verify`，就绪通知协议已测试。**尚未在真实开机流程中验证**：开发环境里 systemd 没有作为 1 号进程运行。

在浏览器里打开「一键登录」链接即可进入面板；也可以打开面板地址，再粘贴令牌登录。浏览器把令牌保存在当前标签页的 sessionStorage 里，关闭标签页或点「退出」后需要重新登录（令牌本身仍然有效）。

脚本或 Prometheus 可以直接读令牌文件：

```sh
curl -H "Authorization: Bearer $(tailproxy token)" http://127.0.0.1:7708/metrics
```

也可以用环境变量指定令牌（由你自己管理，不写入文件）：

```sh
TAILPROXY_PANEL_TOKEN='至少16个字符的令牌' ./tailproxy start -c config.example.yaml
```

面板内容：

- **概览**：各组件状态、规则和出口数量、重新加载配置。
- **出口**：Tailscale 账号登录、账号下的设备列表、已配置的出口（出口节点 / 中继 / 出口组）及其运行状态。
- **规则**：规则列表、可视化编辑，以及规则测试（输入域名 / IP / 端口，查看命中哪条规则、走哪个出口）。
- **配置**：当前生效的配置。

### 出口与 SOCKS5 入口

配置里的每个出口槽位（`egress` 中没有 `type` 的条目）都会在进程内启动一个独立的 Tailscale 节点：主机名为 `tailproxy-<名称>`，状态保存在 `<state-dir>/tsnet/<名称>`，重启后仍是同一台设备。节点上线后，会按 `exit_node` 在 tailnet 中查找出口节点，可以写主机名、MagicDNS 名、100.x IP 或 StableID，找到后把它设为该节点的出口。

**统一登录与可视化配置（面板「出口」页）**：

1. tailproxy 始终运行一个主节点（主机名 `tailproxy`，可用 `tailnet.hostname` 修改）。在「Tailscale 账号」里点「登录 Tailscale」**登录一次**即可。
2. 主节点登录后，「你账号下的设备」会列出 tailnet 中的所有设备：在线状态、最后在线时间、IP、系统、所有者，以及是否已批准为出口节点。
3. 对已批准的出口节点点「添加为出口节点」，就会新建一个出口：写回配置文件的 `egress:` 段，并立即启动对应的设备 `tailproxy-<名称>`。已配置的出口可以直接换成另一个出口节点，也可以删除；删除时，对应设备会从 tailnet 注销，本地状态也会删除。仍被规则引用的出口不能删除（保存时会报错）。
4. 因为每个出口都是一台独立的 Tailscale 设备，所以：
   - 在「自动登录（auth key）」里保存一个可重复使用的 auth key 后，新增出口会自动加入 tailnet；
   - 不保存 key 时，每个新出口要在列表里点一次「授权这台设备」。

**加入 tailnet** 有两种方式：

- **推荐**：在 Tailscale 管理后台生成一个**可重复使用**的 auth key，放进 `tailnet.auth_key_env` 指向的环境变量（默认 `TS_AUTHKEY`）后启动：
  - `tailproxy start`：直接在当前 shell 里 `export TS_AUTHKEY=...`；
  - systemd 服务：写进 `<state-dir>/tailproxy.env`（例如 `~/.lighthousepro/tailproxy.env`，权限 600），内容为 `TS_AUTHKEY=tskey-auth-...`，然后 `systemctl restart tailproxy.service`。
- 不设置 auth key：「出口」页会显示每个槽位的 Tailscale 登录链接，逐个打开并登录即可。

**tailnet 侧的前提**（Tailscale 官方要求）：出口节点要执行 `--advertise-exit-node` 并在管理后台批准；ACL 要给这些槽位设备授予 `autogroup:internet`。

**使用**：在配置里打开 `capture.socks_listen`（例如 `127.0.0.1:1080`），把应用或系统的 SOCKS5 代理指向它：

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

- 按规则分流：`direct` 用本机网络直连；`reject` 拒绝（SOCKS 回复 0x02）；`tailnet` 通过任意已连接的槽位访问 tailnet 内部；出口名或出口组经对应的出口节点连接。
- **不回落**：命中某个出口的连接，如果该出口没有就绪（未登录、找不到出口节点、出口节点离线），会直接失败，**不会**改走本地网络。
- **DNS 不经本地**：发往出口的域名，通过该出口访问 `dns.per_egress_doh`（默认 `https://1.1.1.1/dns-query`）解析，所以解析结果与出口所在地一致，查询也不经过本地网络。这个地址必须写 IP，不能写域名。
- SOCKS5 入口没有认证，所以只允许监听回环地址。目前只支持 TCP CONNECT，不支持 UDP ASSOCIATE。
- IP 规则只匹配客户端直接给出的 IP 地址。客户端给的是域名时（例如 `--socks5-hostname`），只匹配域名规则。
- 槽位登录后，「出口」页会列出 tailnet 中所有已批准的出口节点：名称、IP、系统、是否在线、被哪个槽位使用。把名称填进 `exit_node` 即可。
- 某个出口所在地访问 `1.1.1.1` 不稳定时，可以给这个槽位单独设置 `doh:`（必须是 `https://<IP>/...`），覆盖全局的 `dns.per_egress_doh`。
- 「连接」页实时显示活动连接和最近 200 条已结束的连接：命中的规则、目标、实际经过的槽位、流量和错误。

**验证情况**：

- 已实际验证：
  - 真实的 tsnet 节点能连上 Tailscale 控制面，并在面板上显示「需要登录」和登录链接；
  - SOCKS5 → `direct` 能正常访问；
  - 命中未就绪出口的连接会被拒绝，不会泄漏到本地网络；
  - DoH 客户端能从 Cloudflare 的真实解析器取得正确结果。
- 已在真实 tailnet 上验证（2026-09-24）：从中国 VPS 经出口节点（美国 VPS）访问 `ifconfig.me`，返回美国 VPS 的公网 IP，空闲 90 秒后仍然正常，详见下文「中继出口」一节的验证表。

### 中继出口：一台设备，多个出口

Tailscale 的出口节点是整台设备的设置，一台设备同一时间只能用一个出口节点 [来源 DESIGN S1]。所以上面「出口节点」类型的出口，每个都要单独登录一台 tailnet 设备。**中继**换了一种做法：

- 在每台出口机器（VPS）上运行 `tailproxy relay`：它是一个 SOCKS5 服务（RFC 1928，用户名 / 密码认证 RFC 1929）[来源 DESIGN S48][来源 DESIGN S49]，**只监听本机的 Tailscale 地址**。
- 客户端 tailproxy 经**主节点**连到这个地址，请它代为连接目标；流量从 VPS 自己的网络出去。
- 客户端不管配多少个中继，都只有主节点这一台设备；VPS 也**不需要**开启或批准出口节点，只要装好 Tailscale 并登录。

**VPS 上**（已安装并登录 Tailscale）：

```sh
sudo tailproxy service install --relay     # systemd 开机自启，在 tailscaled 之后启动；打印令牌
# 或临时在前台运行：tailproxy relay
tailproxy relay token                       # 以后随时查看令牌（保存在 ~/.lighthousepro/relay.token，权限 600）
```

**客户端面板**：在「出口」→「你账号下的设备」里找到这台 VPS，点「添加为中继」，填名称、端口（默认 1081）和令牌。令牌保存在客户端的 `<state-dir>/relay/<名称>.token`（权限 600），**不写进配置文件**。也可以直接写配置：

```yaml
egress:
  - {name: us, relay: '100.98.60.52:1081'}    # 令牌在面板里填，或用 relay_token_env 指定环境变量
  - {name: cn, relay: 'vm-0-5-opencloudos:1081', relay_token_env: TP_RELAY_CN}
  - {name: auto, type: fallback, members: [us, cn]}   # 组成员可以混用出口节点和中继
```

中继的安全措施：

- 只能监听 Tailscale 地址（100.64.0.0/10、fd7a:115c:a1e0::/48）或回环地址，写 `0.0.0.0` 会直接报错；
- 只接受来自 tailnet 或回环地址的连接，并且必须带令牌；
- 默认拒绝连接内网、回环、链路本地（包括云厂商元数据地址 169.254.169.254 [来源 DESIGN S50]）和 tailnet 地址，防止令牌泄露后被用来访问 VPS 自身的服务。确实需要时加 `--allow-private`。

中继的其他行为：

- 目标域名交给 VPS 解析，所以解析结果与出口所在地一致；客户端不做 DNS 查询，也不需要 `doh`（中继出口设置 `doh` 会报错）。
- 状态：`缺少令牌` → `连不上中继` / `令牌错误` → `就绪`。客户端大约每 20 秒检查一次（出问题时每 5 秒）。和出口节点一样，**不会回落**到本地网络。
- 端口：VPS 上 1081/TCP，只在 Tailscale 地址上监听，不需要在云防火墙里放行。
- 更换令牌：在 VPS 上执行 `tailproxy relay token --rotate` 和 `systemctl restart tailproxy-relay`，再在客户端面板点「更新令牌」。
- 卸载：`sudo tailproxy service uninstall --relay`。

**验证情况**（2026-09-24，真实 tailnet）：客户端运行在中国 VPS 上，只登录了主节点一台设备（另有一台 `tailproxy-us` 用于对比出口节点方式）。

| 出口 | 类型 | 经 SOCKS5 访问 IP 回显服务得到的公网 IP |
|---|---|---|
| 直连 | — | 106.52.30.242（中国 VPS 本机，广州） |
| `cn` | 中继 → 中国 VPS | 106.52.30.242 |
| `us` | 出口节点 → 美国 VPS | 186.244.245.39（洛杉矶） |
| `usr` | 中继 → 美国 VPS | 186.244.245.39 |

- 186.244.245.39 就是美国 VPS 的 WireGuard 端点地址（`tailscale ping` 输出 `via 186.244.245.39:41641`）。
- 两台 VPS 都用 `tailproxy service install --relay` 装成 systemd 服务：只监听本机 Tailscale IP，从公网 IP 连 1081 会被拒绝；令牌不出现在 journal、客户端配置文件和客户端日志里。
- 停掉美国的中继后，`usr` 变为「连不上中继」，连接直接失败（SOCKS 错误），**没有**改走本地网络；中继恢复后自动重新可用。
- 这次测试发现并修复了一个出口节点方式的 bug：经出口节点的 DoH 解析可能只拿到 IPv6，或者在空闲后卡住（见提交 dde44c6）。

**日志上传**：内嵌的 tsnet 与官方客户端一样，默认会把诊断日志上传到 `log.tailscale.com`。不希望上传时，启动前设置 `TS_NO_LOGS_NO_SUPPORT=true`（systemd 服务写进 `tailproxy.env`）。

### 透明捕获（Linux，TPROXY）

不想给每个应用配 SOCKS5 时，在 Linux 主机或路由器上用 root 运行 tailproxy，并打开透明捕获：

```yaml
capture:
  mode: tproxy
  scope: selective          # selective（默认）| all
  tproxy_port: 7893
  dns_listen: 127.0.0.1:1053  # 路由器给局域网用时改成 0.0.0.0:1053
dns:
  mode: fakeip
  direct_upstream: system   # 或 "223.5.5.5, 119.29.29.29"
  anti_bypass: { canary: true }
  unknown_domain: ip_rules_only   # ip_rules_only | reject | egress:<名称>
```

启动后 tailproxy 会：

- 建一张 nftables 表 `inet tailproxy`，加一条策略路由（`fwmark 0x2000 → table 7893`，本地路由到 lo）。TCP 经 TPROXY 送进 tailproxy，本机和局域网的 DNS（53 端口）重定向到 tailproxy 的 DNS。
- **selective（推荐）**：DNS 只给「可能命中非 direct 规则」的域名返回 FakeIP（`198.18.0.0/15`、`fc00::/18`），其余域名照常返回真实 IP。捕获只接管 FakeIP 地址池和规则里的 `ip_cidr`，所以没命中规则的流量**根本不经过 tailproxy**（DESIGN §4.6 的 A 路径）。
- **all**：接管除私有、组播和 tailnet 地址以外的全部 TCP；域名靠 FakeIP 或 SNI / HTTP Host 嗅探得到，没命中规则的走 `direct`。
- 连接的域名来源依次是：FakeIP 反查、TLS ClientHello 的 SNI、HTTP 的 Host。ECH 连接的 SNI 只是外层公共名，面板上会标出来；有 FakeIP 映射时以映射为准。
- 发往 FakeIP 的 UDP（如 QUIC）会立刻返回「不可达」，应用会马上改用 TCP。目前只代理 TCP。
- `use-application-dns.net` 返回 NXDOMAIN，让 Firefox 关闭默认开启的 DoH。
- 发往 FakeIP 的 HTTPS / SVCB 记录返回空，防止客户端用记录里的 IP 提示或 ECH 配置绕开 FakeIP。
- **封堵加密 DNS 通道（DESIGN §4.8 L2，默认开启）**：应用自己用 DoH 解析时，tailproxy 的 DNS 看不到查询，FakeIP 就拿不到域名。所以：
  - 公开 DoH 端点的域名在 DNS 阶段返回 NXDOMAIN；
  - 被捕获的连接如果 SNI 是 DoH 端点，直接拒绝；
  - DoH 服务器 IP 的 443 端口和 DoT / DoQ 的 853 端口，由 nft 立即回 RST 或拒绝，本机和局域网的流量都一样处理。

  这样应用会退回系统 DNS。名单来自公开的 [DoH-IP-blocklists](https://github.com/dibdot/DoH-IP-blocklists)，当前约 1362 个域名、2014 个 IPv4 地址、1373 个 IPv6 地址：启动后下载，之后每 12 小时更新一次；缓存在状态目录的 `doh-lists.txt`，下载失败时沿用缓存或内置的主流提供方。`doh_allow` 可以加白名单，`block_doh: false` / `block_dot_doq: false` 可以关闭。tailproxy 自己经出口做的 DoH 走 tsnet，不经过内核，不受影响。
- **剥离 ECH（L3）**：`strip_ech: auto`（默认）只在 `dns.mode: real` 时，删除转发的 HTTPS / SVCB 应答里的 `ech` 参数，让客户端在 SNI 里发送真实域名；`on` / `off` 可以强制开关。FakeIP 模式下有了域名就不需要 SNI，所以不剥离。
- **地址学习（L4，默认开启）**：
  - 规则里明确写出的主机名（`domain` 和 `domain_suffix` 本身），每 10 分钟通过上游解析一次；
  - 经过 tailproxy 的 DNS 应答里、属于路由域名的地址，也会记下来；
  - 连接看不到域名（没有 SNI / Host，或者 SNI 只是 ECH 外层名）时，按地址查回域名，面板上显示为「学习的 DNS 应答」；
  - 学到的地址也会加入 selective 模式的捕获范围，所以 `dns.mode: real` 也能用 selective。

  代价是 CDN 共享 IP：同一个地址对应多个域名时，以最近一次应答为准（DESIGN §4.8 L4）。`learn_rule_ips: false` 可以关闭。
- **可见度统计（L0）**：面板「连接」页会统计透明捕获连接的域名来源（FakeIP / SNI / 未知）、带 ECH 的连接数和拦截的 DoH 次数，并列出「域名未知」最多的目的地，直接给出旁路影响有多大。

防回环：Tailscale 在 Linux 上以 root 运行时，会给自己的套接字打 `SO_MARK 0x80000`（`tailscale.com/net/netns`），tsnet 同样如此。tailproxy 的直连和上游 DNS 查询也打这个标记，nft 规则会放过带这个标记的包，所以既不会回环，也不会把 tsnet 自己的 WireGuard 流量再抓回来。

**崩溃恢复**：进程异常退出时，规则可能会残留，导致被捕获的流量没有去处。可以用 `sudo tailproxy capture down` 立即删除。systemd 服务已经加了 `ExecStopPost=-tailproxy capture down`，服务停止或崩溃时会自动清理；下次启动时也会先清掉残留。

**要求**：root；nftables（`nft` 命令）；内核支持 `nft_tproxy` / `nft_socket`（OpenWrt：`opkg install nftables kmod-nft-tproxy kmod-nft-socket`）。策略路由直接通过 netlink 设置，不依赖 `ip` 命令。IPv6 被禁用的主机会自动只用 IPv4。

**验证情况**：`internal/capture` 的集成测试在独立的网络命名空间里跑真实的 nftables TPROXY，覆盖以下内容：DNS 劫持得到 FakeIP；FakeIP 连接按域名交给出口；`ip_cidr` + Host 嗅探；某个端口走 direct 的 FakeIP 域名（带绕行标记、用上游解析，不会再拿到 FakeIP）；UDP 到 FakeIP 立即不可达；DoH 域名 NXDOMAIN；DoH IP 的 443 和 853 端口立即 RST；带绕行标记的连接不被拦；SNI 为 DoH 端点的连接被拒；all 模式；real 模式下从 DNS 应答学到的地址被 selective 捕获，没有 SNI / Host 的连接按学到的域名交给出口；清理后无残留。还没有在真实路由器或局域网客户端上验证。

### tpctl：本机命令行（不用再装 tailscale）

tailproxy 本身已经带着一个登录好的 Tailscale 节点（主节点）。如果为了 `tailscale status`、`ping` 这类操作再装一个官方客户端，这台机器就会变成**两台** tailnet 设备。`tpctl` 把这两件事合在一起：

- **管理 tailproxy**（经本机 REST API，令牌自动从状态目录读取）：

  ```sh
  tpctl status                                    # 各组件状态
  tpctl egress                                    # 出口列表
  echo "$RELAY_TOKEN" | tpctl egress add us --relay 100.98.60.52:1081 --token-stdin
  tpctl egress add jp --exit-node tokyo-vps
  tpctl egress set us --exit-node ser647557941975
  tpctl egress rm jp
  tpctl rules test chat.openai.com 443            # 会走哪个出口
  tpctl devices                                   # 主节点看到的设备
  tpctl conns --all                               # 连接和域名可见度统计
  tpctl reload
  ```

  中继令牌只从标准输入读取，不会出现在命令行参数和进程列表里。加 `--json` 输出原始 JSON。

- **内置官方 tailscale 客户端**：`tpctl ts <子命令>` 就是官方 `tailscale` 命令（直接编译进来的同一份代码），操作对象是 tailproxy 的主节点：

  ```sh
  tpctl ts status
  tpctl ts ping ser647557941975
  tpctl ts ip -4
  tpctl ts whois 100.98.60.52
  tpctl ts netcheck
  tpctl ts exit-node list
  ```

  也可以 `ln -s tpctl tailscale`，之后 `tailscale status` 就等同于 `tpctl ts status`。
  - tailproxy 运行时，会在状态目录创建主节点的 LocalAPI 套接字 `tailscaled.sock`：目录权限 700，套接字权限 600，只有运行 tailproxy 的用户能用。路径超过 Unix 套接字长度上限时，改放在 `$TMPDIR/tailproxy-<uid>/`，实际路径记在 `tailproxy.json` 里。
  - `down` / `logout` / `up` / `set` / `switch` 会影响主节点，中继和设备列表都依赖它，所以需要加 `--yes` 确认（通过 `tailscale` 软链接调用时不需要，和官方客户端一致）。
  - 暂不支持 Windows：官方客户端在 Windows 上走命名管道，需要单独处理权限。

- **schema**：给脚本和 AI 代理用的机器可读描述，不需要 tailproxy 在运行：

  ```sh
  tpctl schema config     # 配置文件的 JSON Schema（draft 2020-12），由配置结构体反射生成，与解析器一致
  tpctl schema api        # REST API 的 OpenAPI 3.1 文档
  tpctl schema commands   # tpctl 全部命令、参数、是否会修改状态、用到的 API
  ```

  测试会检查：每个配置字段都有说明；示例配置里的每个键都在 schema 中；OpenAPI 的路径与面板实际注册的路由完全一致。另外用第三方校验器验证过：`jsonschema` 校验示例配置通过，并能拦住故意写错的配置；`openapi-spec-validator` 校验 OpenAPI 文档通过。

### API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/v1/status` | 版本、运行时长、组件状态 |
| GET | `/api/v1/config` | 当前生效的配置（只包含环境变量名，不含密钥） |
| POST | `/api/v1/config/reload` | 重新加载配置文件；失败时保留旧配置 |
| GET | `/api/v1/egress` | 配置中的出口，以及每个槽位 / 组的运行状态（登录链接、Tailscale IP、出口节点、健康检查） |
| PUT | `/api/v1/egress` | `{"revision":"…","egress":[…]}` 保存 `egress:` 段并立即应用 |
| PUT | `/api/v1/egress/{name}/relay-token` | `{"token":"…"}` 保存中继出口的令牌（写入状态目录，不写配置文件） |
| GET | `/api/v1/tailnet` | 主节点登录状态、auth key 状态、账号下的设备 |
| PUT / DELETE | `/api/v1/tailnet/authkey` | 保存 / 删除 auth key |
| GET | `/api/v1/connections` | 活动连接和最近结束的连接 |
| GET | `/api/v1/rules` | 规则列表、可选目标、`revision`（配置文件内容哈希） |
| PUT | `/api/v1/rules` | `{"revision":"…","rules":[…]}` 保存整套规则，见下文 |
| POST | `/api/v1/rules/test` | `{"domain":"chat.openai.com","ip":"","port":443}` → 命中结果；可带 `"rules":[…]` 用未保存的草稿测试 |
| GET | `/metrics` | Prometheus 文本格式指标 |

### 可视化编辑规则

在「规则」页点「编辑规则」，可以：增删规则、上下移动（首条命中，顺序很重要）、为每条规则选择目标出口、分别填写关键词 / 后缀 / 完整域名 / IP 段 / 端口，以及设置兜底（final）。编辑期间，规则测试使用尚未保存的草稿。

点「保存」后：

1. 服务端按与启动时相同的规则校验（目标必须存在、final 只能放最后、CIDR 合法等），失败时列出错误并标红对应规则，文件不做任何改动。
2. 只替换配置文件里顶层的 `rules:` 段，**文件其余部分逐字节保持不变**（包括注释和对齐）。`rules:` 段内原有的注释不会保留。
3. 写入前把旧文件另存为 `<配置文件>.bak`，再用「临时文件 + rename」原子替换，然后重新解析写好的文件，确认与提交的规则一致。
4. 新规则立即生效，不需要重启。

如果开始编辑后配置文件被手动修改、被重新加载，或者被另一个会话保存过，保存会返回 409 冲突，而不是覆盖别人的修改。

### 访问控制

- **所有 API 和 `/metrics` 都需要令牌**（`Authorization: Bearer <令牌>`），只有登录页本身的静态文件不需要。令牌用常数时间比较。
- 令牌由 32 字节随机数生成，持久化在权限 600 的文件里（目录权限 700）。**能以你的用户身份读取这个文件的人（包括 root）都能登录面板**；怀疑泄露时用 `tailproxy token --rotate` 更换并重启服务。一键登录链接把令牌放在 `#` 后面，这一部分不会发送给服务器，页面读取后会立即从地址栏移除。
- 令牌只打印到执行 `start` 的终端，不写进 `tailproxy.log`。用 `tailproxy run` 在前台运行时令牌会打印到 stderr：如果用 systemd 等方式把前台输出写进日志，能读日志的人也能拿到令牌。
- 默认只监听 `127.0.0.1:7708`，并且只接受回环地址的 `Host` 头，用来防御 DNS 重绑定攻击。
- 所有写操作（保存规则、重新加载配置）都会拒绝跨站请求（检查 `Origin` 和 `Sec-Fetch-Site`），防止你浏览器里打开的其他网页偷偷改规则；保存规则还要求 `Content-Type: application/json`。
- `panel.listen` 可以设为局域网地址，访问同样需要令牌；这时不再校验 `Host` 头。
- `panel.tailnet`（只对 tailnet 开放面板）依赖 `ts` 槽位，尚未实现；设置后启动时会打印警告，面板仍只监听 `panel.listen`。

## 测试

```sh
go test ./...
```
