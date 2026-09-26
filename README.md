# tailproxy

基于 Tailscale 的跨平台透明代理插件：按域名关键词 / 后缀 / IP CIDR 规则，把流量分流到不同的 Tailscale 出口节点。

- 设计文档：[docs/DESIGN.md](docs/DESIGN.md)
- 许可证：[MIT](LICENSE)（依赖各自保留其许可证：tailscale.com BSD-3-Clause、wireguard-go MIT、gVisor Apache-2.0 等）

## 安装

- **下载发行版**：[Releases](https://github.com/NannaOlympicBroadcast/tailproxy/releases) 提供 `tailproxy_<版本>_<系统>_<架构>` 压缩包（Linux amd64 / arm64 / armv7 / mips / mipsle / riscv64，macOS amd64 / arm64，Windows amd64 / arm64），内含 `tailproxy`、`tpctl`、LICENSE、README 和配置示例；用 `SHA256SUMS` 校验。0.x 版本以预发布（pre-release）形式发布。
- **让 Agent 引导配置（Cowork / Claude Code 插件）**：本仓库同时是一个插件市场。在 Cowork 或 claude.ai 的 Customize > Plugins 里添加市场 `NannaOlympicBroadcast/tailproxy` 并安装 `tailproxy` 插件（或上传发行版里的 `tailproxy-plugin_<版本>.zip`）；Claude Code 中：`/plugin marketplace add NannaOlympicBroadcast/tailproxy`，然后 `/plugin install tailproxy@tailproxy`。插件提供三个技能：
  - `setup`：选择部署方式（本机 SOCKS5 / 本机 TUN / Linux 路由器 / VPS 中继）→ 下载并校验发行版 → 生成并用 `tailproxy check` 校验 config.yaml → 登录 Tailscale → 启动 → 验证各规则走到的出口；
  - `rules`：用自然语言增改规则和出口，`tailproxy check` 校验后 `tpctl reload` 生效并逐条测试；
  - `troubleshoot`：按 `tpctl status` / `egress list` / `conns` 和日志定位问题。
  - 插件只包含技能（Cowork 不安装带顶层 `bin/` 的插件），命令在 Cowork 会话所在的电脑上执行，所以要让 Cowork 运行在需要配置的那台机器上；需要 root、修改系统或涉及密钥的步骤都会先征得同意，auth key 和中继令牌不经过对话。
- **从源码构建**：见下一节。

## 当前进度

| 模块 | 状态 |
|---|---|
| 配置加载与校验（`internal/config`） | 已实现 |
| 规则引擎（`internal/rule`，首条命中；keyword / suffix / domain / ip_cidr / outer_sni / port） | 已实现 |
| Web 面板 + REST API + `/metrics`（`internal/panel`，端口 7708） | 已实现 |
| 命令行 start / stop / status / token、systemd 开机自启 | 已实现 |
| 出口管理器（`internal/egress`）：每个出口一个内嵌 tsnet 节点、固定出口节点、经出口的 DoH 解析、故障转移 / 延迟优选组与健康检查 | 已实现；出口节点出口已在真实 tailnet 上验证（见下文），出口组尚未在真实环境验证 |
| SOCKS5 入口（`internal/proxy`，CONNECT + UDP ASSOCIATE、仅回环地址）+ 连接追踪 | 已实现；UDP ASSOCIATE 有单元测试，并用 PySocks 1.7.1 客户端互通测试过 |
| 中继出口（`tailproxy relay` + `internal/relay`）：客户端只用一台 tailnet 设备就能有多个出口 | 已实现；已在真实 tailnet（中国 + 美国 VPS）上端到端验证 |
| Linux 透明捕获（`capture.mode: tproxy`）：nftables TPROXY + 策略路由、FakeIP / 分流 DNS、SNI / HTTP Host 嗅探、DNS 劫持、防回环 | 已实现；在网络命名空间里做了端到端集成测试，**尚未在真实路由器 / OpenWrt 上验证** |
| `tpctl` 本机命令行：管理 tailproxy + 内置官方 tailscale 客户端（操作主节点）+ schema | 已实现；Linux / macOS 走 Unix 套接字，Windows 走命名管道（由 CI 在真实 Windows 上验证） |
| UDP 代理（Linux 透明捕获，`capture.udp: proxy`）：按规则经出口节点 / 直连转发 UDP（如 QUIC） | 已实现；网络命名空间集成测试覆盖，**尚未在真实路由器和出口节点上验证**；中继出口不承载 UDP |
| TUN 模式（`capture.mode: tun`）：TUN 设备 + gVisor 用户态协议栈，路由 + 协议栈内 DNS | Linux / macOS（utun）/ Windows（Wintun）已实现，三个平台都在 GitHub Actions 上用真实 TUN 设备跑通集成测试（DNS→FakeIP、TCP、UDP 到出口）；运行时自动把系统 DNS 指向协议栈内 DNS、退出时恢复（`capture.tun_system_dns`，CI 中三个平台都用系统解析器验证过）；Windows 需要 `wintun.dll`；支持 selective 和 all 范围（all：Linux 在网络命名空间里用真实设备测试）；Android / iOS 走移动端 SDK（应用为 TODO）；尚未在真实桌面上长期使用 |
| 嵌入式 SDK（`sdk`）：在其他 Go 程序里内嵌 tailproxy——经规则拨号（`DialContext` / `HTTPClient`）、SOCKS5 入口、接管 VPN 的 TUN 设备或文件描述符 | 已实现；单元测试 + 网络命名空间里用真实 TUN 文件描述符的集成测试（CI） |
| 移动端 SDK（`sdk/mobile`，gomobile）：Android AAR / iOS xcframework 的绑定接口 | 已实现；CI 中交叉编译 Android / iOS 并用 gobind 生成 Java 绑定；**Android / iOS 应用本身是 TODO**，未在真机上运行 |

## 启动与管理

需要 Go 1.26.6 及以上版本（`tailscale.com` v1.102.4 的要求）。本地 Go 较旧时，可以用 `GOTOOLCHAIN=go1.26.6 go build ...` 自动下载对应的工具链。

```sh
go build -o tailproxy ./cmd/tailproxy
./tailproxy check -c config.example.yaml   # 只校验配置，不启动
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
- **规则**：规则列表、可视化编辑，以及规则测试（输入域名 / IP / ECH 外层 SNI / 端口，查看命中哪条规则、走哪个出口）。
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
- SOCKS5 入口没有认证，所以只允许监听回环地址。支持 TCP CONNECT 和 UDP ASSOCIATE（RFC 1928 §7）：
  - UDP 中继端口开在与 SOCKS 监听相同的回环地址上，只接受发起关联的 TCP 连接所在 IP 的数据报，第一个数据报的源端口确定后只认这个端口；TCP 控制连接关闭时关联和它的所有 UDP 流一起结束。
  - 每个目的地址是一条 UDP 流，和 CONNECT 一样按规则选出口（直连或出口节点；中继出口不承载 UDP，这类流量被丢弃），空闲 5 分钟结束；面板和 `tpctl conns` 里显示为 `socks5`、`/udp`。
  - 不支持分片（FRAG 不为 0 的数据报按 RFC 要求丢弃）；BIND 命令不支持。
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
  udp: block                # block（默认）| proxy
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
- 连接的域名来源依次是：FakeIP 反查、TLS ClientHello 的 SNI（UDP 为 QUIC Initial 中的 SNI）、HTTP 的 Host。ECH 连接的 SNI 只是服务商的外层公共名（如 `cloudflare-ech.com`），不当作域名：普通域名规则不会匹配它，只有 `outer_sni` 规则会（见下文）；面板上显示为「ECH，外层 SNI …」。
- **UDP**：
  - `capture.udp: block`（默认）：发往 FakeIP 的 UDP（如 QUIC）立即返回「不可达」，应用马上改用 TCP；其他 UDP 不经过 tailproxy。
  - `capture.udp: proxy`：UDP 和 TCP 使用同样的捕获范围和规则（53 端口除外，仍交给 DNS）。每个「客户端地址 × 原目的地址」是一条流，第一包决定路由：FakeIP 反查；否则读 QUIC Initial 包里 ClientHello 的 SNI（Initial 包的密钥由客户端选的连接 ID 派生，不需要任何私钥；ClientHello 跨多个数据报时会合并，最多等 150 毫秒）；再否则用学到的域名或 IP 规则。5 分钟没有数据包后结束。出口节点经 tsnet 转发 UDP，`direct` 带绕行标记直连。**中继出口只承载 TCP**，命中中继的 UDP 会被丢弃，QUIC 客户端会改用 TCP（可能要等到它自己的超时）。面板和 `tpctl conns` 里这类流标为 UDP。
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
- **`outer_sni` 规则（L4）**：ECH 连接查不到真实域名时，可以按外层 SNI 粗粒度分流，例如把所有经 Cloudflare ECH 的连接交给某个出口：

  ```yaml
  rules:
    - { outer_sni: [cloudflare-ech.com], port: [443], egress: us }
  ```

  按后缀匹配；和同一条规则里的域名条件、`ip_cidr` 是「或」，和 `port` 是「且」。只在 ClientHello 带 ECH、又没有 FakeIP 映射或学到的域名时参与；命中后 `unknown_domain` 不再生效，出口按目的 IP 连接。外层名背后可能是任意网站，所以这是粗粒度的兜底。selective 模式只捕获 FakeIP、`ip_cidr` 和学到的地址，要让 `outer_sni` 看到其他 ECH 连接，需要 `capture.scope: all`。
- **可见度统计（L0）**：面板「连接」页会统计透明捕获连接的域名来源（FakeIP / SNI / 未知）、带 ECH 的连接数和拦截的 DoH 次数，并列出「域名未知」最多的目的地，直接给出旁路影响有多大。

防回环：Tailscale 在 Linux 上以 root 运行时，会给自己的套接字打 `SO_MARK 0x80000`（`tailscale.com/net/netns`），tsnet 同样如此。tailproxy 的直连和上游 DNS 查询也打这个标记，nft 规则会放过带这个标记的包，所以既不会回环，也不会把 tsnet 自己的 WireGuard 流量再抓回来。

### TUN 模式（`capture.mode: tun`）

不想用 nftables，或在 macOS / Windows 上使用时，TUN 模式用一块虚拟网卡加用户态 TCP/IP 协议栈（gVisor netstack）接管流量，规则、FakeIP、SNI / QUIC 嗅探、出口都和 TPROXY 一样：

```yaml
capture:
  mode: tun
  tun_name: tailproxy0        # 默认
  tun_address: 172.19.0.1/30  # 默认；172.19.0.2 是协议栈内的 DNS
  tun_system_dns: auto        # 默认：运行时把系统 DNS 指向 172.19.0.2，退出时恢复；off 不改
  udp: proxy                  # 或 block（默认：UDP 立即回 ICMP 不可达）
dns:
  mode: fakeip
```

- 需要 root / 管理员权限。tailproxy 创建设备，把 FakeIP 地址池、规则里的 `ip_cidr`、学到的地址和 DNS 地址路由进设备（`scope: selective`，默认）。
- `scope: all`：默认路由也进入设备（拆成 `0.0.0.0/1`、`128.0.0.0/1`、`::/1`、`8000::/1`，系统原来的默认路由保留，仍指向物理网卡），所有 TCP/UDP 都经过规则，没有域名的连接靠 SNI / HTTP Host / QUIC 嗅探和学到的地址。
  - 排除网段：`capture.exclude_cidr` 和与 tproxy 相同的默认排除（本机、局域网私有地址、链路本地、组播、保留地址、tailnet 的 100.64.0.0/10 和 fd7a:115c:a1e0::/48）直连、不经规则；被规则 `ip_cidr`、FakeIP 池或学到的地址覆盖的默认排除网段仍按规则走，`exclude_cidr` 总是优先。Linux 上排除网段用路由表 7894 里的 throw 路由退回 main 表，根本不进设备（ping 等也正常）；macOS / Windows 上它们会进入设备，由 tailproxy 绑定物理网卡直连，所以只有 TCP / UDP 可用（已直连的局域网网段有更具体的系统路由，不受影响）。
  - `udp: block` 时只有发往 FakeIP 的 UDP 立即不可达，其他 UDP 直连（和 tproxy 不捕获 UDP 的效果一致）；`udp: proxy` 时 UDP 按规则走。
  - ICMP（ping）到被捕获的地址没有响应；启用前已建立、且目的地址被捕获的连接可能中断（协议栈里没有它们的状态，未实测）。
  - 验证情况：Linux 在网络命名空间里用真实设备测试（被规则捕获的地址到达出口、排除网段不进设备、关闭后 throw 路由删除）；macOS / Windows 的 CI 测试验证了 tailproxy 自己的直连会绑定物理网卡离开设备（把 1.1.1.1/32 路由进 TUN 后，HTTP 请求经协议栈直连成功），但为了不切断 CI runner 自己的连接，没有在 runner 上装默认路由；尚未在真实桌面上用 all 范围长期使用。
- 各平台的路由和防回环：
  - **Linux**：独立路由表 7894（策略规则优先级 9895）；带绕行标记 `0x80000` 的包（tailproxy 自己的直连、上游 DNS，以及 tsnet）先查 main 表（优先级 9894），不会回环。
  - **macOS**：设备名固定为 `utunN`（内核分配 N，`tun_name` 不以 `utun` 开头时忽略）；用 `ifconfig` / `route` 添加指向该接口的路由；tailproxy 自己的出站套接字用 `IP_BOUND_IF` 绑定到默认路由所在的物理网卡。
  - **Windows**：Wintun，需要把 [wintun.dll](https://www.wintun.net) 放在 `tailproxy.exe` 同一目录；地址和路由通过 IP Helper API 设置；出站套接字用 `IP_UNICAST_IF` 绑定到默认路由网卡。
  - macOS / Windows 上 tsnet 自己的套接字不经过这些路由（只把 FakeIP 池和规则网段路由进设备），所以不会被抓回来；访问回环地址的连接不绑定网卡。
- **系统 DNS**（`capture.tun_system_dns: auto`，默认）：启动后把系统 DNS 指向 `172.19.0.2`，退出时恢复：
  - Linux：通过 systemd-resolved 给 TUN 网卡设置 DNS 和仅路由域 `~.`（`resolvectl dns/domain`），所有没有被其他网卡更具体的路由域匹配的查询都发往 tailproxy；设备删除时设置随之消失。没有 systemd-resolved 时只打印警告，需要手动改 `/etc/resolv.conf`。
  - macOS：用 `networksetup -setdnsservers` 修改每个网络服务的 DNS（与 wg-quick 的做法相同），原设置保存在 `/var/db/tailproxy/dns-backup.json`；崩溃后下次启动或 `sudo tailproxy capture down` 会恢复。
  - Windows：给 Wintun 网卡设置 DNS 并把接口跃点数设为 0（与 wireguard-windows 相同），并清空 DNS 缓存；网卡删除时设置随之消失。CI 中设置后约 8 秒系统解析器才开始使用它，之前的查询仍走原来的 DNS。
  - 设置失败时只打印警告，面板的捕获组件会显示状态；也可以设 `off` 手动配置，例如 Linux `resolvectl dns tailproxy0 172.19.0.2; resolvectl domain tailproxy0 '~.'`，macOS `networksetup -setdnsservers Wi-Fi 172.19.0.2`（恢复：`... Wi-Fi empty`），Windows `Set-DnsClientServerAddress -InterfaceAlias <物理网卡> -ServerAddresses 172.19.0.2`（恢复：`-ResetServerAddresses`）。
  - `dns.direct_upstream: system` 会跳过 `172.19.0.2`，避免 tailproxy 把查询转发给自己；Windows 上 `system` 读取已启用网卡的 DNS 设置（跳过回环、链路本地和 `fec0::` 占位地址）。
  - 也可以另设 `capture.dns_listen` 让 DNS 同时监听主机地址。
- DoH 封堵只有域名部分生效（DNS 和 SNI），按 IP 封堵依赖 nftables，只在 tproxy 模式下有。
- 停止时设备和路由随之删除；`tailproxy capture down` 也会清理残留的策略规则。

**验证情况**：`internal/tunstack` 的单元测试用第二个用户态协议栈当客户端（不需要 root，所有系统上都跑）。`TestTUNIntegration` 创建真实 TUN 设备，经设备做 DNS（得到 FakeIP）、HTTP 和 UDP 到出口：Linux 在网络命名空间里跑，另外检查 `udp: block` 时内核 UDP 套接字立即得到 ECONNREFUSED、关闭后策略规则被删除；macOS（utun）和 Windows（Wintun 0.14.1）在 GitHub Actions 的 runner 上以 root / 管理员身份跑（`TP_TUN_INTEGRATION=1`）。系统 DNS：macOS、Windows 和 Ubuntu 主机命名空间（systemd-resolved，`TestTUNSystemDNS`）上设置后，用系统解析器解析规则域名得到 FakeIP，关闭后检查系统 DNS 设置与之前一致。`tailproxy run` 的 TUN 模式在 Linux 网络命名空间里手动跑通过（reject 规则、面板显示 TUN 入口）。还没有在真实桌面上长期使用；Windows 上与出口节点默认路由共存（DESIGN R5）尚未验证。

**崩溃恢复**：进程异常退出时，规则可能会残留，导致被捕获的流量没有去处。可以用 `sudo tailproxy capture down` 立即删除。systemd 服务已经加了 `ExecStopPost=-tailproxy capture down`，服务停止或崩溃时会自动清理；下次启动时也会先清掉残留。

**要求**：root；nftables（`nft` 命令）；内核支持 `nft_tproxy` / `nft_socket`（OpenWrt：`opkg install nftables kmod-nft-tproxy kmod-nft-socket`）。策略路由直接通过 netlink 设置，不依赖 `ip` 命令。IPv6 被禁用的主机会自动只用 IPv4。

**验证情况**：`internal/capture` 的集成测试在独立的网络命名空间里跑真实的 nftables TPROXY，覆盖以下内容：UDP 代理（经 FakeIP 和 `ip_cidr` 交给出口、回包源地址是客户端发往的地址、QUIC Initial 按 SNI 分流、中继目标不回包、发往被捕获地址的 DNS 仍由 DNS 前端处理）；QUIC 解密用 RFC 9001 / RFC 9369 附录 A 的测试向量验证；DNS 劫持得到 FakeIP；FakeIP 连接按域名交给出口；`ip_cidr` + Host 嗅探；某个端口走 direct 的 FakeIP 域名（带绕行标记、用上游解析，不会再拿到 FakeIP）；UDP 到 FakeIP 立即不可达；DoH 域名 NXDOMAIN；DoH IP 的 443 和 853 端口立即 RST；带绕行标记的连接不被拦；SNI 为 DoH 端点的连接被拒；all 模式；real 模式下从 DNS 应答学到的地址被 selective 捕获，没有 SNI / Host 的连接按学到的域名交给出口；清理后无残留。还没有在真实路由器或局域网客户端上验证。

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
  tpctl rules test - 443 --outer-sni cloudflare-ech.com   # ECH 连接按外层 SNI 会走哪个出口
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
  - tailproxy 运行时，会把主节点的 LocalAPI 开放给本机：
    - **Linux / macOS**：状态目录里的 Unix 套接字 `tailscaled.sock`，目录权限 700，套接字权限 600，只有运行 tailproxy 的用户能用。路径超过 Unix 套接字长度上限时，改放在 `$TMPDIR/tailproxy-<uid>/`。
    - **Windows**：随机命名的命名管道 `\\.\pipe\tailproxy-<随机>`，DACL 只允许当前用户和 SYSTEM，并且不继承上级权限。Tailscale 自己的管道允许所有用户连接，再逐个连接检查令牌；tailproxy 不做这种检查，所以直接在管道上限制。同名管道已存在时监听会失败（`FILE_CREATE`），不会被抢注的管道冒充。
    - 实际路径记在 `tailproxy.json` 里，tpctl 从那里读取。
  - `down` / `logout` / `up` / `set` / `switch` 会影响主节点，中继和设备列表都依赖它，所以需要加 `--yes` 确认（通过 `tailscale` 软链接调用时不需要，和官方客户端一致）。

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

在「规则」页点「编辑规则」，可以：增删规则、上下移动（首条命中，顺序很重要）、为每条规则选择目标出口、分别填写关键词 / 后缀 / 完整域名 / IP 段 / ECH 外层 SNI / 端口，以及设置兜底（final）。编辑期间，规则测试使用尚未保存的草稿。

点「保存」后：

1. 服务端按与启动时相同的规则校验（目标必须存在、final 只能放最后、CIDR 合法等），失败时列出错误并标红对应规则，文件不做任何改动。
2. 只替换配置文件里顶层的 `rules:` 段，**文件其余部分逐字节保持不变**（包括注释和对齐）。`rules:` 段内原有的注释不会保留。
3. 写入前把旧文件另存为 `<配置文件>.bak`，再用「临时文件 + rename」原子替换，然后重新解析写好的文件，确认与提交的规则一致。
4. 新规则立即生效，不需要重启。

如果开始编辑后配置文件被手动修改、被重新加载，或者被另一个会话保存过，保存会返回 409 冲突，而不是覆盖别人的修改。

### 浏览器策略：关闭浏览器自带的 DoH（L5，需明确执行）

浏览器自带 DoH 时会绕过系统 DNS，FakeIP 和按域名分流就拿不到域名。`tailproxy doctor` 可以写入浏览器的企业策略把它关掉，写入前列出所有改动并要求输入 `yes`，随时可以一键撤销：

```sh
sudo tailproxy doctor                              # 只查看：将写入什么、当前是否已应用
sudo tailproxy doctor --apply-browser-policy       # 写入（加 --disable-ech 同时关闭 Chrome 的 ECH；--yes 跳过确认）
sudo tailproxy doctor --revert-browser-policy      # 撤销，恢复原来的值
```

| 浏览器 | 写入的策略 | Linux | macOS | Windows |
|---|---|---|---|---|
| Chrome / Chromium | `DnsOverHttpsMode = "off"`；可选 `EncryptedClientHelloEnabled = false` | `/etc/opt/chrome/policies/managed/tailproxy.json`；Chromium 为 `/etc/chromium/…` 和 Ubuntu 的 `/etc/chromium-browser/…` | `defaults`：`/Library/Preferences/com.google.Chrome`（**推荐**级别，用户仍可改回；强制级别需要 MDM 描述文件） | `HKLM\SOFTWARE\Policies\Google\Chrome` |
| Edge | `DnsOverHttpsMode = "off"` | `/etc/opt/edge/policies/managed/tailproxy.json` | `defaults`：`/Library/Preferences/com.microsoft.Edge`（推荐级别） | `HKLM\SOFTWARE\Policies\Microsoft\Edge` |
| Firefox | `DNSOverHTTPS {Enabled: false, Locked: true}` | `/etc/firefox/policies/policies.json`（合并，保留其他策略） | `Firefox.app/Contents/Resources/distribution/policies.json` | `HKLM\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS` |

- Linux / macOS 只为检测到已安装的浏览器写入（`--all-browsers` 强制全部）；Windows 三个浏览器的注册表项都写入（未安装的浏览器不受影响）。
- 每项改动的原值记录在 `/var/lib/tailproxy/browser-policy.json`（macOS `/var/db/tailproxy/…`，Windows `%ProgramData%\tailproxy\…`），撤销时按记录逐项恢复；写入中途失败会自动回滚。
- 重启浏览器后生效，可在 `chrome://policy`、`edge://policy`、`about:policies` 查看。
- 验证情况：三个平台的写入与撤销都有测试（Linux 用临时目录、macOS 用临时 plist 和真实 `defaults`、Windows 用 HKCU 下的临时键和真实注册表），在 CI 中运行；**没有在真实浏览器里确认策略生效**。

### 嵌入式 SDK：把 tailproxy 放进你的应用

除了作为独立服务运行，tailproxy 也可以作为库嵌入其他程序：同样的规则、出口节点 / 中继出口、tailnet 访问、FakeIP DNS 和连接追踪，但不需要另起进程，也不改系统路由。

**Go**（`github.com/NannaOlympicBroadcast/tailproxy/sdk`）：

```go
cfg, _ := sdk.LoadConfig("config.yaml")          // 与服务相同的配置格式
eng, _ := sdk.New(sdk.Options{Config: cfg, StateDir: "/var/lib/myapp/tailproxy"})
eng.Start(ctx)                                    // 后台启动主节点和出口节点（auth key 或 eng.Account().Main.AuthURL 登录）
defer eng.Close()

resp, err := eng.HTTPClient().Get("https://api.openai.com/v1/models") // 按规则走出口
conn, err := eng.DialContext(ctx, "tcp", "db.internal:5432")            // tcp / udp，被拒绝时返回 sdk.ErrRejected
ln, _ := sdk.ListenSOCKS("127.0.0.1:1080"); go eng.ServeSOCKS(ctx, ln) // 给其他进程用的 SOCKS5（CONNECT + UDP）
```

| 能力 | 接口 |
|---|---|
| 经规则拨号 / HTTP | `DialContext(ctx, "tcp"|"udp", "host:port")`、`HTTPClient()`；连接在 `Connections()` 中显示为 `sdk` 入口 |
| SOCKS5 入口 | `ListenSOCKS`（只允许回环地址）+ `ServeSOCKS` |
| VPN / TUN | `ServeTUN(ctx, tun.Device, TUNOptions)`、`ServeTUNFD(ctx, fd, mtu, TUNOptions)`：协议栈内 DNS（FakeIP）、TCP/UDP 按规则转发；路由和系统 DNS 由应用 / 平台 VPN 设置 |
| 绕过自身 VPN | `Options.Protect func(fd int) bool`：tailproxy 自己的直连、上游 DNS，以及 Android 上 Tailscale 节点的套接字在连接前交给它（Android 传 `VpnService.protect`） |
| 查询与控制 | `Match`、`Connections`、`Egress`、`Account`、`SetConfig`（热更新规则和出口）、`SetAuthKey` |

**Android / iOS**（`sdk/mobile`，gomobile 绑定，只用字符串 / 整数 / 小接口，结构化数据为 JSON）：

```sh
gomobile bind -target=android -androidapi 24 ./sdk/mobile   # 生成 AAR
gomobile bind -target=ios ./sdk/mobile                       # 生成 xcframework
```

```kotlin
val engine = Engine(configYaml, filesDir.path + "/tailproxy", logger, protector /* 调 VpnService.protect */)
engine.start()
val fd = Builder().addAddress("172.19.0.1", 30).addDnsServer("172.19.0.2")
    .addRoute("198.18.0.0", 15).addRoute("172.19.0.2", 32).establish()!!.detachFd()
engine.startTUN(fd.toLong(), 1500, "172.19.0.2", "223.5.5.5,119.29.29.29")
// engine.accountJSON() / connectionsJSON() / matchJSON(...) / updateConfig(...) / stop()
```

- 系统级捕获（nftables TPROXY、创建 TUN 设备和路由、修改系统 DNS、浏览器策略）只在 `tailproxy` 命令里提供，SDK 不做。
- 验证情况：Go SDK 有单元测试，并在网络命名空间里把真实 TUN 设备的文件描述符交给 `ServeTUNFD`（像 VPN 应用那样）测试了 DNS→FakeIP、上游转发经 `Protect`、按规则拒绝、UDP 立即不可达；移动端包在 CI 中交叉编译 Android / iOS，并用 gobind 生成 Java 绑定检查接口可绑定。**Android / iOS 应用本身是 TODO**，SDK 还没有在真机上运行过。

### 访问控制

- **所有 API 和 `/metrics` 都需要令牌**（`Authorization: Bearer <令牌>`），只有登录页本身的静态文件不需要。令牌用常数时间比较。
- 令牌由 32 字节随机数生成，持久化在权限 600 的文件里（目录权限 700）。**能以你的用户身份读取这个文件的人（包括 root）都能登录面板**；怀疑泄露时用 `tailproxy token --rotate` 更换并重启服务。一键登录链接把令牌放在 `#` 后面，这一部分不会发送给服务器，页面读取后会立即从地址栏移除。
- 令牌只打印到执行 `start` 的终端，不写进 `tailproxy.log`。用 `tailproxy run` 在前台运行时令牌会打印到 stderr：如果用 systemd 等方式把前台输出写进日志，能读日志的人也能拿到令牌。
- 默认只监听 `127.0.0.1:7708`，并且只接受回环地址的 `Host` 头，用来防御 DNS 重绑定攻击。
- 所有写操作（保存规则、重新加载配置）都会拒绝跨站请求（检查 `Origin` 和 `Sec-Fetch-Site`），防止你浏览器里打开的其他网页偷偷改规则；保存规则还要求 `Content-Type: application/json`。
- `panel.listen` 可以设为局域网地址，访问同样需要令牌；这时不再校验 `Host` 头。
- `panel.tailnet: true`：主节点接入 tailnet 后，面板和 API 同时监听主节点 tailnet 地址上与 `panel.listen` 相同的端口（例如 `http://100.x.y.z:7708`，或 MagicDNS 名 `http://tailproxy.<tailnet>.ts.net:7708`）。
  - 仍然需要令牌（`tailproxy token` 查看）；谁能连上这个端口由 Tailscale ACL 决定。
  - 该监听只接受 Tailscale 地址（100.64.0.0/10、fd7a:115c:a1e0::/48）、`*.ts.net` 名和短 MagicDNS 名作为 Host，防 DNS 重绑定；本机 `panel.listen` 仍只接受回环 Host。
  - 主节点重新登录或重启时自动重新监听；面板「组件」里的 panel 一行显示 tailnet 地址。修改该项需要重启 tailproxy。
  - 验证情况：监听 / 重新监听逻辑和 Host 检查有单元测试（用本地监听代替 tsnet），尚未在真实 tailnet 上验证。

## 测试

```sh
go test ./...
```
