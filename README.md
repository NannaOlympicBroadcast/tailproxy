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
| 出口管理器（`internal/egress`）：每个出口一个内嵌 tsnet 节点、固定出口节点、经出口的 DoH 解析、故障转移 / 延迟优选组与健康检查 | 已实现；**尚未用真实出口节点做端到端验证**（见下文） |
| SOCKS5 入口（`internal/proxy`，仅 CONNECT、仅回环地址）+ 连接追踪 | 已实现 |
| 透明捕获（TUN / TPROXY）、FakeIP DNS、SNI 嗅探、UDP | 未实现 |

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
- **出口**：配置中的出口槽位和出口组。出口管理器尚未实现，所以运行状态一律显示「未运行」。
- **规则**：规则列表、可视化编辑，以及规则测试（输入域名 / IP / 端口，查看命中哪条规则、走哪个出口）。
- **配置**：当前生效的配置。

### 出口与 SOCKS5 入口

配置里的每个出口槽位（`egress` 中没有 `type` 的条目）都会在进程内启动一个独立的 Tailscale 节点：主机名为 `tailproxy-<名称>`，状态保存在 `<state-dir>/tsnet/<名称>`，重启后仍是同一台设备。节点上线后，会按 `exit_node` 在 tailnet 中查找出口节点，可以写主机名、MagicDNS 名、100.x IP 或 StableID，找到后把它设为该节点的出口。

**统一登录与可视化配置（面板「出口」页）**：

1. tailproxy 始终运行一个主节点（主机名 `tailproxy`，可用 `tailnet.hostname` 修改）。在「Tailscale 账号」里点「登录 Tailscale」**登录一次**即可。
2. 主节点登录后，「你账号下的设备」会列出 tailnet 中的所有设备：在线状态、最后在线时间、IP、系统、所有者，以及是否已批准为出口节点。
3. 对已批准的出口节点点「添加为出口」，就会新建一个出口：写回配置文件的 `egress:` 段，并立即启动对应的设备 `tailproxy-<名称>`。已配置的出口可以直接换成另一个出口节点，也可以删除；删除时，对应设备会从 tailnet 注销，本地状态也会删除。仍被规则引用的出口不能删除（保存时会报错）。
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
- **没有验证**：流量真正经由出口节点发出。这需要一个已登录的 tailnet 和已批准的出口节点，开发环境里没有。第一次使用时，建议通过两个出口分别访问 IP 回显服务（例如 `curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me`，并为它写好对应规则），确认返回的是出口节点的公网 IP。

**日志上传**：内嵌的 tsnet 与官方客户端一样，默认会把诊断日志上传到 `log.tailscale.com`。不希望上传时，启动前设置 `TS_NO_LOGS_NO_SUPPORT=true`（systemd 服务写进 `tailproxy.env`）。

### API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/v1/status` | 版本、运行时长、组件状态 |
| GET | `/api/v1/config` | 当前生效的配置（只包含环境变量名，不含密钥） |
| POST | `/api/v1/config/reload` | 重新加载配置文件；失败时保留旧配置 |
| GET | `/api/v1/egress` | 配置中的出口，以及每个槽位 / 组的运行状态（登录链接、Tailscale IP、出口节点、健康检查） |
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
