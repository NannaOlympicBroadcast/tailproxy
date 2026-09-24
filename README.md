# tailproxy

基于 Tailscale 的跨平台透明代理插件：按域名关键词 / 后缀 / IP CIDR 规则，把流量分流到不同的 Tailscale 出口节点。

- 设计文档：[docs/DESIGN.md](docs/DESIGN.md)

## 当前进度

| 模块 | 状态 |
|---|---|
| 配置加载与校验（`internal/config`） | 已实现 |
| 规则引擎（`internal/rule`，首条命中；keyword / suffix / domain / ip_cidr / port） | 已实现 |
| Web 面板 + REST API + `/metrics`（`internal/panel`，端口 7708） | 已实现 |
| 出口管理器（tsnet 槽位）、捕获层（TUN / TPROXY / SOCKS）、FakeIP DNS | 未实现 |

## 启动与管理

需要 Go 1.24 及以上版本。

```sh
go build -o tailproxy ./cmd/tailproxy
./tailproxy start --save-token -c config.example.yaml
```

`start` 会在后台启动服务，等面板真正开始监听后打印地址和令牌，然后退出前台：

```
tailproxy dev
  面板地址：http://127.0.0.1:7708/（监听 127.0.0.1:7708）
  访问令牌：<43 个字符的随机令牌>
  一键登录：http://127.0.0.1:7708/#token=<43 个字符的随机令牌>
  令牌已保存到 ~/.lighthousepro/tailproxy.token（权限 600），可用 tailproxy token 查看
  本进程运行期间令牌一直有效，不会过期；重启后会生成新令牌。如需固定令牌，设置 panel.auth_token_env 指向的环境变量（至少 16 个字符）。

  已在后台运行：pid 15734，日志 ~/.lighthousepro/tailproxy.log
  查看状态：tailproxy status    停止：tailproxy stop
```

| 命令 | 作用 |
|---|---|
| `tailproxy start [-c FILE] [--save-token]` | 后台启动。启动失败（配置错误、端口被占用等）时直接在终端报错，退出码为 1 |
| `tailproxy run [-c FILE] [--save-token]` | 前台运行，Ctrl-C 停止。旧用法 `tailproxy -c FILE` 等同于它 |
| `tailproxy status` | 是否在运行、pid、面板地址、运行时长、配置文件、日志、令牌保存在哪里 |
| `tailproxy token` | 打印已保存的令牌（启动时需要加 `--save-token`） |
| `tailproxy stop` | 发送 SIGTERM 让服务正常退出，最多等 10 秒 |

**令牌**：一个进程只有一个令牌，由这个进程启动时生成，运行多久都一直有效，不会过期；进程重启后生成新令牌，旧令牌立即失效。

**状态目录**默认是 `~/.lighthousepro`（权限 700），可用 `--state-dir` 修改：

| 文件 | 内容 | 生命周期 |
|---|---|---|
| `tailproxy.json` | 运行中实例的 pid、面板地址、配置路径等 | 进程退出时删除 |
| `tailproxy.token` | 访问令牌（只在加了 `--save-token` 时写入，权限 600） | 进程退出时删除 |
| `tailproxy.log` | 后台进程的输出（**不含令牌**） | 持续追加，目前没有自动轮转 |

同一个状态目录下同时只能运行一个实例，重复 `start` 会提示已在运行。进程被 `kill -9` 或崩溃后留下的状态文件和令牌文件，会在下一次 `status` / `start` / `token` 时识别为失效并清理。

后台进程脱离终端运行：独立会话（setsid）、没有控制终端、stdin 指向 `/dev/null`、工作目录为 `/`（因此配置文件路径会先转成绝对路径）。

**平台**：后台模式支持 Linux 和 macOS。Windows 目前只支持 `tailproxy run`（前台）；`tailproxy start` 在 Windows 上会明确报错，以后应改为注册成 Windows 服务。开机自启（systemd / launchd）尚未提供。

在浏览器里打开「一键登录」链接即可进入面板；也可以打开面板地址，再粘贴令牌登录。浏览器把令牌保存在当前标签页的 sessionStorage 里，关闭标签页或点「退出」后需要重新登录（令牌本身仍然有效）。

需要固定令牌（例如给 Prometheus 抓取 `/metrics` 用）时，设置 `panel.auth_token_env` 指向的环境变量。这时令牌不会在终端显示，也不会被 `--save-token` 写入文件：

```sh
TAILPROXY_PANEL_TOKEN='至少16个字符的令牌' ./tailproxy start -c config.example.yaml
curl -H "Authorization: Bearer $TAILPROXY_PANEL_TOKEN" http://127.0.0.1:7708/metrics
```

面板内容：

- **概览**：各组件状态、规则和出口数量、重新加载配置。
- **出口**：配置中的出口槽位和出口组。出口管理器尚未实现，所以运行状态一律显示「未运行」。
- **规则**：规则列表、可视化编辑，以及规则测试（输入域名 / IP / 端口，查看命中哪条规则、走哪个出口）。
- **配置**：当前生效的配置。

### API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/v1/status` | 版本、运行时长、组件状态 |
| GET | `/api/v1/config` | 当前生效的配置（只包含环境变量名，不含密钥） |
| POST | `/api/v1/config/reload` | 重新加载配置文件；失败时保留旧配置 |
| GET | `/api/v1/egress` | 配置中的出口（`runtime` 在出口管理器实现前为 `null`） |
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
- 随机令牌由 32 字节随机数生成，每次启动都不同，重启后旧令牌立即失效。一键登录链接把令牌放在 `#` 后面，这一部分不会发送给服务器，页面读取后会立即从地址栏移除。
- 随机令牌只打印到执行 `start` 的终端，不写进 `tailproxy.log`。用 `tailproxy run` 在前台运行时令牌会打印到 stderr：如果用 systemd 等方式把前台输出写进日志，能读日志的人也能拿到令牌，这种情况建议改用环境变量设置固定令牌。
- 默认只监听 `127.0.0.1:7708`，并且只接受回环地址的 `Host` 头，用来防御 DNS 重绑定攻击。
- 所有写操作（保存规则、重新加载配置）都会拒绝跨站请求（检查 `Origin` 和 `Sec-Fetch-Site`），防止你浏览器里打开的其他网页偷偷改规则；保存规则还要求 `Content-Type: application/json`。
- `panel.listen` 可以设为局域网地址，访问同样需要令牌；这时不再校验 `Host` 头。
- `panel.tailnet`（只对 tailnet 开放面板）依赖 `ts` 槽位，尚未实现；设置后启动时会打印警告，面板仍只监听 `panel.listen`。

## 测试

```sh
go test ./...
```
