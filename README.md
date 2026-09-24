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

## 运行 Web 面板

需要 Go 1.24 及以上版本。

```sh
go build -o tailproxy ./cmd/tailproxy
./tailproxy -c config.example.yaml
```

启动时终端会打印面板地址和访问令牌：

```
tailproxy dev
  面板地址：http://127.0.0.1:7708/（监听 127.0.0.1:7708）
  访问令牌：<43 个字符的随机令牌>
  一键登录：http://127.0.0.1:7708/#token=<43 个字符的随机令牌>
  令牌在每次启动时随机生成，重启后失效；如需固定令牌，设置 panel.auth_token_env 指向的环境变量（至少 16 个字符）。
```

在浏览器里打开「一键登录」链接即可进入面板；也可以打开面板地址，再粘贴令牌登录。令牌保存在浏览器标签页的 sessionStorage 里，关闭标签页或点「退出」后需要重新登录。

需要固定令牌（例如给 Prometheus 抓取 `/metrics` 用）时，设置 `panel.auth_token_env` 指向的环境变量。这时令牌不会在终端显示：

```sh
TAILPROXY_PANEL_TOKEN='至少16个字符的令牌' ./tailproxy -c config.example.yaml
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
- 注意：随机令牌会打印到终端。如果用 systemd 等方式把输出写进日志，能读日志的人也能拿到令牌；这种情况建议改用环境变量设置固定令牌。
- 默认只监听 `127.0.0.1:7708`，并且只接受回环地址的 `Host` 头，用来防御 DNS 重绑定攻击。
- 所有写操作（保存规则、重新加载配置）都会拒绝跨站请求（检查 `Origin` 和 `Sec-Fetch-Site`），防止你浏览器里打开的其他网页偷偷改规则；保存规则还要求 `Content-Type: application/json`。
- `panel.listen` 可以设为局域网地址，访问同样需要令牌；这时不再校验 `Host` 头。
- `panel.tailnet`（只对 tailnet 开放面板）依赖 `ts` 槽位，尚未实现；设置后启动时会打印警告，面板仍只监听 `panel.listen`。

## 测试

```sh
go test ./...
```
