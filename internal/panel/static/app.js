"use strict";

const TOKEN_KEY = "tailproxy.panelToken";
let token = "";
try { token = sessionStorage.getItem(TOKEN_KEY) || ""; } catch (_) { /* storage unavailable */ }

// One-click login link printed at startup: http://…/#token=<token>. The
// fragment never reaches the server; take the token and drop it from the URL.
(function takeTokenFromHash() {
  const m = /^#token=(.+)$/.exec(location.hash);
  if (!m) return;
  token = decodeURIComponent(m[1]);
  try { sessionStorage.setItem(TOKEN_KEY, token); } catch (_) { /* storage unavailable */ }
  history.replaceState(null, "", location.pathname + location.search + "#overview");
})();

function saveToken(t) {
  token = t;
  try {
    if (t) sessionStorage.setItem(TOKEN_KEY, t); else sessionStorage.removeItem(TOKEN_KEY);
  } catch (_) { /* storage unavailable */ }
}

const $ = (id) => document.getElementById(id);

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = String(text);
  if (cls) e.className = cls;
  return e;
}

class AuthError extends Error {}

async function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers);
  if (token) headers["Authorization"] = "Bearer " + token;
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  if (res.status === 401) throw new AuthError("unauthorized");
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(body.error || res.status + " " + res.statusText);
    err.status = res.status;
    if (Array.isArray(body.errors)) err.details = body.errors;
    throw err;
  }
  return body;
}

function showError(msg) {
  const b = $("error");
  b.textContent = msg;
  b.hidden = !msg;
}

function showLogin(show, message) {
  document.body.classList.toggle("locked", show);
  $("login").hidden = !show;
  const err = $("login-error");
  err.textContent = message || "";
  err.hidden = !message;
  if (show) {
    $("token").value = "";
    $("token").focus();
  } else {
    selectTab(currentTab());
  }
}

function currentTab() {
  const h = location.hash.replace("#", "");
  return ["overview", "egress", "rules", "connections", "config"].includes(h) ? h : "overview";
}

function selectTab(name) {
  document.querySelectorAll(".tab").forEach((t) => { t.hidden = t.id !== name; });
  document.querySelectorAll("nav a").forEach((a) => a.classList.toggle("active", a.dataset.tab === name));
}

function fmtDuration(sec) {
  const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60), s = sec % 60;
  if (d) return `${d}天${h}时`;
  if (h) return `${h}时${m}分`;
  if (m) return `${m}分${s}秒`;
  return `${s}秒`;
}

function fmtTime(iso) {
  const t = new Date(iso);
  return isNaN(t) ? iso : t.toLocaleString();
}

const STATE_TEXT = {
  running: "运行中", loaded: "已加载", ready: "就绪", idle: "空闲", disabled: "未启用", degraded: "部分就绪",
  not_implemented: "未实现", not_running: "未运行",
  starting: "启动中", needs_login: "需要登录", needs_machine_auth: "等待批准",
  exit_node_pending: "等待出口节点", exit_node_offline: "出口节点离线", stopped: "已停止", error: "错误",
  no_token: "缺少令牌", unreachable: "连不上中继", auth_failed: "令牌错误",
};

function stateBadge(state) {
  return el("span", STATE_TEXT[state] || state, "state " + state);
}

async function loadStatus() {
  const s = await api("/api/v1/status");
  $("version").textContent = s.version;
  $("uptime").textContent = fmtDuration(s.uptime_seconds);
  $("n-rules").textContent = s.rules;
  $("n-slots").textContent = s.egress_slots;
  $("n-groups").textContent = s.egress_groups;
  $("cfg-path").textContent = s.config_path;
  $("cfg-loaded").textContent = fmtTime(s.config_loaded);
  $("panel-listen").textContent = s.panel_listen;
  const src = s.token_source || "";
  $("auth").textContent = src.startsWith("file:") ? "持久化保存在 " + src.slice(5) + "（重启后不变）"
    : src.startsWith("env:") ? "来自环境变量 $" + src.slice(4)
    : "一次性令牌（进程退出即失效）";
  const tb = $("components");
  tb.replaceChildren();
  for (const c of s.components) {
    const tr = el("tr");
    tr.append(el("td", c.name));
    const st = el("td"); st.append(stateBadge(c.state)); tr.append(st);
    tr.append(el("td", c.detail || "", "muted"));
    tb.append(tr);
  }
}

function safeHttpsLink(url, text) {
  if (!/^https:\/\//.test(url || "")) return el("span", url || "");
  const a = el("a", text || url);
  a.href = url;
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  return a;
}

/* ---------- 出口页：账号、设备、出口 ---------- */

let egressState = { configured: [], runtime: [], revision: "" };
let tailnetState = { account: null, peers: null };
let addingFor = null; // {id, mode: "exit" | "relay"} of the open "添加" form
let tokenFor = null;  // relay egress whose "更新令牌" form is open

function egressMsg(text, kind) {
  const b = $("egress-msg");
  b.replaceChildren();
  if (!text) { b.hidden = true; return; }
  if (Array.isArray(text)) {
    b.append(el("strong", kind === "error" ? "保存失败" : ""), errorList(text));
  } else {
    b.textContent = text;
  }
  b.className = "banner " + (kind === "error" ? "error" : kind === "ok" ? "ok" : "warn");
  b.hidden = false;
}

function fmtAgo(iso) {
  const sec = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (sec < 90) return "刚刚";
  if (sec < 3600) return Math.round(sec / 60) + " 分钟前";
  if (sec < 86400 * 2) return Math.round(sec / 3600) + " 小时前";
  return Math.round(sec / 86400) + " 天前";
}

async function loadEgress() {
  const [e, t] = await Promise.all([
    api("/api/v1/egress"),
    api("/api/v1/tailnet").catch((err) => { if (err instanceof AuthError) throw err; return { error: err.message }; }),
  ]);
  egressState = e;
  tailnetState = t;
  $("egress-detail").textContent = e.detail || "";
  $("egress-detail").hidden = !e.detail;
  renderAccount();
  if (addingFor === null) renderPeers();
  if (tokenFor === null) renderEgressList();
}

function renderAccount() {
  const t = tailnetState;
  const body = $("account-body");
  body.replaceChildren();
  $("account-state").replaceChildren();
  if (t.error || !t.account) {
    body.append(el("p", "代理未运行，无法读取 Tailscale 状态" + (t.error ? "：" + t.error : ""), "muted"));
    $("authkey-box").hidden = true;
    return;
  }
  $("authkey-box").hidden = false;
  const a = t.account, m = a.main;
  $("account-state").append(stateBadge(m.state));
  if (m.state === "ready") {
    const p = el("p");
    p.append(el("span", "已登录 "), el("strong", m.login_name || "（未知账号）"));
    if (m.tailnet) p.append(el("span", " · tailnet " + m.tailnet));
    body.append(p);
    body.append(el("p", `主节点 ${m.hostname}${m.tailscale_ips && m.tailscale_ips.length ? "（" + m.tailscale_ips[0] + "）" : ""}：用于读取设备列表和访问 tailnet 内部，不使用出口节点。`, "muted"));
  } else if (m.state === "needs_login") {
    body.append(el("p", "只需登录一次：登录后自动读取你账号下的所有设备，之后在下方直接选择出口节点。"));
    if (m.auth_url) {
      const btn = safeHttpsLink(m.auth_url, "登录 Tailscale");
      btn.className = "button";
      body.append(btn);
    }
    if (a.auto_login) body.append(el("p", "已保存 auth key，主节点会自动登录，请稍候。", "muted"));
  } else {
    body.append(el("p", m.detail || "主节点状态：" + m.state, "muted"));
  }

  const st = $("authkey-status");
  const clear = $("authkey-clear");
  const input = $("authkey-input");
  const submit = $("authkey-form").querySelector("button[type=submit]");
  if (a.auth_key_source && a.auth_key_source.startsWith("env:")) {
    st.textContent = `来自环境变量 $${a.auth_key_source.slice(4)}（${a.auth_key_hint || ""}），新增出口会自动加入`;
    input.disabled = submit.disabled = clear.disabled = true;
  } else if (a.auth_key_source === "file") {
    st.textContent = `已保存（${a.auth_key_hint}），新增出口会自动加入`;
    input.disabled = submit.disabled = false;
    clear.disabled = false;
  } else {
    st.textContent = "未设置，新增出口需要各自点一次授权链接";
    input.disabled = submit.disabled = false;
    clear.disabled = true;
  }
  const link = $("authkey-link");
  if (/^https:\/\//.test(a.keys_url || "")) link.href = a.keys_url;
}

function suggestName(p) {
  let n = (p.hostname || p.name || "exit").toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 24) || "exit";
  const used = new Set(egressState.configured.map((e) => e.name));
  let cand = n, i = 2;
  while (used.has(cand)) cand = `${n}-${i++}`.slice(0, 40);
  return cand;
}

function renderPeers() {
  const tb = $("peer-list");
  tb.replaceChildren();
  const msg = (text) => { const tr = el("tr"); const td = el("td", text, "muted"); td.colSpan = 6; tr.append(td); tb.append(tr); };
  const t = tailnetState;
  if (t.error) return msg("读取失败：" + t.error);
  if (t.peers_error) return msg("读取设备失败：" + t.peers_error);
  if (!t.peers) return msg("登录 Tailscale 后，这里会列出你账号下的设备");
  const onlyOnline = $("peers-online").checked;
  const list = t.peers.filter((p) => !onlyOnline || p.online);
  if (!list.length) return msg(onlyOnline ? "没有在线的设备（取消「只看在线」可以查看全部）" : "tailnet 中没有其他设备");
  for (const p of list) {
    const tr = el("tr");
    const dev = el("td");
    dev.append(el("div", p.name));
    const sub = [p.hostname !== p.name ? p.hostname : "", p.owner, (p.tags || []).join(" ")].filter(Boolean).join(" · ");
    if (sub) dev.append(el("div", sub, "muted"));
    tr.append(dev);
    tr.append(el("td", (p.tailscale_ips || [])[0] || ""));
    tr.append(el("td", [p.os, p.country].filter(Boolean).join(" / ") || "—"));
    const on = el("td");
    on.append(el("span", p.online ? "在线" : "离线", "state " + (p.online ? "ready" : "stopped")));
    if (!p.online && p.last_seen) on.append(el("div", "最后在线 " + fmtAgo(p.last_seen), "muted"));
    tr.append(on);
    const ex = el("td");
    if (p.exit_node_option) ex.append(el("span", "已批准", "state ready"));
    else {
      const s = el("span", "未开启", "muted");
      s.title = "在该设备上执行 tailscale set --advertise-exit-node，并在管理后台批准（Edit route settings → Use as exit node）";
      ex.append(s);
    }
    tr.append(ex);
    tr.append(peerActions(p));
    tb.append(tr);
  }
}

function peerIPv4(p) {
  return (p.tailscale_ips || []).find((ip) => /^\d+\.\d+\.\d+\.\d+$/.test(ip)) || "";
}

async function putRelayToken(name, token) {
  await api(`/api/v1/egress/${encodeURIComponent(name)}/relay-token`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
  });
}

function peerActions(p) {
  const td = el("td");
  if (p.tailproxy) {
    td.append(el("span", p.tailproxy === "main" ? "tailproxy 主节点" : `tailproxy 出口 ${p.tailproxy} 的设备`, "muted"));
    return td;
  }
  if (p.used_by && p.used_by.length) td.append(el("div", "出口节点：" + p.used_by.join(", ")));
  if (p.relay_for && p.relay_for.length) td.append(el("div", "中继：" + p.relay_for.join(", ")));
  if (!addingFor || addingFor.id !== p.id) {
    const row = el("div", null, "row compact");
    if (p.exit_node_option) {
      const b = el("button", "添加为出口节点", "secondary");
      b.type = "button";
      b.title = "tailproxy 为它单独登录一台设备 tailproxy-<名称>，通过 Tailscale 出口节点转发";
      b.addEventListener("click", () => { addingFor = { id: p.id, mode: "exit" }; renderPeers(); });
      row.append(b);
    }
    if (peerIPv4(p)) {
      const b = el("button", "添加为中继", "secondary");
      b.type = "button";
      b.title = "该设备上运行 tailproxy relay：只用主节点一台设备，不需要开启出口节点";
      b.addEventListener("click", () => { addingFor = { id: p.id, mode: "relay" }; renderPeers(); });
      row.append(b);
    }
    if (row.childElementCount) td.append(row);
    else if (!td.childElementCount) td.append(el("span", "—", "muted"));
    return td;
  }
  const relay = addingFor.mode === "relay";
  const form = el("form", null, "row compact");
  const name = el("input");
  name.value = suggestName(p);
  name.setAttribute("aria-label", "出口名称");
  name.title = relay ? "出口名称：小写字母、数字和 -，会用在规则里" : "出口名称：小写字母、数字和 -，会用在规则里和设备名 tailproxy-<名称>";
  form.append(name);
  let port, token;
  if (relay) {
    port = el("input");
    port.type = "number"; port.min = "1"; port.max = "65535"; port.value = "1081";
    port.className = "port";
    port.setAttribute("aria-label", "中继端口");
    port.title = "tailproxy relay 的端口（默认 1081）";
    token = el("input");
    token.type = "password"; token.autocomplete = "off"; token.required = true;
    token.placeholder = "中继令牌";
    token.setAttribute("aria-label", "中继令牌");
    token.title = "在该设备上执行 tailproxy relay token 查看";
    form.append(port, token);
  }
  const ok = el("button", "添加");
  ok.type = "submit";
  const cancel = el("button", "取消", "secondary");
  cancel.type = "button";
  cancel.addEventListener("click", () => { addingFor = null; renderPeers(); });
  form.append(ok, cancel);
  if (relay) form.append(el("div", "先在该设备上运行 tailproxy relay（或 tailproxy service install --relay），令牌用 tailproxy relay token 查看。", "muted hint"));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const n = name.value.trim();
    const list = egressState.configured.slice();
    if (!relay) {
      list.push({ name: n, exit_node: p.hostname || p.name });
      if (await saveEgress(list, `已添加出口 ${n} → ${p.name}（出口节点）`)) addingFor = null;
      return;
    }
    const addr = `${peerIPv4(p)}:${port.value.trim() || "1081"}`;
    const tok = token.value.trim();
    if (tok.length < 16) { egressMsg("中继令牌至少 16 个字符（在该设备上执行 tailproxy relay token 查看）", "error"); return; }
    list.push({ name: n, relay: addr });
    if (!(await saveEgress(list, `已添加中继出口 ${n} → ${p.name}（${addr}）`))) return;
    addingFor = null;
    try {
      await putRelayToken(n, tok);
      egressMsg(`已添加中继出口 ${n} → ${p.name}（${addr}），正在连接中继`, "ok");
    } catch (err) {
      if (err instanceof AuthError) { authFailed(); return; }
      egressMsg(`出口 ${n} 已添加，但保存令牌失败：${err.message}。可以在「已配置的出口」里重新填写令牌。`, "error");
    }
    await loadEgress().catch(() => {});
  });
  td.append(form);
  setTimeout(() => name.focus(), 0);
  return td;
}

function renderEgressList() {
  const e = egressState;
  const rt = {};
  for (const r of e.runtime || []) rt[r.name] = r;
  const tb = $("egress-list");
  tb.replaceChildren();
  if (!e.configured || e.configured.length === 0) {
    const tr = el("tr"); const td = el("td", "还没有出口。登录后在上面的设备列表里点「添加为出口节点」或「添加为中继」。", "muted"); td.colSpan = 6; tr.append(td); tb.append(tr);
    return;
  }
  const exitPeers = (tailnetState.peers || []).filter((p) => p.exit_node_option && !p.tailproxy);
  e.configured.forEach((x, idx) => {
    const r = rt[x.name];
    const tr = el("tr");
    tr.append(el("td", x.name));
    tr.append(el("td", x.type ? (x.type === "fallback" ? "组：故障转移" : "组：延迟优选") : x.relay ? "中继" : "出口节点"));
    const target = el("td");
    if (x.type) {
      target.append(el("div", (x.members || []).join(", ")));
      if (r && r.selected) target.append(el("div", "当前使用：" + r.selected, "muted"));
      if (x.health_check) target.append(el("div", `健康检查 ${x.health_check.url} / ${x.health_check.interval}`, "muted"));
    } else if (x.relay) {
      target.append(el("div", x.relay));
      const peer = (tailnetState.peers || []).find((p) => (p.relay_for || []).includes(x.name));
      if (peer) target.append(el("div", `${peer.name}（${peer.online ? "在线" : "离线"}）`, "muted"));
    } else {
      target.append(el("div", x.exit_node));
      const en = r && r.exit_node;
      if (en && en.name) target.append(el("div", `${en.name}（${en.online ? "在线" : "离线"}）`, "muted"));
    }
    tr.append(target);
    const st = el("td");
    st.append(stateBadge(r ? r.state : "not_running"));
    if (r && r.detail) st.append(el("div", r.detail, "muted"));
    if (r && r.auth_url) {
      const d = el("div");
      d.append(safeHttpsLink(r.auth_url, "授权这台设备"));
      st.append(d);
    }
    tr.append(st);
    const info = el("td", null, "muted");
    if (r && r.hostname) info.append(el("div", r.hostname));
    if (x.relay) info.append(el("div", r && r.token_source ? (r.token_source === "file" ? "令牌：已保存" : `令牌：环境变量 $${r.token_source.slice(4)}`) : "令牌：未设置"));
    if (r && r.tailscale_ips && r.tailscale_ips.length) info.append(el("div", r.tailscale_ips[0]));
    if (r && r.health) info.append(el("div", r.health.ok ? `健康 ✓ ${r.health.rtt_ms.toFixed(0)} ms` : `健康 ✗ ${r.health.error || ""}`));
    tr.append(info);

    const act = el("td");
    if (x.relay) {
      if (tokenFor === x.name) {
        const f = el("form", null, "row compact");
        const inp = el("input");
        inp.type = "password"; inp.autocomplete = "off"; inp.placeholder = "新的中继令牌"; inp.required = true;
        inp.setAttribute("aria-label", `出口 ${x.name} 的中继令牌`);
        const save = el("button", "保存");
        save.type = "submit";
        const cancel = el("button", "取消", "secondary");
        cancel.type = "button";
        cancel.addEventListener("click", () => { tokenFor = null; renderEgressList(); });
        f.append(inp, save, cancel);
        f.addEventListener("submit", async (ev) => {
          ev.preventDefault();
          try {
            await putRelayToken(x.name, inp.value.trim());
            tokenFor = null;
            egressMsg(`出口 ${x.name} 的中继令牌已保存，正在重新连接`, "ok");
            await loadEgress();
          } catch (err) {
            if (err instanceof AuthError) { authFailed(); return; }
            egressMsg("保存令牌失败：" + err.message, "error");
          }
        });
        act.append(f);
        setTimeout(() => inp.focus(), 0);
      } else {
        const b = el("button", "更新令牌", "secondary");
        b.type = "button";
        b.disabled = !!(r && r.token_source && r.token_source.startsWith("env:"));
        b.title = b.disabled ? "令牌来自环境变量（relay_token_env），请在环境里修改" : "在中继设备上执行 tailproxy relay token 查看令牌";
        b.addEventListener("click", () => { tokenFor = x.name; renderEgressList(); });
        act.append(b);
      }
    } else if (!x.type) {
      const sel = el("select");
      sel.setAttribute("aria-label", `出口 ${x.name} 使用的节点`);
      const cur = new Option(`${x.exit_node}（当前）`, x.exit_node);
      sel.append(cur);
      for (const p of exitPeers) {
        const v = p.hostname || p.name;
        if (v !== x.exit_node) sel.append(new Option(`${p.name}${p.online ? "" : "（离线）"}`, v));
      }
      sel.disabled = sel.options.length < 2;
      sel.title = sel.disabled ? "登录后可以从 tailnet 的出口节点里选择" : "更换出口节点";
      sel.addEventListener("change", async () => {
        const list = egressState.configured.map((y, j) => (j === idx ? Object.assign({}, y, { exit_node: sel.value }) : y));
        await saveEgress(list, `出口 ${x.name} 已切换到 ${sel.value}`);
      });
      act.append(sel);
    }
    const del = el("button", "删除", "danger icon");
    del.type = "button";
    del.addEventListener("click", async () => {
      const what = x.type ? "" : x.relay ? "本地保存的中继令牌会一起删除（中继设备本身不受影响）。\n" : `它对应的设备 tailproxy-${x.name} 会从 tailnet 注销，本地状态也会删除。\n`;
      if (!confirm(`删除出口 ${x.name}？\n${what}仍在使用它的规则或出口组需要先改掉，否则保存会失败。`)) return;
      await saveEgress(egressState.configured.filter((_, j) => j !== idx), `已删除出口 ${x.name}`);
    });
    if (tokenFor !== x.name) act.append(del);
    tr.append(act);
    tb.append(tr);
  });
}

async function saveEgress(list, okText) {
  egressMsg("保存中…");
  try {
    const r = await api("/api/v1/egress", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ revision: egressState.revision, egress: list }),
    });
    await Promise.all([loadEgress(), loadRules(), loadConfig()]);
    egressMsg(r.warning || okText, r.warning ? "warn" : "ok");
    return true;
  } catch (err) {
    if (err instanceof AuthError) { authFailed(); return false; }
    egressMsg(err.details || err.message, "error");
    if (err.status === 409) await loadEgress().catch(() => {});
    return false;
  }
}

$("peers-online").addEventListener("change", renderPeers);

$("authkey-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const key = $("authkey-input").value.trim();
  if (!key) return;
  try {
    await api("/api/v1/tailnet/authkey", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ auth_key: key }) });
    $("authkey-input").value = "";
    egressMsg("auth key 已保存：正在等待登录的节点会用它自动登录，新增出口会自动加入", "ok");
    await loadEgress();
  } catch (err) {
    if (err instanceof AuthError) { authFailed(); return; }
    egressMsg("保存 auth key 失败：" + err.message, "error");
  }
});

$("authkey-clear").addEventListener("click", async () => {
  if (!confirm("删除已保存的 auth key？已登录的设备不受影响，之后新增的出口需要各自点授权链接。")) return;
  try {
    await api("/api/v1/tailnet/authkey", { method: "DELETE" });
    egressMsg("已删除保存的 auth key", "ok");
    await loadEgress();
  } catch (err) {
    if (err instanceof AuthError) { authFailed(); return; }
    egressMsg("删除失败：" + err.message, "error");
  }
});

function fmtBytes(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
  return (n / 1073741824).toFixed(2) + " GB";
}

function connRow(c, active) {
  const tr = el("tr");
  tr.append(el("td", new Date(c.started).toLocaleTimeString()));
  const dst = el("td");
  dst.append(el("div", `${c.host}:${c.port}`));
  dst.append(el("div", `${c.inbound} ${c.source}`, "muted"));
  tr.append(dst);
  tr.append(el("td", c.rule_index >= 0 ? `#${c.rule_index} ${c.reason}` : c.reason));
  tr.append(el("td", c.via && c.via !== c.target ? `${c.target} → ${c.via}` : c.target));
  tr.append(el("td", `↑ ${fmtBytes(c.up)}  ↓ ${fmtBytes(c.down)}`));
  const st = el("td");
  if (active) st.append(stateBadge("running"));
  else if (c.error) st.append(el("span", c.error, "conn-error"));
  else st.append(el("span", "已结束", "muted"));
  tr.append(st);
  return tr;
}

async function loadConnections() {
  let d;
  try {
    d = await api("/api/v1/connections");
  } catch (err) {
    if (err instanceof AuthError) throw err;
    $("conn-summary").textContent = "代理未运行：" + err.message;
    return;
  }
  $("conn-summary").textContent = `活动 ${d.active.length} 条，累计 ${d.total} 条，失败 ${d.failed} 条（最近结束的保留 200 条）`;
  const a = $("conn-active"), r = $("conn-recent");
  a.replaceChildren();
  r.replaceChildren();
  for (const c of d.active) a.append(connRow(c, true));
  for (const c of d.recent) r.append(connRow(c, false));
  if (!d.active.length) { const tr = el("tr"); const td = el("td", "没有活动连接", "muted"); td.colSpan = 6; tr.append(td); a.append(tr); }
  if (!d.recent.length) { const tr = el("tr"); const td = el("td", "还没有连接记录", "muted"); td.colSpan = 6; tr.append(td); r.append(tr); }
}

const COND_LABELS = [
  ["domain", "域名"], ["domain_suffix", "后缀"], ["domain_keyword", "关键词"], ["ip_cidr", "IP 段"], ["port", "端口"],
];

let rulesState = { rules: [], targets: [], revision: "" };

async function loadRules() {
  const r = await api("/api/v1/rules");
  rulesState = r;
  const tb = $("rule-list");
  tb.replaceChildren();
  r.rules.forEach((rule, i) => {
    const tr = el("tr");
    tr.append(el("td", i));
    const cond = el("td");
    if (rule.final) cond.append(el("span", "兜底（final）", "muted"));
    for (const [k, label] of COND_LABELS) {
      if (!rule[k] || !rule[k].length) continue;
      const line = el("div");
      line.append(el("span", label + "：", "muted"));
      for (const v of rule[k]) line.append(el("code", v, "tag"));
      cond.append(line);
    }
    tr.append(cond);
    tr.append(el("td", rule.final || rule.egress));
    tb.append(tr);
  });
  if (r.implicit_final) {
    const tr = el("tr", null, "muted");
    tr.append(el("td", "—"));
    tr.append(el("td", "未写 final，未命中的流量隐式走 direct"));
    tr.append(el("td", "direct"));
    tb.append(tr);
  }
}

async function loadConfig() {
  const c = await api("/api/v1/config");
  $("config-json").textContent = JSON.stringify(c, null, 2);
}

// authFailed is called when the server rejects the token. Unsaved rule edits
// stay in memory and are still there after logging in again.
function authFailed() {
  const hadToken = !!token;
  saveToken("");
  showLogin(true, hadToken ? "令牌无效：可能已用 tailproxy token --rotate 更换并重启了服务，或者服务是用一次性令牌启动的。在服务器上执行 tailproxy token 可以查看当前令牌。" : "");
}

async function refresh() {
  if (!token) { showLogin(true); return; }
  try {
    await Promise.all([loadStatus(), loadEgress(), loadRules(), loadConfig(), loadConnections()]);
    showError("");
    showLogin(false);
  } catch (err) {
    if (err instanceof AuthError) { authFailed(); return; }
    showError("加载失败：" + err.message);
  }
}

$("login").addEventListener("submit", (ev) => {
  ev.preventDefault();
  saveToken($("token").value.trim());
  refresh();
});

$("logout").addEventListener("click", () => {
  if (editing && dirty && !confirm("有未保存的规则修改，确定退出？")) return;
  if (editing) stopEdit();
  saveToken("");
  showLogin(true);
});

$("reload").addEventListener("click", async () => {
  const btn = $("reload"), msg = $("reload-msg");
  btn.disabled = true;
  msg.textContent = "";
  try {
    const r = await api("/api/v1/config/reload", { method: "POST" });
    msg.textContent = `已重新加载，共 ${r.rules} 条规则` + (r.warning ? `；${r.warning}` : "");
    await refresh();
  } catch (err) {
    msg.textContent = "重新加载失败：" + err.message;
  } finally {
    btn.disabled = false;
  }
});

$("test").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const out = $("test-result");
  const port = $("t-port").value;
  const body = { domain: $("t-domain").value.trim(), ip: $("t-ip").value.trim(), port: port ? Number(port) : 0 };
  out.hidden = false;
  out.replaceChildren(el("span", "测试中…", "muted"));
  try {
    if (editing) body.rules = buildDraftRules();
    const r = await api("/api/v1/rules/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const head = el("div", "目标：" + r.target, "target");
    if (editing) head.append(el("span", "草稿", "draft-tag"));
    out.replaceChildren(
      head,
      el("div", r.implicit ? "未命中任何规则" : `命中规则 #${r.rule_index}`),
      el("div", "原因：" + r.reason, "muted"),
    );
  } catch (err) {
    if (err instanceof AuthError) { authFailed(); return; }
    out.replaceChildren(el("span", "测试失败：" + err.message));
    if (err.details) out.append(errorList(err.details));
  }
});

/* ---------- 规则可视化编辑 ---------- */

const EDIT_FIELDS = [
  ["domain_keyword", "关键词（子串匹配）", "例：openai"],
  ["domain_suffix", "域名后缀", "例：.jp"],
  ["domain", "完整域名", "例：www.example.com"],
  ["ip_cidr", "IP 段", "例：203.0.113.0/24"],
  ["port", "端口（可选）", "例：443"],
];

let editing = false;
let dirty = false;
let draft = []; // [{target, domain_keyword: "text", ...}]
let editBaseRevision = "";

function splitValues(text) {
  return text.split(/[\s,，]+/).map((v) => v.trim()).filter(Boolean);
}

function errorList(items) {
  const ul = el("ul");
  for (const e of items) ul.append(el("li", e));
  return ul;
}

function markDirty() {
  dirty = true;
  $("edit-status").textContent = "有未保存的修改";
}

function startEdit() {
  const rules = rulesState.rules || [];
  const last = rules[rules.length - 1];
  const hasFinal = last && last.final;
  draft = (hasFinal ? rules.slice(0, -1) : rules).map((r) => {
    const d = { target: r.egress };
    for (const [k] of EDIT_FIELDS) d[k] = (r[k] || []).join("\n");
    return d;
  });
  editBaseRevision = rulesState.revision;
  editing = true;
  dirty = false;
  renderFinalSelect(hasFinal ? last.final : "");
  renderDraft();
  showEditErrors(null);
  $("edit-status").textContent = "";
  $("rule-view").hidden = true;
  $("rule-editor").hidden = false;
  $("edit-start").hidden = true;
  $("test-mode").textContent = "编辑期间，测试使用尚未保存的草稿。";
}

function stopEdit() {
  editing = false;
  dirty = false;
  $("rule-view").hidden = false;
  $("rule-editor").hidden = true;
  $("edit-start").hidden = false;
  $("test-mode").textContent = "结果来自正在运行的规则引擎。";
}

function targetSelect(value, allowNone) {
  const sel = el("select");
  if (allowNone) sel.append(new Option("不设置（未命中隐式走 direct）", ""));
  const targets = rulesState.targets || [];
  for (const t of targets) sel.append(new Option(t, t));
  if (value && !targets.includes(value)) sel.append(new Option(value + "（不存在）", value));
  sel.value = value || (allowNone ? "" : targets[0] || "");
  return sel;
}

function renderFinalSelect(value) {
  const old = $("edit-final");
  const sel = targetSelect(value, true);
  sel.id = "edit-final";
  sel.addEventListener("change", markDirty);
  old.replaceWith(sel);
}

function renderDraft() {
  const box = $("edit-rules");
  box.replaceChildren();
  if (draft.length === 0) box.append(el("p", "还没有规则。点「添加规则」新建一条。", "muted"));
  draft.forEach((d, i) => {
    const card = el("div", null, "rule-edit");
    card.dataset.index = i;
    const head = el("div", null, "head");
    head.append(el("span", "#" + i, "num"), el("span", "目标", "muted"));
    const sel = targetSelect(d.target, false);
    if (!d.target) d.target = sel.value;
    sel.addEventListener("change", () => { d.target = sel.value; markDirty(); });
    head.append(sel, el("span", null, "spacer"));
    const btn = (label, title, cls, fn, disabled) => {
      const b = el("button", label, cls);
      b.type = "button";
      b.title = title;
      b.setAttribute("aria-label", title);
      b.disabled = !!disabled;
      b.addEventListener("click", fn);
      return b;
    };
    head.append(
      btn("↑", "上移", "secondary icon", () => moveRule(i, -1), i === 0),
      btn("↓", "下移", "secondary icon", () => moveRule(i, 1), i === draft.length - 1),
      btn("删除", "删除这条规则", "danger icon", () => { draft.splice(i, 1); markDirty(); renderDraft(); }),
    );
    card.append(head);
    const fields = el("div", null, "fields");
    for (const [k, label, ph] of EDIT_FIELDS) {
      const wrap = el("div");
      const id = `edit-${i}-${k}`;
      const lab = el("label", label);
      lab.htmlFor = id;
      const ta = el("textarea");
      ta.id = id;
      ta.placeholder = ph;
      ta.value = d[k] || "";
      ta.spellcheck = false;
      ta.addEventListener("input", () => { d[k] = ta.value; markDirty(); });
      wrap.append(lab, ta);
      fields.append(wrap);
    }
    card.append(fields);
    box.append(card);
  });
}

function moveRule(i, delta) {
  const j = i + delta;
  if (j < 0 || j >= draft.length) return;
  [draft[i], draft[j]] = [draft[j], draft[i]];
  markDirty();
  renderDraft();
}

function buildDraftRules() {
  const rules = draft.map((d, i) => {
    const r = {};
    for (const [k] of EDIT_FIELDS) {
      const vals = splitValues(d[k] || "");
      if (!vals.length) continue;
      r[k] = k !== "port" ? vals : vals.map((v) => {
        const n = Number(v);
        if (!/^\d+$/.test(v) || n > 65535) throw new Error(`rules[${i}]: 端口 "${v}" 无效，必须是 0–65535 的整数`);
        return n;
      });
    }
    r.egress = d.target;
    return r;
  });
  const fin = $("edit-final").value;
  if (fin) rules.push({ final: fin });
  return rules;
}

function showEditErrors(items, conflict) {
  const box = $("edit-errors");
  document.querySelectorAll(".rule-edit.invalid").forEach((c) => c.classList.remove("invalid"));
  if (!items || !items.length) { box.hidden = true; box.replaceChildren(); return; }
  box.replaceChildren(el("strong", conflict ? "保存冲突" : "无法保存"), errorList(items));
  if (conflict) {
    const b = el("button", "放弃草稿并载入最新规则", "secondary");
    b.type = "button";
    b.addEventListener("click", async () => { await refresh(); startEdit(); });
    box.append(b);
  }
  box.hidden = false;
  for (const e of items) {
    const m = /^rules\[(\d+)\]/.exec(e);
    const card = m && document.querySelector(`.rule-edit[data-index="${m[1]}"]`);
    if (card) card.classList.add("invalid");
  }
}

async function saveRules() {
  let rules;
  try {
    rules = buildDraftRules();
  } catch (err) {
    showEditErrors([err.message]);
    return;
  }
  const btn = $("edit-save");
  btn.disabled = true;
  $("edit-status").textContent = "保存中…";
  try {
    const r = await api("/api/v1/rules", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ revision: editBaseRevision, rules }),
    });
    stopEdit();
    await refresh();
    $("edit-status").textContent = "";
    showSaved(`已保存 ${r.rules} 条规则，并已生效；旧配置备份在 ${r.backup}`);
  } catch (err) {
    if (err instanceof AuthError) { authFailed(); return; }
    $("edit-status").textContent = "";
    showEditErrors(err.details || [err.message], err.status === 409);
  } finally {
    btn.disabled = false;
  }
}

function showSaved(msg) {
  const out = $("test-result");
  out.hidden = false;
  out.replaceChildren(el("div", msg));
}

$("edit-start").addEventListener("click", startEdit);
$("edit-add").addEventListener("click", () => {
  draft.push({ target: "" });
  markDirty();
  renderDraft();
  const cards = document.querySelectorAll(".rule-edit");
  const last = cards[cards.length - 1];
  if (last) { last.scrollIntoView({ block: "nearest" }); last.querySelector("textarea").focus(); }
});
$("edit-cancel").addEventListener("click", () => {
  if (dirty && !confirm("放弃所有未保存的修改？")) return;
  stopEdit();
});
$("edit-save").addEventListener("click", saveRules);
window.addEventListener("beforeunload", (ev) => {
  if (editing && dirty) { ev.preventDefault(); ev.returnValue = ""; }
});

window.addEventListener("hashchange", () => { if ($("login").hidden) selectTab(currentTab()); });
refresh();
setInterval(() => {
  if (!$("login").hidden || document.hidden) return;
  loadStatus().catch(() => {});
  if (currentTab() === "egress") loadEgress().catch(() => {});
}, 5000);
setInterval(() => {
  if ($("login").hidden && !document.hidden && currentTab() === "connections") loadConnections().catch(() => {});
}, 2000);
