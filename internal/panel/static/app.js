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

async function loadEgress() {
  const e = await api("/api/v1/egress");
  $("egress-detail").textContent = e.detail || "";
  $("egress-detail").hidden = !e.detail;
  const rt = {};
  for (const r of e.runtime || []) rt[r.name] = r;
  const tb = $("egress-list");
  tb.replaceChildren();
  if (!e.configured || e.configured.length === 0) {
    const tr = el("tr"); const td = el("td", "配置中没有出口", "muted"); td.colSpan = 5; tr.append(td); tb.append(tr);
    return;
  }
  for (const x of e.configured) {
    const r = rt[x.name];
    const tr = el("tr");
    tr.append(el("td", x.name));
    tr.append(el("td", x.type ? (x.type === "fallback" ? "组：故障转移" : "组：延迟优选") : "槽位"));
    const target = el("td");
    if (x.type) {
      target.append(el("div", (x.members || []).join(", ")));
      if (r && r.selected) target.append(el("div", "当前使用：" + r.selected, "muted"));
      if (x.health_check) target.append(el("div", `健康检查 ${x.health_check.url} / ${x.health_check.interval}`, "muted"));
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
      d.append(safeHttpsLink(r.auth_url, "打开 Tailscale 登录链接"));
      st.append(d);
    }
    tr.append(st);
    const info = el("td", null, "muted");
    if (r && r.hostname) info.append(el("div", r.hostname));
    if (r && r.tailscale_ips && r.tailscale_ips.length) info.append(el("div", r.tailscale_ips.join(" ")));
    if (r && r.health) {
      const h = r.health;
      info.append(el("div", h.ok ? `健康 ✓ ${h.rtt_ms.toFixed(0)} ms` : `健康 ✗ ${h.error || ""}`));
    }
    tr.append(info);
    tb.append(tr);
  }
}

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
