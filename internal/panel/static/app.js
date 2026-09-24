"use strict";

const TOKEN_KEY = "tailproxy.panelToken";
let token = "";
try { token = sessionStorage.getItem(TOKEN_KEY) || ""; } catch (_) { /* storage unavailable */ }

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
  if (!res.ok) throw new Error(body.error || res.status + " " + res.statusText);
  return body;
}

function showError(msg) {
  const b = $("error");
  b.textContent = msg;
  b.hidden = !msg;
}

function showLogin(show) {
  $("login").hidden = !show;
  document.querySelectorAll(".tab").forEach((t) => { if (show) t.hidden = true; });
  if (!show) selectTab(currentTab());
}

function currentTab() {
  const h = location.hash.replace("#", "");
  return ["overview", "egress", "rules", "config"].includes(h) ? h : "overview";
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
  running: "运行中", loaded: "已加载", ready: "就绪",
  not_implemented: "未实现", not_running: "未运行",
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
  $("auth").textContent = s.auth_enabled ? "已启用" : "未启用（仅回环地址可访问）";
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

async function loadEgress() {
  const e = await api("/api/v1/egress");
  $("egress-detail").textContent = e.detail || "";
  $("egress-detail").hidden = !e.detail;
  const tb = $("egress-list");
  tb.replaceChildren();
  if (!e.configured || e.configured.length === 0) {
    const tr = el("tr"); const td = el("td", "配置中没有出口", "muted"); td.colSpan = 5; tr.append(td); tb.append(tr);
    return;
  }
  for (const x of e.configured) {
    const tr = el("tr");
    tr.append(el("td", x.name));
    tr.append(el("td", x.type ? (x.type === "fallback" ? "组：故障转移" : "组：延迟优选") : "槽位"));
    tr.append(el("td", x.type ? (x.members || []).join(", ") : x.exit_node));
    tr.append(el("td", x.health_check ? `${x.health_check.url} / ${x.health_check.interval}` : "—", "muted"));
    const st = el("td"); st.append(stateBadge(e.runtime ? e.runtime[x.name] : "not_running")); tr.append(st);
    tb.append(tr);
  }
}

const COND_LABELS = [
  ["domain", "域名"], ["domain_suffix", "后缀"], ["domain_keyword", "关键词"], ["ip_cidr", "IP 段"], ["port", "端口"],
];

async function loadRules() {
  const r = await api("/api/v1/rules");
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

async function refresh() {
  try {
    await Promise.all([loadStatus(), loadEgress(), loadRules(), loadConfig()]);
    showError("");
    showLogin(false);
  } catch (err) {
    if (err instanceof AuthError) {
      showLogin(true);
      return;
    }
    showError("加载失败：" + err.message);
  }
}

$("login").addEventListener("submit", (ev) => {
  ev.preventDefault();
  token = $("token").value.trim();
  try { sessionStorage.setItem(TOKEN_KEY, token); } catch (_) { /* storage unavailable */ }
  refresh();
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
    const r = await api("/api/v1/rules/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    out.replaceChildren(
      el("div", "目标：" + r.target, "target"),
      el("div", r.implicit ? "未命中任何规则" : `命中规则 #${r.rule_index}`),
      el("div", "原因：" + r.reason, "muted"),
    );
  } catch (err) {
    if (err instanceof AuthError) { showLogin(true); return; }
    out.replaceChildren(el("span", "测试失败：" + err.message));
  }
});

window.addEventListener("hashchange", () => { if ($("login").hidden) selectTab(currentTab()); });
selectTab(currentTab());
refresh();
setInterval(() => { if ($("login").hidden && !document.hidden) loadStatus().catch(() => {}); }, 5000);
