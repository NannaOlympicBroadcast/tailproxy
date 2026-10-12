---
name: rules
description: Change tailproxy's routing rules or exits from a plain-language request ("send YouTube through the Japan exit", "stop proxying example.com", "add my new VPS as an exit"), test the result and reload without restarting. Supports both Davin and Bacarra kernel modes. Use when the user wants to route, unroute, block or re-route domains, IP ranges, ports or apps through tailproxy, or add / change / remove an exit.
---

# tailproxy rules

tailproxy is already installed and running (if not, use the `setup` skill). Rules live in config.yaml under `rules:` and are evaluated **top to bottom, first match wins**; a final `{final: direct}` (or another target) catches the rest.

## Steps

1. **Read the current state**: `tpctl rules list` and `tpctl egress list` (add `--json` for structured output). Find the config path and active kernel mode (`davin` vs. `bacarra`) from `tpctl status` / `tpctl config`.
2. **Translate the request into rules** and show them before writing:
   - Sites: prefer `domain_suffix: [example.com]` (covers subdomains); `domain_keyword` only for brand names that span many domains; `domain` for one exact name.
   - Networks: `ip_cidr: [203.0.113.0/24]`; ports: `port: [443]` combines with other conditions of the same rule (AND), while domain / IP conditions are OR.
   - Targets: an egress name, `direct`, `reject`, or `tailnet`.
   - Order matters: put specific rules above broad ones; say where each new rule goes and why.
3. **Exits**:
   - In **Davin mode**: add with `tpctl egress add NAME --exit-node HOST` or `--relay HOST:PORT` (relay token: piped into `tpctl egress relay-token NAME`); change with `tpctl egress set`, remove with `tpctl egress rm`.
   - In **Bacarra mode**: traffic is routed through the host's existing official Tailscale connection according to rule-injected CIDR/FakeIP routes.
4. **Edit config.yaml** with user's OK (keep a backup copy), then **validate**: `tailproxy check -c config.yaml`. Fix and re-check until it passes.
5. **Apply**: `tpctl reload` (rules apply at once; in Bacarra mode, host routes are diffed and updated incrementally).
6. **Test**: `tpctl rules test <domain> 443` for every affected name, plus one name that should *not* match. In Bacarra mode, verify that `tpctl status` reflects active injected routes targeting the official Tailscale adapter. For real traffic, `tpctl conns` shows live connections with their rule and target.

Report the before / after behavior in one line per changed rule. If a test does not route as intended, re-check the rule order first.
