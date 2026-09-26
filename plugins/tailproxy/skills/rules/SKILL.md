---
name: rules
description: Change tailproxy's routing rules or exits from a plain-language request ("send YouTube through the Japan exit", "stop proxying example.com", "add my new VPS as an exit"), test the result and reload without restarting. Use when the user wants to route, unroute, block or re-route domains, IP ranges, ports or apps through tailproxy, or add / change / remove an exit.
---

# tailproxy rules

tailproxy is already installed and running (if not, use the `setup` skill). Rules live in config.yaml under `rules:` and are evaluated **top to bottom, first match wins**; a final `{final: direct}` (or another target) catches the rest.

## Steps

1. **Read the current state**: `tpctl rules list` and `tpctl egress list` (add `--json` for structured output). Find the config path from `tpctl status` / `tpctl config`.
2. **Translate the request into rules** and show them before writing:
   - Sites: prefer `domain_suffix: [example.com]` (covers subdomains); `domain_keyword` only for brand names that span many domains; `domain` for one exact name.
   - Networks: `ip_cidr: [203.0.113.0/24]`; ports: `port: [443]` combines with the other conditions of the same rule (AND), while domain / IP conditions are OR.
   - Targets: an egress name, `direct`, `reject`, or `tailnet`.
   - Order matters: put specific rules above broad ones; say where each new rule goes and why.
3. **Exits**: add with `tpctl egress add NAME --exit-node HOST` or `--relay HOST:PORT` (relay token: the user pipes it into `tpctl egress relay-token NAME`, never on the command line or in chat); change with `tpctl egress set`, remove with `tpctl egress rm` (refused while rules still use it).
4. **Edit config.yaml** with the user's OK (keep a backup copy next to it), then **validate**: `tailproxy check -c config.yaml`. Fix and re-check until it passes.
5. **Apply**: `tpctl reload` (rules apply at once; exits start / stop as needed). The panel's 规则 page is an alternative editor for users who prefer it.
6. **Test**: `tpctl rules test <domain> 443` for every affected name, plus one name that should *not* match. For real traffic, `tpctl conns` shows live connections with their rule and target.

Report the before / after behavior in one line per changed rule. If a test does not route as intended, re-check the rule order first.
