---
name: troubleshoot
description: Diagnose tailproxy problems — kernel mode issues (Davin vs Bacarra), official Tailscale adapter discovery failures, route table conflicts, sites not going through the intended exit, exits stuck logging in or offline, DNS / FakeIP issues, TUN or router capture not taking effect, the panel or tpctl not reachable — by reading status, connections and logs and applying the documented fix. Use when tailproxy is not working as expected.
---

# tailproxy troubleshooting

Work from evidence: run the checks, quote what they print, change one thing at a time and re-check. Ask before anything that needs `sudo` or changes the system.

## 1. Collect

- `tailproxy status` — is it running, active kernel mode (`davin` / `bacarra`), which config, where the log is.
- `tpctl status` — component states (kernel engine, panel, rule engine, egress manager, capture, DNS, route manager) with details.
- `tpctl egress list` — each exit's state, exit node online, last health check.
- `tpctl conns --all` — recent connections: host, how the name was learned (fakeip / sniffed / learned), rule, target, error.
- The log file from `tailproxy status` (last ~50 lines).

## 2. Match the symptom

| Symptom | Likely cause → fix |
|---|---|
| Bacarra mode: `ErrTailscaleNotDetected` / `not detected` | Official Tailscale is not running, not logged in, or adapter has no IP in `100.64.0.0/10` / `fd7a:115c:a1e0::/48`. Start official Tailscale (`tailscale up`), verify `tailscale status` / `ip addr` / `ipconfig`, then restart tailproxy. |
| Bacarra mode: route injection permission denied | Host route manipulation requires root (Linux/macOS) or Administrator (Windows). Run `tailproxy` with elevated privileges. |
| Bacarra mode: stale routes or no network after crash | Injected host routes were not cleared before sudden kill. Run `sudo tailproxy capture down` (or admin shell on Windows) to parse `bacarra_routes.json` and purge all injected routes. |
| egress manager `needs_login`, exit `needs_login` (Davin mode) | Node not logged in → open login URL from `tpctl egress list` / panel, or set reusable auth key (panel 出口 page, or `tailnet.auth_key_env`). |
| exit `needs_machine_auth` | Tailnet requires device approval → approve device in Tailscale admin console (Machines). |
| exit `exit_node_pending` / `exit_node_offline` | Exit node not approved or offline → approve it in Tailscale admin console, check ACLs, `tpctl ts ping <node>`. |
| Relay exit `no_token` / `auth_failed` / `unreachable` | No or wrong token → on VPS `tailproxy relay token`, pipe into `tpctl egress relay-token NAME`; unreachable → relay not running or wrong IP:port. |
| Site goes direct / wrong exit | `tpctl rules test <domain> 443` — rule order (first match wins) or missing suffix. In `tpctl conns`, IP with no name means name never learned (see `tailproxy doctor`). |
| TUN mode, nothing captured (Davin mode) | Not root / Administrator; Windows missing `wintun.dll`; system DNS not pointed at stack (`tpctl status` DNS line; `capture.tun_system_dns`). |
| Router (TPROXY), LAN not captured | Clients must use router as gateway and DNS; `sudo nft list table inet tailproxy`; after crash `sudo tailproxy capture down` then restart. |
| Panel / tpctl unreachable | Service not running (`tailproxy status`); another process on port 7708 (`panel.listen`). |
| Config rejected at start | `tailproxy check -c config.yaml` prints exact field and reason (e.g. unknown `kernel` mode). |

## 3. Confirm

After a fix, repeat the check that showed the problem and the relevant `tpctl rules test`. If nothing in the table fits, show the user the collected output and the log excerpt, and point to the README section for their mode. Report bugs at https://github.com/NannaOlympicBroadcast/tailproxy/issues with the output (remove tokens, auth URLs and IPs first).
