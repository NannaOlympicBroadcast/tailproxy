---
name: troubleshoot
description: Diagnose tailproxy problems — a site not going through the intended exit, exits stuck logging in or offline, DNS / FakeIP issues, TUN or router capture not taking effect, the panel or tpctl not reachable — by reading status, connections and logs and applying the documented fix. Use when tailproxy is not working as expected.
---

# tailproxy troubleshooting

Work from evidence: run the checks, quote what they print, change one thing at a time and re-check. Ask before anything that needs `sudo` or changes the system.

## 1. Collect

- `tailproxy status` — is it running, which config, where the log is.
- `tpctl status` — component states (panel, rule engine, egress manager, capture, DNS) with details.
- `tpctl egress list` — each exit's state, exit node online, last health check.
- `tpctl conns --all` — recent connections: host, how the name was learned (fakeip / sniffed / learned), rule, target, error.
- The log file from `tailproxy status` (last ~50 lines).

## 2. Match the symptom

| Symptom | Likely cause → fix |
|---|---|
| egress manager `needs_login`, exit `needs_login` | Node not logged in → open the login URL from `tpctl egress list` / the panel, or set a reusable auth key (panel 出口 page, or `tailnet.auth_key_env`). |
| exit `needs_machine_auth` | The tailnet requires device approval → approve the device in the Tailscale admin console (Machines). |
| exit `exit_node_pending` / `exit_node_offline` | Exit node not approved or offline → approve it as an exit node in the Tailscale admin console, check ACLs, `tpctl ts ping <node>`. |
| Relay exit `no_token` / `auth_failed` / `unreachable` | No or wrong token → on the VPS `tailproxy relay token`, then the user pipes it into `tpctl egress relay-token NAME`; unreachable → the relay is not running (`tailproxy relay` / its service) or the address is not the VPS's Tailscale IP:port. |
| Site goes direct / wrong exit | `tpctl rules test <domain> 443` — rule order (first match wins) or missing suffix. In `tpctl conns`, an IP with no name means the name was never learned: the app uses its own DoH (see `tailproxy doctor`), or `dns.unknown_domain` decides. |
| TUN mode, nothing captured | Not root / Administrator; Windows missing `wintun.dll`; system DNS not pointed at the stack (`tpctl status` DNS line; `capture.tun_system_dns`). |
| Router (TPROXY), LAN not captured | Clients must use the router as gateway and DNS; `sudo nft list table inet tailproxy`; after a crash `sudo tailproxy capture down` then restart. |
| No network after a crash | `sudo tailproxy capture down` (removes rules, restores system DNS). |
| Panel / tpctl unreachable | Service not running (`tailproxy status`); another process on port 7708 (`panel.listen`). |
| Config rejected at start | `tailproxy check -c config.yaml` prints the exact field and reason. |

## 3. Confirm

After a fix, repeat the check that showed the problem and the relevant `tpctl rules test`. If nothing in the table fits, show the user the collected output and the log excerpt, and point to the README section for their mode. Report bugs at https://github.com/NannaOlympicBroadcast/tailproxy/issues with the output (remove tokens, auth URLs and IPs first).
