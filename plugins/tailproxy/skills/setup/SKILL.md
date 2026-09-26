---
name: setup
description: Install and configure tailproxy step by step — pick a deployment (this computer via SOCKS5, whole-computer TUN, Linux router, or a VPS relay), download and verify the release, write and validate config.yaml (exits and routing rules), log in to Tailscale, start it and check that traffic takes the intended exit. Use when the user wants to set up, install, deploy or reconfigure tailproxy, or route certain apps / sites / domains through a specific Tailscale exit node or VPS.
---

# tailproxy setup

tailproxy sends each connection to a Tailscale exit node, a VPS relay, the tailnet or directly, by rules on domain / IP / port. You are guiding the user through installing and configuring it **on the machine this session runs on**. Speak the user's language; keep each step short and confirm before anything that changes the system.

Project: https://github.com/NannaOlympicBroadcast/tailproxy (README has the full reference; `tpctl schema config` prints the config JSON Schema).

## Ground rules

- **Run on the user's own machine.** If this session runs in a cloud sandbox rather than on the computer / router to configure, say so and stop: setting tailproxy up there would not help the user.
- **Never ask for secrets in chat.** Tailscale auth keys and relay tokens are entered by the user in the panel, in an environment variable, or piped on stdin (`tpctl egress relay-token NAME` reads stdin). Do not echo them, write them into config.yaml, or put them in command lines.
- **Ask before system changes**: installing binaries into system paths, `sudo`, TUN / TPROXY capture, systemd services, browser policies. Show the exact command first.
- **Verify, do not assume**: after each step run the check listed for it and report what it printed. If a step fails, switch to the `troubleshoot` skill.

## 1. Understand the goal

Ask (one short message) and note the answers:

1. What should use which exit? e.g. "OpenAI and Claude via the US server, everything else direct".
2. What exits exist? Tailscale **exit nodes** already approved in the tailnet (hostname / 100.x IP), and/or a **VPS** where tailproxy can run as a **relay** (no exit-node approval needed; one tailnet device on the client side).
3. Which deployment:

| Deployment | When | Needs |
|---|---|---|
| SOCKS5 on this computer | Only chosen apps / a browser profile use it | No root; `capture.socks_listen: 127.0.0.1:1080` |
| TUN on this computer | All apps, Linux / macOS / Windows | root / Administrator; Windows also `wintun.dll` next to `tailproxy.exe` |
| Linux router (TPROXY) | Whole LAN through a Linux / OpenWrt box | root, nftables |
| Relay on a VPS | The VPS is an exit for other tailproxy clients | Tailscale on the VPS; `tailproxy relay` |

## 2. Install

Detect OS and CPU (`uname -sm`, or `$env:PROCESSOR_ARCHITECTURE` on Windows). Releases are at https://github.com/NannaOlympicBroadcast/tailproxy/releases — pre-releases included, so list them with the API rather than `/releases/latest`:

```sh
curl -fsSL https://api.github.com/repos/NannaOlympicBroadcast/tailproxy/releases?per_page=1
```

Assets are `tailproxy_<version>_<os>_<arch>.tar.gz` (`.zip` for Windows) plus `SHA256SUMS`; `<os>` is linux / darwin / windows, `<arch>` amd64 / arm64 / armv7 / mips / mipsle / riscv64 (OpenWrt routers: `mipsle` or `mips` softfloat — check `uname -m` and the router's docs). Download the archive and `SHA256SUMS`, **verify the checksum** (`sha256sum -c --ignore-missing SHA256SUMS`, or `shasum -a 256` / `Get-FileHash`), unpack, and with the user's OK put `tailproxy` and `tpctl` on the PATH (`~/.local/bin` needs no root; `/usr/local/bin` does). Check: `tailproxy version` and `tpctl version`.

Windows TUN only: download Wintun from https://www.wintun.net and put `wintun.dll` (matching architecture) next to `tailproxy.exe`.

## 3. Write config.yaml

Start from the release's `config.example.yaml` (also in the repo). Keep it minimal:

```yaml
egress:
  - {name: us, exit_node: us-vps}           # a Tailscale exit node (hostname / 100.x / MagicDNS name)
  - {name: jp, relay: "100.64.0.9:1081"}    # or a VPS running `tailproxy relay`
rules:                                       # first match wins
  - {domain_suffix: [openai.com, chatgpt.com, anthropic.com, claude.ai], egress: us}
  - {domain_keyword: [netflix], egress: jp}
  - {ip_cidr: [203.0.113.0/24], egress: us}
  - {final: direct}
capture:
  mode: auto                                 # SOCKS5 only; tun / tproxy for system-wide capture
  socks_listen: 127.0.0.1:1080
```

- Rule fields: `domain`, `domain_suffix`, `domain_keyword`, `ip_cidr`, `port`, `outer_sni`, `final`; targets are an egress name, `direct`, `reject` or `tailnet`. Explain each rule back to the user in one line.
- TUN: `capture: {mode: tun}` (system DNS is pointed at tailproxy while it runs and restored on exit; `scope: all` also routes everything else through the rules). Router: `capture: {mode: tproxy}`; add `udp: proxy` to route QUIC / UDP.
- Auth key without a browser: `tailnet: {auth_key_env: TAILPROXY_AUTHKEY}` and the user sets that variable themselves (reusable key from https://login.tailscale.com/admin/settings/keys), or they paste it into the panel's 出口 page later.

**Validate** before starting: `tailproxy check -c config.yaml` (prints a summary or the exact error). Test the rules without running anything else: after start, `tpctl rules test chat.openai.com 443`.

## 4. Start and log in

- Foreground trial: `tailproxy run -c config.yaml` (Ctrl-C stops). Background: `tailproxy start -c config.yaml` — it prints the panel URL (http://127.0.0.1:7708) and a one-click login link with the access token. TUN / TPROXY need `sudo` (Windows: an Administrator shell).
- Tailscale login: each node needs logging in once. With an auth key set, it is automatic; otherwise `tpctl egress list` and the panel's 出口 page show login URLs — the user opens them in a browser. Exit nodes must be approved as exit nodes in the Tailscale admin console and allowed by ACLs.
- Relay on the VPS (run there): `tailproxy relay` (or `sudo tailproxy service install --relay`), then `tailproxy relay token` prints the token; on the client the user pipes it: `tpctl egress relay-token jp` (reads stdin).
- Start on boot (Linux, systemd): `sudo tailproxy service install -c /absolute/path/config.yaml`.

## 5. Verify

Run and report:

1. `tpctl status` — every component `running` / `ready`; egress manager not `needs_login`.
2. `tpctl egress list` — each exit `ready`, exit node online.
3. `tpctl rules test <a domain from each rule> 443` — the intended egress.
4. Real traffic: SOCKS5 `curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me` for a routed site's exit IP vs. `curl https://ifconfig.me` direct; TUN / router: open the site and check `tpctl conns` shows it with the right target.
5. Optional, only if the user asks: browsers' built-in DoH bypasses tailproxy's DNS; `sudo tailproxy doctor --apply-browser-policy` turns it off (prints every change and asks; `--revert-browser-policy` undoes it).

Finish with a short summary: what runs where, how to stop (`tailproxy stop`), where the panel is, and how to change rules later (the `rules` skill).
