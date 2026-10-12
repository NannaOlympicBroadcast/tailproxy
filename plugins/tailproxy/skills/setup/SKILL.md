---
name: setup
description: Install and configure tailproxy step by step — pick a kernel (Davin for standalone embedded tsnet or Bacarra for host route hijacking with existing Tailscale), pick a deployment (this computer via SOCKS5, whole-computer TUN, Linux router, or a VPS relay), download and verify the release, write and validate config.yaml (exits and routing rules), log in to Tailscale, start it and check that traffic takes the intended exit. Use when the user wants to set up, install, deploy or reconfigure tailproxy, or route certain apps / sites / domains through a specific Tailscale exit node or VPS.
---

# tailproxy setup

tailproxy sends each connection to a Tailscale exit node, a VPS relay, the tailnet or directly, by rules on domain / IP / port. You are guiding the user through installing and configuring it **on the machine this session runs on**. Speak the user's language; keep each step short and confirm before anything that changes the system.

Project: https://github.com/NannaOlympicBroadcast/tailproxy (README has the full reference; `tpctl schema config` prints the config JSON Schema).

## Ground rules

- **Run on the user's own machine.** If this session runs in a cloud sandbox rather than on the computer / router to configure, say so and stop: setting tailproxy up there would not help the user.
- **Never ask for secrets in chat.** Tailscale auth keys and relay tokens are entered by the user in the panel, in an environment variable, or piped on stdin (`tpctl egress relay-token NAME` reads stdin). Do not echo them, write them into config.yaml, or put them in command lines.
- **Ask before system changes**: installing binaries into system paths, `sudo`, TUN / TPROXY capture, systemd services, browser policies. Show the exact command first.
- **Verify, do not assume**: after each step run the check listed for it and report what it printed. If a step fails, switch to the `troubleshoot` skill.

## 1. Understand the goal & Kernel Selection

Ask (one short message) and note the answers:

1. **Kernel Mode**:
   - **`kernel: davin` (Default)**: Use when this device does **not** have the official Tailscale client installed. tailproxy spins up embedded `tsnet.Server` nodes to manage exits, relays, and capture.
   - **`kernel: bacarra`**: Use when this device **already has the official Tailscale client installed and connected**. tailproxy does not spawn extra tsnet nodes; it discovers the official Tailscale adapter (`tailscale0`, Windows Tailscale adapter, macOS `utun`) and selectively hijacks the host routing table to send routed traffic out of the exit node. Requires root / Administrator.
2. **What should use which exit?** e.g. "OpenAI and Claude via the US server, everything else direct".
3. **What exits exist?** Tailscale **exit nodes** already approved in the tailnet (hostname / 100.x IP), and/or a **VPS** where tailproxy can run as a **relay** (no exit-node approval needed; one tailnet device on the client side).
4. **Which deployment / capture mode**:

| Deployment | Kernel | When | Needs |
|---|---|---|---|
| Bacarra Host Routing | `bacarra` | Official Tailscale installed; route table hijack | root / Administrator; official Tailscale running |
| SOCKS5 on this computer | `davin` | Only chosen apps / a browser profile use it | No root; `capture.socks_listen: 127.0.0.1:1080` |
| TUN on this computer | `davin` | All apps, Linux / macOS / Windows | root / Administrator; Windows also `wintun.dll` next to `tailproxy.exe` |
| Linux router (TPROXY) | `davin` | Whole LAN through a Linux / OpenWrt box | root, nftables |
| Relay on a VPS | `davin` | The VPS is an exit for other tailproxy clients | Tailscale on the VPS; `tailproxy relay` |

## 2. Install

Detect OS and CPU (`uname -sm`, or `$env:PROCESSOR_ARCHITECTURE` on Windows). Releases are at https://github.com/NannaOlympicBroadcast/tailproxy/releases — pre-releases included, so list them with the API rather than `/releases/latest`:

```sh
curl -fsSL https://api.github.com/repos/NannaOlympicBroadcast/tailproxy/releases?per_page=1
```

Assets are `tailproxy_<version>_<os>_<arch>.tar.gz` (`.zip` for Windows) plus `SHA256SUMS`; `<os>` is linux / darwin / windows, `<arch>` amd64 / arm64 / armv7 / mips / mipsle / riscv64. Download the archive and `SHA256SUMS`, **verify the checksum** (`sha256sum -c --ignore-missing SHA256SUMS`, or `shasum -a 256` / `Get-FileHash`), unpack, and put `tailproxy` and `tpctl` on the PATH. Check: `tailproxy version` and `tpctl version`.

Windows Davin TUN only: download Wintun from https://www.wintun.net and put `wintun.dll` next to `tailproxy.exe`. Bacarra mode uses the existing official Tailscale adapter and does not need extra DLLs.

## 3. Write config.yaml

Start from the release's `config.example.yaml` (also in the repo). Keep it minimal:

```yaml
kernel: davin                                   # or bacarra (if official Tailscale is installed)

egress:
  - {name: us, exit_node: us-vps}           # a Tailscale exit node (hostname / 100.x / MagicDNS name)
  - {name: jp, relay: "100.64.0.9:1081"}    # or a VPS running `tailproxy relay`

rules:                                       # first match wins
  - {domain_suffix: [openai.com, chatgpt.com, anthropic.com, claude.ai], egress: us}
  - {domain_keyword: [netflix], egress: jp}
  - {ip_cidr: [203.0.113.0/24], egress: us}
  - {final: direct}

capture:
  mode: auto                                 # SOCKS5 only; tun / tproxy for system-wide capture (Davin)
  socks_listen: 127.0.0.1:1080
```

- In **Bacarra mode** (`kernel: bacarra`): tailproxy verifies official Tailscale interface membership in CGNAT `100.64.0.0/10` and ULA `fd7a:115c:a1e0::/48`, and injects FakeIP and matched `ip_cidr` routes into the host routing table.
- Rule fields: `domain`, `domain_suffix`, `domain_keyword`, `ip_cidr`, `port`, `outer_sni`, `final`; targets are an egress name, `direct`, `reject` or `tailnet`.

**Validate** before starting: `tailproxy check -c config.yaml` (prints kernel mode, exit summary, or exact error).

## 4. Start and log in

- Foreground trial: `tailproxy run -c config.yaml` (Ctrl-C stops). Background: `tailproxy start -c config.yaml` — prints panel URL (http://127.0.0.1:7708) and access token.
- Bacarra mode requires root / Administrator shell for host route table modification.
- Davin mode login: each slot logs in once via auth key or panel URL. Bacarra mode relies on the host's already logged-in official Tailscale connection.
- Teardown: `tailproxy stop` cleans up all injected routes; in case of crash recovery, run `tailproxy capture down` to restore the system route table.

## 5. Verify

Run and report:

1. `tpctl status` — reports active kernel mode (`davin` or `bacarra`), component states, and active routes.
2. `tpctl egress list` — each exit's state and health check.
3. `tpctl rules test <a domain from each rule> 443` — verify intended egress matching.
4. Real traffic check: verify routed traffic exits through the exit node IP while direct traffic uses host default gateway.
