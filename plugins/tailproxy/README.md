<p align="center"><img src="tailproxy-logo-512.png" alt="tailproxy logo" width="160"></p>

# tailproxy plugin

Agent-guided install, configuration and troubleshooting for [tailproxy](https://github.com/NannaOlympicBroadcast/tailproxy), a dual-kernel tool that sends each connection to a Tailscale exit node, a VPS relay, the tailnet or directly, based on rules for domains, IP ranges, ports and apps.

## Dual-Kernel Architecture

tailproxy supports two distinct operating modes:
- **Davin Kernel (`kernel: davin`)**: The default embedded tsnet multi-slot mode. Runs private `tsnet.Server` nodes without requiring the official Tailscale client installed on the host. Intercepts traffic via SOCKS5, TUN, or Linux TPROXY.
- **Bacarra Kernel (`kernel: bacarra`)**: Designed specifically for devices with the official Tailscale client already installed and connected. Operates without spawning separate tsnet nodes, instead selectively hijacking host routing table entries for FakeIP and rule-matched IP/CIDR blocks directly into the official Tailscale adapter.

## Skills

- **setup**: pick a kernel mode (Davin vs. Bacarra), choose a deployment (SOCKS5, whole-computer TUN, Linux router, VPS relay, or host route hijacking), download and verify the release, write and validate `config.yaml`, start tailproxy and check traffic flow.
- **rules**: change routing rules or exits from a plain-language request, such as "send YouTube through the Japan exit", then test and reload without a restart across both Davin and Bacarra modes.
- **troubleshoot**: diagnose kernel mode issues, official Tailscale adapter discovery failures, route table conflicts, sites taking the wrong exit, DNS / FakeIP problems, or an unreachable panel, using status, connections and logs.

## What the plugin runs and contacts

The plugin has no hooks and no MCP servers. Its skills tell Claude which commands to run, and Claude asks before anything that needs `sudo` or changes the system. Those commands may:

- run `tailproxy` and `tpctl` on your machine and edit your tailproxy `config.yaml`;
- query the GitHub API and download releases from `github.com/NannaOlympicBroadcast/tailproxy/releases`;
- on Windows Davin TUN setups, point you to `wintun.net` for the Wintun driver;
- send you to `login.tailscale.com` to create an auth key or log in;
- call `ifconfig.me`, directly and through the proxy, to confirm which exit IP traffic uses;
- open the local panel at `127.0.0.1:7708`.

No data is sent anywhere else by the plugin itself.

## License

MIT. Logo artwork used with the artist's permission.
