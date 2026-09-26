<p align="center"><img src="tailproxy-logo-512.png" alt="tailproxy logo" width="160"></p>

# tailproxy plugin

Agent-guided install, configuration and troubleshooting for [tailproxy](https://github.com/NannaOlympicBroadcast/tailproxy), a tool that sends each connection to a Tailscale exit node, a VPS relay, the tailnet or directly, based on rules for domains, IP ranges, ports and apps.

## Skills

- **setup**: pick a deployment (SOCKS5 on this computer, whole-computer TUN, Linux router, or a VPS relay), download and verify the release, write and validate `config.yaml`, log in to Tailscale, start tailproxy and check that traffic takes the intended exit.
- **rules**: change routing rules or exits from a plain-language request, such as "send YouTube through the Japan exit", then test and reload without a restart.
- **troubleshoot**: diagnose a site taking the wrong exit, exits stuck logging in, DNS / FakeIP problems, TUN or router capture not taking effect, or an unreachable panel, using status, connections and logs.

## What the plugin runs and contacts

The plugin has no hooks and no MCP servers. Its skills tell Claude which commands to run, and Claude asks before anything that needs `sudo` or changes the system. Those commands may:

- run `tailproxy` and `tpctl` on your machine and edit your tailproxy `config.yaml`;
- query the GitHub API and download releases from `github.com/NannaOlympicBroadcast/tailproxy/releases`;
- on Windows TUN setups, point you to `wintun.net` for the Wintun driver;
- send you to `login.tailscale.com` to create an auth key or log in;
- call `ifconfig.me`, directly and through the proxy, to confirm which exit IP traffic uses;
- open the local panel at `127.0.0.1:7708`.

No data is sent anywhere else by the plugin itself.

## License

MIT. Logo artwork used with the artist's permission.
