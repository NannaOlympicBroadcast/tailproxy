# Bacarra Kernel Engine Package

`internal/kernel/bacarra` implements the cross-platform adapter discovery and host route hijacking engine for Tailproxy's Bacarra kernel mode.

## Overview

In Bacarra mode, Tailproxy does not spawn standalone `tsnet.Server` node instances. Instead, it interfaces directly with the host's existing official Tailscale client (`tailscaled` / Tailscale GUI):
1. **Adapter Discovery**: Automatically discovers the active official Tailscale network interface (`Tailscale` on Windows, `tailscale0` on Linux, `utun*` on macOS) and validates its IP assignment against RFC 6598 CGNAT (`100.64.0.0/10`) and Tailscale IPv6 ULA (`fd7a:115c:a1e0::/48`).
2. **Fail-Fast & Anti-Mock**: If no active official Tailscale interface is found, it immediately reports `ErrTailscaleNotDetected`. Never mocks, hallucinates, or silently degrades.
3. **Selective Route Hijacking**: Injects host routing entries for FakeIP subnets (`198.18.0.0/15`, `fc00::/18`) and rule-matched `ip_cidr` blocks, directing targeted traffic into the Tailscale adapter towards the configured exit node.
4. **Windows NextHop Safety**: Subnet routes on Windows use NextHop `100.100.100.100` (`tsaddr.TailscaleServiceIP`) to avoid Windows on-link subnet broadcast restrictions (WSA error 10049).
5. **State Persistence & Recovery**: Actively applied routes are persisted to `<stateDir>/bacarra_routes.json`. Crashed runs or stale routes are cleaned up via `TeardownStale`.

## Architecture & Platform Implementation

| Platform | Interface Discovery | Route Addition | Route Deletion | NextHop |
|---|---|---|---|---|
| **Windows** | `winipcfg.GetAdaptersAddresses` (`Tailscale` / `Wintun`) | `luid.AddRoute(prefix, nextHop, metric)` | `luid.DeleteRoute(prefix, nextHop)` | `100.100.100.100` (IPv4) / `tsaddr.TailscaleServiceIPv6` (IPv6) |
| **Linux** | `net.Interfaces()` (`tailscale*`, `IFF_UP`) | `rtnetlink.Route.Replace` (`RT_TABLE_MAIN`, `RT_SCOPE_LINK`) | `rtnetlink.Route.Delete` | On-link via `tailscale0` |
| **macOS** | `net.Interfaces()` (`utun*`, `IFF_UP`) | `/sbin/route -q -n add -inet <p> -interface <dev>` | `/sbin/route -q -n delete -inet <p> -interface <dev>` | Interface binding |

## Key Components

- `discovery.go`: Common interface discovery definitions, `IsTailscaleIP`, `ValidateAdapterIPs`.
- `discovery_windows.go`: Windows-specific adapter enumeration and `winipcfg.LUID` acquisition.
- `discovery_linux.go`: Linux `tailscale*` interface detection.
- `discovery_darwin.go`: macOS `utun*` interface detection.
- `route.go`: `RouteManager` lifecycle, diffing calculation, incremental route injection, and `TeardownStale`.
- `route_windows.go`: Windows routing driver via `winipcfg`.
- `route_linux.go`: Linux routing driver via `rtnetlink`.
- `route_darwin.go`: macOS routing driver via `/sbin/route`.
- `state.go`: Atomic serialization and parsing for `<stateDir>/bacarra_routes.json`.
