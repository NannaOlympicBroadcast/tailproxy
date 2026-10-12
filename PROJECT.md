# Project: Tailproxy Dual-Kernel Architecture Refactoring

## Architecture
Tailproxy is refactored from a purely embedded tsnet proxy into a dual-kernel transparent proxy engine supporting two distinct operating modes:

1. **Davin Kernel Mode** (`kernel: davin`, default):
   - Retains the existing embedded multi-slot `tsnet.Server` architecture (`internal/egress/manager.go`).
   - Spins up private tsnet nodes for egress slots, intercepts traffic via TUN / Linux TPROXY, resolves routed domains to FakeIPs, and proxies L4 connections through pinned exit nodes.
   - Requires no host Tailscale client.

2. **Bacarra Kernel Mode** (`kernel: bacarra`):
   - Operates on systems with the official Tailscale client installed (`tailscaled` / Tailscale GUI).
   - Does NOT spawn standalone `tsnet.Server` instances.
   - Detects the host's active official Tailscale network adapter (Windows `Tailscale` / `winipcfg.LUID`, Linux `tailscale0`, macOS `utun*`) verifying IPv4 membership in RFC 6598 CGNAT block `100.64.0.0/10` and IPv6 in ULA block `fd7a:115c:a1e0::/48`.
   - Injects host routing table entries for FakeIP pools (`198.18.0.0/15`, `fc00::/18`) and rule `ip_cidr` blocks targeting the Tailscale adapter.
   - Traffic matching routed domains (assigned FakeIP) or CIDRs is routed by the OS kernel directly into the official Tailscale network stack towards the configured exit node.
   - Non-proxied / direct traffic falls through to host physical default routes untouched.
   - Persists active route state to `<stateDir>/bacarra_routes.json` with safe teardown on exit and crash recovery in `tailproxy capture down`.

```
                        ┌─────────────────────────────────────┐
                        │        Configuration & CLI          │
                        │      config.yaml / tpctl / API      │
                        └──────────────────┬──────────────────┘
                                           │
                                  kernel.New(cfg)
                                           │
                    ┌──────────────────────┴──────────────────────┐
                    ▼                                             ▼
       [Mode: Davin (Embedded tsnet)]               [Mode: Bacarra (Host Hijacking)]
                    │                                             │
      ┌─────────────┴─────────────┐                 ┌─────────────┴─────────────┐
      │ egress.Manager            │                 │ bacarra.AdapterDetector   │
      │  - tsnet.Server slots     │                 │  - Windows: winipcfg.LUID │
      │  - Exit node pinning      │                 │  - Linux: tailscale0      │
      │  - Local DoH resolution   │                 │  - macOS: utun*           │
      │ proxy.Router & Tracker    │                 ├───────────────────────────┤
      │  - SOCKS5 / TPROXY / TUN  │                 │ bacarra.RouteManager      │
      │ dnsserver & fakeip.Pool   │                 │  - Inject FakeIP & CIDRs  │
      └───────────────────────────┘                 │  - bacarra_routes.json    │
                                                    │  - Safe cleanup & teardown│
                                                    │ dnsserver & fakeip.Pool   │
                                                    └───────────────────────────┘
```

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Configuration schema `kernel` field | Add `kernel: davin \| bacarra` (default `davin`) in `config.Config` | M1 | ORIGINAL_REQUEST §R1 |
| 2 | Configuration validation & defaults | Validate `kernel` values in `internal/config` | M1 | ORIGINAL_REQUEST §R1 |
| 3 | Schema reflection & OpenAPI sync | Add schema docs in `internal/schema/schema.go` to pass `TestEveryConfigFieldDocumented` | M1 | survey_1 handoff |
| 4 | Kernel interface abstraction | Define `kernel.Engine`, `ModeDavin`, `ModeBacarra` in `internal/kernel/engine.go` | M1 | survey_2 handoff |
| 5 | Cross-platform adapter discovery | Discover official Tailscale adapter on Windows, Linux, macOS | M2 | ORIGINAL_REQUEST §R2 |
| 6 | Fail-fast adapter validation | Verify IP in `100.64.0.0/10` / `fd7a:115c:a1e0::/48`, fail immediately without mock | M2 | ORIGINAL_REQUEST guidelines |
| 7 | Host route injection engine | Inject FakeIP and rule `ip_cidr` blocks into Tailscale interface | M2 | ORIGINAL_REQUEST §R2 |
| 8 | Windows NextHop assignment | Use `100.100.100.100` as NextHop on Windows to avoid WSA 10049 broadcast error | M2 | survey_3 handoff |
| 9 | Linux rtnetlink & macOS route | Platform routing drivers for Linux (`rtnetlink`) and macOS (`/sbin/route`) | M2 | survey_3 handoff |
| 10 | Route state persistence | Track active routes in `<stateDir>/bacarra_routes.json` | M2 | survey_3 handoff |
| 11 | Idempotent route lifecycle | Route addition/deletion handles already-existing or already-removed routes | M2 | ORIGINAL_REQUEST §R3 |
| 12 | Safe shutdown teardown | Purge routes upon SIGINT/SIGTERM and daemon exit | M2 | ORIGINAL_REQUEST §R3 |
| 13 | Crash recovery route purge | Hook `tailproxy capture down` and startup pre-clean into `bacarra_routes.json` | M2, M3 | ORIGINAL_REQUEST §R3 |
| 14 | Davin kernel engine packaging | Package `egress.Manager` and `proxy.Router` under `kernel.Engine` | M3 | survey_2 handoff |
| 15 | Daemon runtime dispatch | Branch daemon execution in `cmd/tailproxy` based on `cfg.Kernel` | M3 | ORIGINAL_REQUEST §R1 |
| 16 | Web management panel reflection | Expose active kernel and operational components in `/api/v1/status` and UI | M3 | ORIGINAL_REQUEST §R1 |
| 17 | CLI tool status & check | Update `tpctl status`, `tailproxy status`, `tailproxy check` to display kernel | M3 | ORIGINAL_REQUEST §R1 |
| 18 | Documentation update: README | Architecture, Davin vs. Bacarra guide, configuration, permissions | M4 | ORIGINAL_REQUEST §R4 |
| 19 | Documentation update: DESIGN | Detailed technical design and diagrams in `docs/DESIGN.md` | M4 | ORIGINAL_REQUEST §R4 |
| 20 | Plugin skill: setup | Update `plugins/tailproxy/skills/setup/SKILL.md` with kernel selection | M4 | ORIGINAL_REQUEST §R4 |
| 21 | Plugin skill: troubleshoot | Update `plugins/tailproxy/skills/troubleshoot/SKILL.md` with Bacarra diagnostics | M4 | ORIGINAL_REQUEST §R4 |
| 22 | Plugin skill: rules | Update `plugins/tailproxy/skills/rules/SKILL.md` with route table behavior | M4 | ORIGINAL_REQUEST §R4 |
| 23 | Plugin skill: README | Update `plugins/tailproxy/README.md` with dual-kernel overview | M4 | ORIGINAL_REQUEST §R4 |
| 24 | Programmatic tests passing | Unit and integration tests pass across packages (`go test ./...`) | M5 | ORIGINAL_REQUEST acceptance |
| 25 | Adversarial verification & audit | Stress testing, edge case verification, and forensic integrity audit CLEAN | M5 | Project Pattern |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Kernel Abstraction & Configuration Schema | `internal/config`, `internal/schema`, `config.example.yaml`, `internal/kernel/engine.go` | none | DONE |
| M2 | Bacarra Adapter Discovery & Route Engine | `internal/kernel/bacarra/` (discovery, route manager, persistence, idempotency) | M1 | DONE |
| M3 | Daemon, CLI & Web Panel Integration | `cmd/tailproxy/`, `cmd/tpctl/`, `internal/panel/`, `internal/kernel/davin/` | M1, M2 | PLANNED |
| M4 | Documentation & Plugin Skills Updates | `README.md`, `docs/DESIGN.md`, `plugins/tailproxy/skills/*`, `plugins/tailproxy/README.md` | M1, M2, M3 | PLANNED |
| M5 | Final Integration & Test Suite Verification | Full test pass (`go test ./...`), E2E Tier 1-4 pass, Tier 5 adversarial tests, Forensic Audit | M1, M2, M3, M4 | PLANNED |

## Interface Contracts

### `internal/config` ↔ `internal/kernel`
```go
type Config struct {
    Kernel string `yaml:"kernel,omitempty" json:"kernel,omitempty"` // "davin" | "bacarra", defaults to "davin"
    ...
}
```

### `internal/kernel` Interface
```go
package kernel

type Mode string
const (
    ModeDavin   Mode = "davin"
    ModeBacarra Mode = "bacarra"
)

type Engine interface {
    Type() Mode
    Start(ctx context.Context) error
    Close() error
    Reload(cfg *config.Config, rules *rule.Engine) error
    Status() any
    Components() []panel.Component
    Teardown() error
}

func New(cfg *config.Config, stateDir string, logf func(string, ...any)) (Engine, error)
```

### `internal/kernel/bacarra` ↔ Host Operating System
- **Adapter Discovery**:
  - `DiscoverAdapter() (*AdapterInfo, error)` returns `Name`, `IPs`, `LUID` (Windows), `Index`.
  - Errors if no official Tailscale adapter with `100.64.0.0/10` or `fd7a:115c:a1e0::/48` is found.
- **Route Manager**:
  - `ApplyRoutes(prefixes []netip.Prefix) error`
  - `RemoveRoutes(prefixes []netip.Prefix) error`
  - `Teardown() error` (reads `bacarra_routes.json` and purges routes idempotently)

## Code Layout
- `internal/config/config.go`: Configuration struct, parser, validator
- `internal/schema/schema.go`: Config reflection metadata
- `internal/kernel/engine.go`: Unified kernel abstraction
- `internal/kernel/davin/`: Davin engine (wraps tsnet slot manager & proxy router)
- `internal/kernel/bacarra/`: Bacarra engine (adapter detection & route manager)
  - `discovery.go`, `discovery_windows.go`, `discovery_linux.go`, `discovery_darwin.go`
  - `route.go`, `route_windows.go`, `route_linux.go`, `route_darwin.go`
  - `state.go` (JSON route persistence)
- `cmd/tailproxy/`: Daemon entry point, runtime view, capture cleanup
- `cmd/tpctl/`: Management CLI
- `internal/panel/`: Web management dashboard
- `plugins/tailproxy/skills/`: Agent skills
- `docs/DESIGN.md`: Architecture design document
- `README.md`: User documentation
