# Tailproxy Dual-Kernel E2E Testing Infrastructure

## 1. Executive Summary & Testing Philosophy

This document defines the End-to-End (E2E) testing infrastructure for the **Tailproxy Dual-Kernel Architecture Refactoring** project. Tailproxy provides two distinct operational kernels:
1. **Davin Mode (`kernel: davin`)**: Embedded multi-slot `tsnet.Server` transparent proxy that does not require the official host Tailscale client.
2. **Bacarra Mode (`kernel: bacarra`)**: Coexists with the official host Tailscale client by discovering the active Tailscale adapter and selectively injecting host routing table entries for FakeIP pools and matched rule CIDRs towards the active exit node.

### 1.1 Opaque-Box & Requirement-Driven Methodology
The E2E test suite adheres to strict **opaque-box principles**:
- The tests observe and interact with the system via external interfaces: configuration files (`config.yaml`), CLI commands (`tailproxy`, `tpctl`), OS network interface state, host routing table entries, and persisted route state files (`bacarra_routes.json`).
- Tests do not rely on private internal struct states or unexported functions.
- Every assertion is grounded in the authoritative requirements defined in `ORIGINAL_REQUEST.md` and `PROJECT.md`.

### 1.2 Anti-Mock & Ground Truth Principles
In accordance with user engineering guidelines:
- **No Mocking of Network Adapters**: Production route hijacking and adapter detection must strictly fail-fast when the official Tailscale client is absent or down. The test suite verifies that the system fails with clear diagnostic errors (`ErrTailscaleNotDetected`) rather than silently fabricating mock adapters.
- **Fail-Fast Verification**: Unit and integration tests verify that permissions errors (non-root / non-Administrator), invalid IP subnets, or corrupt state files immediately halt execution with descriptive error codes.
- **Authoritative Ground Truth Derivation**: All expected outputs (CIDR formats, CGNAT ranges, exit node routes) are derived from documented standards (RFC 6598 `100.64.0.0/10`, RFC 4193 / Tailscale ULA `fd7a:115c:a1e0::/48`, and Tailscale LocalAPI protocols).

---

## 2. 4-Tier Test Suite Specification

The test suite is organized into four hierarchical tiers:

```
┌─────────────────────────────────────────────────────────────────┐
│ Tier 4: Real-World Scenarios & Full Lifecycle Simulation       │
│  - Startup -> Adapter Verification -> Route Injection -> Exit   │
│  - Crash Recovery via state file purge & capture down           │
├─────────────────────────────────────────────────────────────────┤
│ Tier 3: Cross-Feature Interactions & Dynamic Behavior          │
│  - Kernel Switching (Davin <-> Bacarra)                         │
│  - Rule Engine (Domain FakeIP + CIDR) Route Set Generation     │
│  - Dynamic Config Reload & Route Diffing                        │
├─────────────────────────────────────────────────────────────────┤
│ Tier 2: Boundary & Corner Cases                                │
│  - Empty / Missing Values & Strict Schema Rejection             │
│  - Case Sensitivity & Invalid Types                             │
│  - Corrupt Route State File Recovery                            │
│  - Unprivileged Execution Safeguards                            │
├─────────────────────────────────────────────────────────────────┤
│ Tier 1: Feature Coverage (>=5 test cases per feature)          │
│  - Feature 1: Configuration Schema & Validation                 │
│  - Feature 2: Default Kernel & Backwards Compatibility          │
│  - Feature 3: CLI Commands (`tailproxy check`, `tpctl schema`)  │
│  - Feature 4: Adapter Discovery & Fail-Fast Conditions         │
└─────────────────────────────────────────────────────────────────┘
```

### 2.1 Tier 1: Feature Coverage (>=5 Test Cases Per Feature)

Tier 1 ensures baseline functional correctness across all new dual-kernel features.

#### Feature 1: Configuration Schema & Validation (`internal/config`)
1. **T1.F1.1: Explicit Davin Kernel Validation**: Validates config containing `kernel: davin` loads and parses successfully.
2. **T1.F1.2: Explicit Bacarra Kernel Validation**: Validates config containing `kernel: bacarra` loads and parses successfully.
3. **T1.F1.3: Invalid Kernel Rejection**: Verifies that invalid values such as `kernel: wireguard`, `kernel: proxy`, or `kernel: custom` fail validation with `"invalid kernel mode"`.
4. **T1.F1.4: JSON/YAML Serialization Parity**: Verifies that `kernel` field marshals and unmarshals identically in both JSON and YAML formats.
5. **T1.F1.5: Schema Documentation Reflection**: Verifies reflection metadata in `internal/schema` documents `kernel` with enum `["davin", "bacarra"]` and default `"davin"`.

#### Feature 2: Default Kernel & Backwards Compatibility
1. **T2.F2.1: Legacy Config Without Kernel Field**: Verifies config files created before dual-kernel refactoring (no `kernel` field) default to `davin`.
2. **T2.F2.2: Nil/Empty String Defaulting**: Verifies explicit `kernel: ""` in configuration is normalized to `davin` during default application.
3. **T2.F2.3: Example Config Alignment**: Verifies `config.example.yaml` contains `kernel: davin` with valid commentary and passes `config.Parse`.
4. **T2.F2.4: Egress Slot Compatibility**: Verifies that in default `davin` mode, existing egress slot and group definitions remain fully valid.
5. **T2.F2.5: Zero-Value Struct Defaulting**: Verifies `(&config.Config{}).Validate()` after `applyDefaults()` enforces `c.Kernel == "davin"`.

#### Feature 3: CLI Commands (`cmd/tailproxy` & `cmd/tpctl`)
1. **T3.F3.1: `tailproxy check` on Davin Config**: Validates that running `tailproxy check -c <file>` on a Davin config succeeds and outputs valid configuration confirmation.
2. **T3.F3.2: `tailproxy check` on Bacarra Config**: Validates that running `tailproxy check -c <file>` on a Bacarra config succeeds and identifies kernel mode.
3. **T3.F3.3: `tailproxy check` on Invalid Kernel**: Validates that `tailproxy check` exits with non-zero status and reports validation error when given invalid kernel.
4. **T3.F3.4: `tpctl schema config` Reflection**: Validates `tpctl schema config` JSON Schema output contains `kernel` property definition with enum `["davin", "bacarra"]`.
5. **T3.F3.5: `tpctl schema api` OpenAPI Reflection**: Validates `tpctl schema api` OpenAPI 3.1 specification contains dual-kernel configuration schema and endpoints.

#### Feature 4: Official Tailscale Adapter Discovery & Fail-Fast Conditions
1. **T4.F4.1: Missing Tailscale Adapter Fail-Fast**: When no official Tailscale adapter exists on the host, discovery returns a clear descriptive error (`ErrTailscaleNotDetected`) without creating mocks.
2. **T4.F4.2: RFC 6598 CGNAT IP Verification**: Interfaces lacking an IPv4 address within `100.64.0.0/10` or IPv6 within `fd7a:115c:a1e0::/48` are strictly rejected.
3. **T4.F4.3: Interface Operational Status (FlagUp)**: Inactive or down interfaces (`FlagUp` false) are rejected even if named `tailscale0` or `Tailscale`.
4. **T4.F4.4: Cross-Platform Adapter Heuristics**: Verifies platform-specific naming heuristics (Windows `Tailscale` / `winipcfg.LUID`, Linux `tailscale0`, macOS `utun*`).
5. **T4.F4.5: LocalAPI Grounding Verification**: Verifies discovery queries LocalAPI `status.Self.TailscaleIPs` where available, ensuring zero hallucinated network addresses.

---

### 2.2 Tier 2: Boundary & Corner Cases

Tier 2 exercises extreme, unusual, and defensive failure boundaries.

1. **T2.B1: Unknown Fields Strict Rejection**: Because `dec.KnownFields(true)` is strictly enforced in `internal/config/config.go`, any typo such as `kernel_mode: davin`, `kernel_type: bacarra`, or `engine: davin` must be immediately rejected with an unmarshal error.
2. **T2.B2: Strict Case Sensitivity**: Verifies that uppercase or mixed-case values (`kernel: Davin`, `kernel: BACARRA`, `kernel: DaViN`) are strictly rejected by the validator to prevent runtime ambiguity.
3. **T2.B3: Corrupt Route State File Recovery**:
   - If `<stateDir>/bacarra_routes.json` contains malformed JSON, truncated bytes, or missing fields:
   - The route loader safely detects corruption, returns a clean error, and provides crash recovery mechanisms to safely clear invalid states without panicking.
4. **T2.B4: Unprivileged Permissions Error Handling**:
   - Modifying OS routing tables in Bacarra mode requires root (`CAP_NET_ADMIN`) on Linux/macOS or Administrator on Windows.
   - Verifies that attempting route operations without elevation returns a distinct permission error (`os.ErrPermission` or clear diagnostic) rather than an unhandled panic.
5. **T2.B5: Empty and Boundary CIDR Routing**:
   - Tests rules containing edge-case CIDR definitions: `0.0.0.0/32`, `255.255.255.255/32`, `127.0.0.1/32`, `::1/128`, and invalid prefix lengths (`/33`, `/129`).
   - Verifies that only valid, non-direct IP prefixes are selected for route hijacking.

---

### 2.3 Tier 3: Cross-Feature Interactions

Tier 3 exercises interactions between multiple distinct subsystems.

1. **T3.I1: Kernel Switching (Davin <-> Bacarra)**:
   - Tests transitioning configuration between `davin` and `bacarra` kernels.
   - Verifies that Davin mode isolates state to tsnet directories (`<stateDir>/tsnet/_main`), while Bacarra isolates state to `<stateDir>/bacarra_routes.json`.
2. **T3.I2: Rule Engine Routed Prefix Extraction for Bacarra**:
   - Configures rules with multiple targets (`target: slot1`, `target: direct`, `target: reject`, `target: tailnet`).
   - Verifies that `rule.Engine.RoutedPrefixes()` extracts only prefixes for proxied targets, completely excluding `target: direct`.
   - Combines with FakeIP pools (`198.18.0.0/15`, `fc00::/18`) to form the exact, complete route set to be injected into the Tailscale adapter.
3. **T3.I3: Dynamic Config Reload & Route Diffing**:
   - Simulates config reload where new CIDR rules are added and obsolete CIDR rules are removed.
   - Verifies route diffing: newly added routes are staged for injection, obsolete routes are staged for deletion, and unchanged routes remain untouched.
4. **T3.I4: FakeIP Pool & Domain Query Interception**:
   - Verifies that DNS requests for domains matching routed rules receive FakeIP addresses (`198.18.0.0/15`), while direct domains receive public IPs.
   - Confirms that in Bacarra mode, only FakeIP ranges and explicit CIDRs hit the Tailscale adapter, preserving normal internet access for direct domains.
5. **T3.I5: Windows NextHop Assignment Coexistence**:
   - On Windows, verifies that injected routes specify NextHop `100.100.100.100` rather than `0.0.0.0` or interface local IP, completely avoiding Windows WSA error 10049 (subnet broadcast reservation bug).

---

### 2.4 Tier 4: Real-World Scenarios & Full Lifecycle Simulation

Tier 4 tests complete lifecycle workflows from configuration to teardown.

1. **T4.S1: Simulated Bacarra Full Lifecycle**:
   - **Step 1 (Pre-Flight Check)**: Validate configuration using `tailproxy check`.
   - **Step 2 (Startup & Pre-Clean)**: Check for stale `<stateDir>/bacarra_routes.json` from any previous abnormal termination, simulate safe purge.
   - **Step 3 (Adapter Discovery & Verification)**: Discover official Tailscale adapter on host, verify CGNAT IP range, fail fast if missing.
   - **Step 4 (Route Calculation & State Persistence)**: Calculate route prefixes (FakeIP + routed rule CIDRs), atomically write `<stateDir>/bacarra_routes.json`.
   - **Step 5 (Graceful Teardown)**: Execute teardown cleanup, verify all tracked routes are scheduled for deletion, remove state file.
   - **Step 6 (Teardown Idempotency)**: Re-execute teardown on already-cleaned state; assert zero errors, zero panics, zero leftover files.

2. **T4.S2: Simulated Crash Recovery & Capture Down**:
   - Create a simulated dirty state where tailproxy was terminated via SIGKILL, leaving `<stateDir>/bacarra_routes.json` populated with active routes.
   - Invoke `tailproxy capture down` / route purge recovery.
   - Verify that the recovery engine reads the persisted state file, removes every recorded route, and unlinks the state file.
   - Execute second cleanup to confirm complete idempotency.

---

## 3. Test Suite Directory Structure & Implementation Layout

All E2E tests reside under `test/e2e/`:

```
e:\tailproxy\
├── TEST_INFRA.md               # Architecture, specification, and execution guide (this document)
├── TEST_READY.md               # Test suite readiness summary and runner commands
└── test/
    └── e2e/
        ├── harness_test.go     # Test fixtures, temp environments, CLI exec helpers, assertions
        ├── tier1_coverage_test.go  # Tier 1: Feature coverage (>=5 cases per feature)
        ├── tier2_boundary_test.go  # Tier 2: Boundary, schema, casing, corrupt state recovery
        ├── tier3_interaction_test.go # Tier 3: Kernel switching, rule prefix extraction, diffing
        └── tier4_lifecycle_test.go  # Tier 4: End-to-end simulated lifecycles & crash recovery
```

---

## 4. Progressive Testability Matrix

Because the dual-kernel refactoring is implemented across milestones (M1 to M5), the E2E test suite is designed with **progressive testability**:

| Milestone | Deliverables | E2E Tests Verifiable |
|---|---|---|
| **M1** | Config schema, `internal/config`, `internal/schema`, `internal/kernel/engine.go` | T1.F1 (Config schema), T1.F2 (Default kernel), T2.B1 (Unknown fields), T2.B2 (Casing) |
| **M2** | Bacarra adapter discovery, route manager, `bacarra_routes.json` state persistence | T1.F4 (Adapter discovery & fail-fast), T2.B3 (Corrupt state recovery), T3.I2 (Prefix extraction), T4.S1 (Full lifecycle simulation) |
| **M3** | Daemon dispatch, CLI (`tailproxy check`, `tailproxy status`, `tpctl schema`), Web panel | T1.F3 (CLI commands), T3.I1 (Kernel switching runtime), T4.S2 (Capture down crash recovery) |
| **M4** | Documentation (`README.md`, `docs/DESIGN.md`) & Skills (`plugins/tailproxy/skills/*`) | Documentation parity and skill configuration consistency verification |
| **M5** | Full integration, E2E test suite execution, adversarial audit | Complete suite execution (`go test -v ./test/e2e/...`), 100% pass |

---

## 5. Test Execution Instructions

### 5.1 Running the Full E2E Test Suite
To execute all E2E test tiers from the project root:
```powershell
go test -v ./test/e2e/...
```

### 5.2 Running Individual Tiers
To execute a specific tier:
```powershell
# Tier 1: Feature Coverage
go test -v ./test/e2e -run "TestTier1"

# Tier 2: Boundary & Corner Cases
go test -v ./test/e2e -run "TestTier2"

# Tier 3: Cross-Feature Interactions
go test -v ./test/e2e -run "TestTier3"

# Tier 4: Real-World Scenarios
go test -v ./test/e2e -run "TestTier4"
```

### 5.3 Complete Repository Verification
To verify that E2E tests and all internal package unit tests pass concurrently:
```powershell
go test ./...
```

---

## 6. Ground Truth & Expected Output Derivation Table

| Test Case | Input / Condition | Expected Output / Behavior | Authoritative Reference |
|---|---|---|---|
| `TestTier1_Feature1_ExplicitDavin` | YAML with `kernel: davin` | Config parsed, `cfg.Kernel == "davin"` | `PROJECT.md` § Interface Contracts |
| `TestTier1_Feature1_ExplicitBacarra` | YAML with `kernel: bacarra` | Config parsed, `cfg.Kernel == "bacarra"` | `PROJECT.md` § Interface Contracts |
| `TestTier1_Feature1_InvalidKernel` | YAML with `kernel: invalid` | Error containing `"invalid kernel mode"` | `PROJECT.md` § Feature 2 |
| `TestTier1_Feature2_OmittedDefault` | YAML without `kernel` key | Parsed config has `cfg.Kernel == "davin"` | `ORIGINAL_REQUEST.md` § R1 |
| `TestTier1_Feature3_CLICheck` | `tailproxy check -c valid.yaml` | Exit 0, output contains "配置有效" | `cmd/tailproxy/check.go` |
| `TestTier1_Feature4_AdapterFailFast` | Interface scan without Tailscale | Discovery fails with `ErrTailscaleNotDetected`, no mock | `ORIGINAL_REQUEST.md` Guidelines |
| `TestTier2_Boundary_UnknownFields` | YAML with `extra_field: 123` | Parse fails due to `dec.KnownFields(true)` | `internal/config/config.go:239` |
| `TestTier2_Boundary_CorruptState` | Malformed JSON in state file | State loader returns error, handles gracefully | `PROJECT.md` § Feature 10 |
| `TestTier3_Interaction_RoutedPrefixes`| Rules with direct, slot, and CIDR | `RoutedPrefixes` includes slot CIDRs, excludes direct | `internal/rule/rule.go:211` |
| `TestTier4_Lifecycle_FullSimulation` | Full lifecycle sequence | Config valid -> routes tracked -> state file written -> teardown removes state file | `PROJECT.md` § Milestones M2, M3 |
