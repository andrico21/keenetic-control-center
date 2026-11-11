# Architecture

kcc is one Rust binary built from a Cargo workspace. This document maps the crates,
follows a request from a front end to the router, and describes the change workflow,
the command catalog and the test tiers.

## Crates

| Crate | Owns |
|---|---|
| `kcc-rci` | RCI HTTP client: outbound policy and DNS pinning, TLS verification and pinning, ndw2/ndw4/digest sign-in, sessions, background commands, firmware and capability detection |
| `kcc-catalog` | the command catalog per firmware line and model, request and CLI-line validation |
| `kcc-config` | router configuration text: parsing, flattening, `ns3` secrets, redaction |
| `kcc-domain` | curated domains (system, interfaces, Wi-Fi, clients, DHCP, segments, routing, policies, NAT, firewall, DNS, VPN, services, components, ...): typed reads and planners for writes |
| `kcc-migrate` | migration sources, target inventory, classification rules, planner, applier, presets |
| `kcc-app` | `kcc.toml`, the state store, encryption, accounts, API keys, roles, router registry, change workflow, backups, jobs, audit log, shared poller |
| `kcc-telemetry` | Prometheus exporter and router log collection and forwarding |
| `kcc-i18n` | every user-visible string in en, ru, uk, de, be and kk |
| `kcc-web` | the Web UI (axum, askama templates, htmx) |
| `kcc-mcp` | the MCP server: tool registry, toolsets, argument validation, result shaping |
| `kcc-testkit` | the fake router, fake log sinks, fixtures and the capture tool |
| `kcc` | the binary: CLI, `serve`, `mcp stdio`, privilege floor |
| `xtask/` | a separate workspace with project gates and generators |

## Data flow

```text
browser ── /ui ─┐
MCP client ─/mcp┼─ rmcp-server-kit (TLS, Origin, API keys, RBAC, rate limits)
                │      ├─ kcc-web  ─┐
                │      └─ kcc-mcp  ─┤
kcc <command> ──┴──────── CLI ──────┤
                                    ▼
                 kcc-app: permissions ─ router registry ─ change workflow ─ audit
                                    │                         │
                       kcc-domain planners ── kcc-catalog validation
                                    ▼
                         kcc-rci session ── outbound policy ──► router
```

- `kcc serve` runs one HTTP listener (rmcp-server-kit) that carries MCP on `/mcp`, the
  Web UI under `/ui`, and `/healthz`, `/readyz`, `/version`. It holds the state
  directory's server lock, so only one server runs per state directory.
- `kcc mcp stdio` and CLI runs share the same state directory without that lock;
  per-file locks, per-router leases and the audit append lock keep them consistent.
- One shared **poller** issues all periodic router reads. Web live views and the
  Prometheus exporter subscribe to it; scrapes and page renders read its cache.
- The **log collector** keeps one `show log` stream per router and fans records out to
  the Web log page and the configured sinks.
- Long operations (diagnostics, component commits, migrations, preset applies) run as
  **jobs** with progress events; one write job per router at a time.

## Change workflow

Every write from any front end goes through `kcc-app`'s `ChangeWorkflow`:

1. **Authorize** the exact operation permission and router scope.
2. **Lease**: take the per-router lease (a lock file), so one change at a time runs
   per router across processes.
3. **Baseline**: read the router's last-change marker and catalog.
4. **Validate**: the domain planner builds the request; `kcc-catalog` validates every
   path, argument and CLI line for the router's firmware and model. Nothing is sent if
   validation fails.
5. **Backup**: an encrypted backup of the startup configuration.
6. **Conflict check**: refuse if someone else changed the router since the baseline.
7. **Apply**, then **read back** and compare with the expected result.
8. **Audit**: append the outcome to the hash-chained audit log.

Changes classified as management risk run between arming and disarming the router's
fail-safe timer (`system configuration fail-safe timer`, 300 s). If kcc loses the
router mid-change, the router restores its saved configuration. Saving is a separate
operation. Migrations and preset applies use the same pieces through `kcc-migrate`'s
applier: fail-safe for the whole run, one line at a time, verification, then commit or
rollback ([MIGRATION.md](MIGRATION.md)).

Management brackets authorize the operation and `SafetyNet::management_permissions()`
before arming. Arming, disarming, keep-alive and rollback share `Destructive`; commit
retains `Save`. CLI, Web and raw and curated MCP writes use this same recovery
permission set. MCP's shared planned-write executor chooses the bracket from the
actual `ChangeOp` risk, including WAN addressing and firewall bindings classified
in `kcc-domain`. Firewall list changes inspect all affected interfaces and fail
closed if discovery fails. HTTP, SSH and Telnet service toggles also receive their
management classification from the domain, shared with the Web and CLI. Router
mode uses the native timer; other modes use a cancellable scheduled reboot. The
curated interface guard retains native recovery and its positive arm verification
until a scheduled-reboot verification contract is established. If cleanup fails after
application, the result reports the applied change and tells the caller to treat
recovery as still armed, rather than reporting a refused change.

## Command catalog

`catalog/<version>/` holds structural command facts (paths, argument types, model
applicability) for firmware 4.3, 5.0 and 5.1, generated from Keenetic's official
command reference PDFs:

```text
cargo xtask catalog fetch --version 5.1    # download into catalog/.cache, record hashes
cargo xtask catalog extract               # PDF to text (poppler in a container)
cargo xtask catalog build --version 5.1    # parse and write catalog/5.1/*.json
```

`catalog/sources.lock` records every manual's URL and SHA-256, and `catalog/overlay.toml`
adds facts the manuals lack (background and destructive commands). The JSON is embedded in the binary. A router uses the newest
catalog line not newer than its firmware (5.2 uses 5.1) and its exact model, or the
union of all models when the model is unknown. See [catalog/README.md](../catalog/README.md).

## Generated documents

- `docs/MCP_TOOLS.md`: `cargo xtask gen-tool-docs`.
- `docs/METRICS.md`: `cargo xtask gen-metric-docs`.
- `crates/kcc-i18n/src/keys.rs`: from the English Fluent files ([I18N.md](I18N.md)).
- `deploy/podman/seccomp-kcc.json`: `cargo xtask seccomp trace` and `gen`.

Tests fail when a committed copy differs from what its generator produces.

## Test tiers

- **Unit**: inline `#[cfg(test)] mod tests` in each crate.
- **Integration**: each crate's `tests/*.rs`, always against the fake router in
  `kcc-testkit` (`FakeRouter::spawn()`), never a real router. Process tests drive the
  built `kcc` binary with a hermetic home, config and master key.
- **Documentation**: `crates/kcc/tests/docs.rs` runs the tagged shell examples in the
  README and `docs/`, checks that [CONFIG.md](CONFIG.md) documents exactly the keys
  `kcc.toml` accepts, checks relative links, and compares the hardware-verified lines in
  [FIRMWARE.md](FIRMWARE.md) with the code.
- **Live**: `crates/kcc/tests/live_*.rs`, ignored by default, run only with the
  `KCC_LIVE_*` variables set and only against routers marked `test_device = true` whose
  serial is allow-listed. A missing variable logs `live-skip:<reason>`.
