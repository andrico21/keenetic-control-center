# Architecture

kcc is one Rust binary built from a Cargo workspace. This document maps the crates,
follows a request from a front end to the router, and describes the change workflow,
the command catalog and the test tiers.

## Crates

| Crate | Owns |
|---|---|
| `kcc-rci` | RCI HTTP client: outbound policy and DNS pinning, TLS verification and pinning, ndw2/ndw4/digest sign-in, sessions, background commands, firmware and capability detection |
| `kcc-catalog` | the command catalog per firmware line and model, request and CLI-line validation |
| `kcc-config` | router configuration text: parsing, flattening, `ns3` secrets, and the one secret masker (`mask.rs`) that the Web UI, MCP and CLI all use to redact answers |
| `kcc-domain` | curated domains (system, interfaces, Wi-Fi, clients, DHCP, segments, routing, policies, NAT, firewall, DNS, VPN, services, components, ...): typed reads and planners for writes |
| `kcc-migrate` | migration sources, target inventory, classification rules, planner, applier, presets |
| `kcc-app` | `kcc.toml`, the state store, encryption, accounts, API keys, roles, router registry, change workflow, backups, jobs, audit log, shared poller |
| `kcc-telemetry` | Prometheus exporter and router log collection and forwarding |
| `kcc-i18n` | every user-visible string in en, ru, uk, de, be and kk |
| `kcc-web` | the Web UI (axum, askama templates, htmx). Shared kits: `page_kit` (`submit`, `form`, `confirm`, `respond`, `request`) runs every write page, `crate::table` renders every table, `crate::wizard` is the one engine of the migration wizard and the preset runs |
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
  directory's server lock, so only one server runs per state directory. A state watcher
  (`crates/kcc/src/state_watch.rs`) checks `api_keys.json` and `users.json` every 2 s, so a
  key revoked or an account changed by the CLI reaches the running server without a
  `SIGHUP` ([SECURITY.md](SECURITY.md)).
- `kcc mcp stdio` and CLI runs share the same state directory without that lock;
  per-file locks, per-router leases and the audit append lock keep them consistent.
- One shared **poller** issues all periodic router reads. Web live views and the
  Prometheus exporter subscribe to it; scrapes and page renders read its cache.
- The **log collector** keeps one `show log` stream per router and fans records out to
  the Web log page and the configured sinks.
- Long operations (diagnostics, component commits, migrations, preset applies) run as
  **jobs** with progress events; one write job per router at a time.
- The **scheduler** (`crates/kcc/src/server_schedules.rs`) runs only in `kcc serve`,
  started after the notifier. Its timetable follows `schedules.json` through the state
  watcher and the registry's profile changes, reads `last_fired_slot` from
  `schedule_runs.json`, and wakes at the earliest slot or every 30 s to read the wall
  clock again. A due slot goes to its router's queue; one worker per router runs the
  queue in order through `run_once`: it re-reads the schedule and its owner (pausing it
  when the owner can no longer run it), records the run as started in the ledger, runs
  the action as a `scheduled.<action>` job under a workflow bracket guard (the change
  goes through the change workflow), records the outcome, appends `schedule.run` to the
  audit log and hands a line to the notifier. A run-now from the Web UI or the CLI uses
  the same `run_once`. At shutdown the scheduler's own cancellation token is cancelled
  as soon as the listener stops; the server waits at most 10 s for the run in progress,
  then for open brackets, the jobs, the notifications and the audit writer.

`show rc` and `show sc` return an opaque `ConfigurationAnswer`, not the general RCI
response type. Its private router envelope is projected inside `kcc-rci`; consumers can
read only `configuration_tree()`. This makes the envelope and requested configuration
root agree by construction and prevents a new reader from silently choosing a wrong root.

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
6. **Conflict check**: refuse if the router's configuration checksum differs from the
   state kcc last observed (the baseline, updated after each of kcc's own writes), so a
   change by any other client is refused; the router reports the same agent for every
   RCI client, so the agent is not compared.
7. **Apply**, then **read back** and compare with the expected result.
8. **Audit**: append the outcome to the hash-chained audit log.

Changes classified as management risk run between arming and disarming the router's
fail-safe timer (`system configuration fail-safe timer`, 300 s). If kcc loses the
router mid-change, the router restores its saved configuration. The arm runs the full
preflight first; the disarm, the keep-alive and the rollback skip the conflict check
and the backup (keeping the permission and scope check), so that no local refusal keeps
the timer running. Saving is a separate
operation. Migrations and preset applies use the same pieces through `kcc-migrate`'s
applier: fail-safe for the whole run, one line at a time, verification, then commit or
rollback ([MIGRATION.md](MIGRATION.md)).

## The shared bracket seam

Every management change on every surface runs through one function,
`kcc_domain::configuration::bracket::guarded`, so the CLI, MCP and the Web UI arm,
work, disarm and report the same way.

- **Arm, work, disarm.** `guarded` refuses an unheld request (`WorkflowError::Unowned`)
  or a dead audit writer before anything is sent. It also refuses, with nothing sent, a
  change set whose baseline shows the router's fail-safe timer already active, armed by
  an operator or another run (`WorkflowError::RecoveryTimerInUse`, fate
  `Fate::TimerInUse`, message `management-timer-in-use`): a bracket neither replaces nor
  disarms a timer it did not arm. Then it arms the router's recovery timer, runs the caller's
  work, and always sends a disarm afterwards, whatever the work returned. The timer is
  300 seconds everywhere. Only a dropped future or a panic skips the disarm, and then the
  router's own timer restores the saved configuration.
- **One permission.** Arm, work and disarm are authorized by the permission of the change
  the timer protects (`Write`, `RawRci`, `Migrate`, ...), plus `Destructive` only for a
  destructive risk (`SafetyNet::required`). A role that may make a change may close its
  bracket.
- **Recovery mode from fresh facts.** `SafetyMode::decide` (and `SafetyMode::for_change`,
  which reads the change set's captured facts) picks the mechanism: router mode uses the
  native `system configuration fail-safe timer`; extender, access-point and repeater
  modes use a cancellable scheduled reboot; a router that reports no mode gets the native
  timer only when `show last-change` carries a fail-safe object with a boolean `active`
  member. Any other router is refused before anything is sent (CLI exit 10, MCP
  `router_mode_unknown`, Web toast `management-mode-unknown`).
- **What a failure says.** A failed bracket carries `recovery::Failure`, whose `fate()` is
  `None` when the timer is off, or an `ArmedFate` when it may still be armed: `NotSent`
  (the arm and its disarm both failed, nothing else was sent), `Applied` (the change was
  applied, the disarm failed), `Unknown` (the change may or may not have applied, the
  disarm failed) or `Saved` (the configuration was saved, the disarm failed).
  `Failure::message_key()` gives the sentence; a refused arm whose disarm was accepted
  reads "not applied, timer off". An audit writer that fails while a failed arm settles
  is that failure's error, as after the work.
- **One closing step.** `configuration::close` (`Close::{KeepUnsaved, Save, Rollback}`)
  ends a bracket for a keep, a save or a rollback in either mode: it disarms; commits
  (router mode: the native commit saves the startup configuration, so no second save
  follows) or saves and cancels the scheduled reboot; or sends the native rollback (router mode) or reboots at once (scheduled-reboot
  mode). The migration engine, preset runs and `kcc config failsafe` all use it.
- **The open-bracket count.** `kcc_app::brackets::Brackets`, owned by `ChangeWorkflow`,
  counts open brackets on every surface. `kcc serve` and `kcc mcp stdio` wait for it
  (at most 10 s, `BRACKET_GRACE` in `crates/kcc/src/server_shutdown.rs`) before they exit,
  then give the audit writer 5 s to flush.
- **Audit waits.** Queuing an entry never waits: `AuditLog::submit` puts it on the one
  unbounded queue to the writer, which keeps the log in submission order. Inside a
  bracket the change set defers its audit receipts (`ChangeSet::defer_audit`): the arm,
  the work and the disarm are queued in order and return at once, so another process
  holding the audit append lock cannot delay the disarm. After the disarm the bracket
  waits at most `BRACKET_AUDIT_WAIT` (20 s). An ordinary write waits `AUDIT_WAIT` (30 s)
  per receipt. The Web sign-in, sign-out and password change queue through
  `AuditLog::submit_within`, which waits for one of 128 slots within the caller's limit
  (`LOGIN_AUDIT_WAIT`, 5 s, for a sign-in) and refuses with `AuditError::QueueFull`
  otherwise, so the action is refused rather than done without its entry. The constants
  live in `crates/kcc-app/src/audit/receipt.rs`.
  A change the router applied whose entry is still queued is reported as applied with a
  pending note, because the writer keeps the entry and writes it later, in order.
- **Surfaces.** The CLI (`crates/kcc/src/cli/change.rs`, `cli/exit.rs`) maps a failure to
  an exit code and a headline, and adds `audit_pending` to `--json`. MCP
  (`crates/kcc-mcp/src/support/raw_change.rs`, `support/errors.rs`) maps the fate to
  `management_not_sent_fail_safe_armed`, `management_applied_fail_safe_armed`,
  `management_saved_fail_safe_armed` or `management_outcome_unknown_fail_safe_armed`, and
  adds `"audit_pending": true` to write results. The Web UI (`crates/kcc-web/src/page_kit/change.rs`)
  holds the request with `brackets::hold` before its first router request, so the server
  owns it until it ends (`crates/kcc-web/src/brackets.rs`), and shows the fate's sentence
  as a toast.
- **Migrations and presets** arm one longer bracket for the whole run in `kcc-migrate`'s
  applier and close it with the same `close` step ([MIGRATION.md](MIGRATION.md)).

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

## Web UI HTML

Templates escape every value they write. HTML is never passed around as a `String`:
a fragment one template embeds in another is either a child template, marked with
`fragment!` (`crates/kcc-web/src/lib.rs`), or a `markup::Rendered`, which only rendering
a template makes. Both are written as they are, because askama already escaped them;
text of any other type, router text included, is escaped. `cargo xtask assets-check`
fails on every other way to skip the escape: the `safe` filter, the `none` escaper, and
a safe-HTML marker outside those two files.

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
  built `kcc` binary with a hermetic home, config and master key. Tests under a paused
  tokio clock reach the fake over a Unix socket (`FakeRouter::serve_local` with the
  test-only `with_local_socket` hook of the outbound policy or registry), never over
  loopback TCP.
- **Documentation**: `crates/kcc/tests/docs.rs` runs the tagged shell examples in the
  README and `docs/`, checks that [CONFIG.md](CONFIG.md) documents exactly the keys
  `kcc.toml` accepts, checks relative links, and compares the hardware-verified lines in
  [FIRMWARE.md](FIRMWARE.md) with the code.
- **Live**: `crates/kcc/tests/live_*.rs`, ignored by default, run only with the
  `KCC_LIVE_*` variables set and only against routers marked `test_device = true` whose
  serial is allow-listed. A missing variable logs `live-skip:<reason>`.
