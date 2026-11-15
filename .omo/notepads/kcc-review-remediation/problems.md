# problems - kcc-review-remediation (append only)

## [2026-11-14] Backlog candidates collected by the orchestrator (for todo 51's docs/BACKLOG.md)
- Todo 35: `secret_pages::dialog::SecretDialog` (`partials/secret_dialog.html`) stays a second dialog engine: its typed-twice pair has its own markup (autocapitalize, rules on both fields, help under the first only, ids secret-new/secret-repeat) that the engine's secret kind does not reproduce byte-identically.
- Todo 34: `routing_page/route_remove.rs` runs through `Action::run_planned(Planned::working(..))` outside `Submission` (route-wipe guard answer needs reads and an extra audit after the run).
- Todo 34: dropped 403 pre-checks (VPN dialog, VPN import): a role with Write but not the planned risk's permission sees the kit's forbidden outcome instead of the 403 page; reboot/reset/mesh-restart ask for confirmation after `context()`.
- Todo 34: on the KN-1811 fake, created PPPoE/PPTP connections are not listed back, so the golden harness's valid `internet/password` and `vpn/credential` submits answer 404 (harness limit).
- `ApplyNeeds::raw_restore` has no production caller; `crates/kcc-app/src/workflow.rs` still ~1509 lines; weak red evidence for todos 7, 23, 25; golden harness gaps (later migration-wizard and preset-run steps, SSE streams, raw restore, one-time API keys).

## [2026-11-14] Backlog candidates (todos 36-37)
- Todo 37: the two-directory line count drops by 2646 but wizard/ holds 2565 (+55 in lib.rs): real net deduplication is -26 lines of Rust and -3 templates; the rest of the plan's number is moved code.
- Todo 37: presets' run list and event end now go through the shared Store (adds a record-id == directory check and a schema check): unreachable through the UI.
- Todo 36: the one confirmation template drops a stray 2-space indent of the old migration confirm dialog (whitespace only).

## [2026-11-14] Backlog candidates (todo 38)
- Wizard finish routes: migration keeps /commit, /rollback, /{way} and presets one /{way}; the shared core serves both but 3 entry handlers remain. Unifying migration onto the presets shape would change edge behavior (content-type of commit, dialog order, unknown way 404 order): owner decision.

## [2026-11-14] Backlog candidates (todos 39-40)
- Five tables stay outside `kit_table.html`: wizard rename grids (`migrate_mapping.html`, `presets_macros.html`), wizard review grids with checkboxes/radios (`migrate_review.html`, `presets_review.html`), and the side-by-side config diff (`config_diff.html`). A form-control cell kind and a multi-tbody view would let them join; each serves only one or two pages.
- Rust for the converted pages grew (+1114 pure LOC in todo 39, +1446 in todo 40) while templates shrank (-601, -803): the markup moved into typed builders, not a size reduction.

## [2026-11-14] Backlog candidate (found during the guidelines adoption)
- `xtask/` is a separate workspace excluded from `cargo fmt --all`; `cd xtask && cargo +nightly-2026-10-03 fmt -- --check` fails in the untouched `xtask/src/seccomp.rs`, `seccomp_gen.rs`, `seccomp_groups.rs`. No gate or CI job checks xtask formatting.

## [2026-11-14] Backlog candidate (todo 42)
- The domain firewall read is a running-config text read (same single request the page always sent); `kcc_domain::firewall::read::configured_rules` (JSON, three requests, IPv4 only) still exists for the CLI. Two readers of the same data remain; unifying them would change the CLI's request count.
- A binding with a direction other than in/out is skipped by the new read (the old page labelled it "in"): the firmware only writes in/out.

## [2026-11-15] Findings left by todo 49 (for the backlog)
- `crates/kcc/tests/cli_domain_writes/admin.rs`: the refusal of an absent firewall rule property prints a sentence with no machine-readable handle; the test now asserts exit code 4 and that no write request was sent.
- Real-time waits outside the named files were reported but not changed: `kcc-telemetry/tests/logs.rs` (239, 257, 290, 292), `kcc/tests/metrics_serve/runtime.rs` (a 500 ms real-time poll loop), `kcc-web/tests/dashboard.rs`, `bracket_ordinary.rs`, `bracket_budget.rs`, and the preset/wizard finish recovery tests.
- `kcc-testkit` fake router: `up` and `down` are now one interface state and the last written wins (the engine kept them as two leaves in first-insertion order).
