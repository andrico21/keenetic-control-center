# problems - kcc-review-remediation (append only)

## [2026-11-14] Backlog candidates collected by the orchestrator (for todo 51's docs/BACKLOG.md)
- Todo 35: `secret_pages::dialog::SecretDialog` (`partials/secret_dialog.html`) stays a second dialog engine: its typed-twice pair has its own markup (autocapitalize, rules on both fields, help under the first only, ids secret-new/secret-repeat) that the engine's secret kind does not reproduce byte-identically.
- Todo 34: `routing_page/route_remove.rs` runs through `Action::run_planned(Planned::working(..))` outside `Submission` (route-wipe guard answer needs reads and an extra audit after the run).
- Todo 34: dropped 403 pre-checks (VPN dialog, VPN import): a role with Write but not the planned risk's permission sees the kit's forbidden outcome instead of the 403 page; reboot/reset/mesh-restart ask for confirmation after `context()`.
- Todo 34: on the KN-1811 fake, created PPPoE/PPTP connections are not listed back, so the golden harness's valid `internet/password` and `vpn/credential` submits answer 404 (harness limit).
- `ApplyNeeds::raw_restore` has no production caller; `crates/kcc-app/src/workflow.rs` still ~1509 lines; weak red evidence for todos 7, 23, 25; golden harness gaps (later migration-wizard and preset-run steps, SSE streams, raw restore, one-time API keys).
