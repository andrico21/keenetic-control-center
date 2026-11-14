# issues - kcc-review-remediation (append only)

## [2026-11-13] Todo 11 (found, out of scope)
- docs/SECURITY.md:162 ("every raw `ip route` item needs `Destructive` and the recovery timer") and docs/USER_GUIDE.md:22 ("need the Destructive permission and run under the router's fail-safe timer") describe the pre-D-Q1 rule. MCP no longer needs the Destructive role permission for management changes (server switch still required for raw); Web/CLI still do until todos 10/12. The last surface todo should update both docs.

## [2026-11-13] Todo 10 findings outside scope
- `crates/kcc/src/cli/migrate_apply.rs` `apply_failure`: `ApplyError::ArmUnconfirmed` headlines `management-not-sent-armed` via `headline_only`, so `--json` output and audit do not carry `fail_safe_armed: true` although the timer may be armed. Fix: `Failure::armed(Exit::Router, ArmedFate::NotSent)` (todo 15 territory).
- Docs still say raw/management changes need `Destructive` (`docs/SECURITY.md:135-170`, `docs/USER_GUIDE.md:22`); true for MCP/Web until todos 11/12, wrong for the CLI after todo 10. Update with todo 18 (D-Q1 on every path).

## [2026-11-13] Todo 12 (worker r12) findings outside scope
- Interface pages (`net_interface_actions.rs` -> `kcc-domain/src/interfaces/guard.rs`): after the Web gate moved to `SafetyNet::required`, an operator sees the interface disable control and passes the page gate, but the guard still arms with `SafetyNet::CONTROL_PERMISSION` (Destructive), so the change set refuses the arm (nothing is sent; the user gets a failure). Closes when todo 13 moves the guard onto the shared bracket with the change's permission.
- The raw console line `system configuration fail-safe timer reboot 300` is catalog risk Management, so after D-Q1 a RawRci role without Destructive may send it (inside kcc's own bracket). D-Q1 keeps Destructive for "explicit standalone timer control" (`kcc config failsafe arm|rollback`); whether a raw console timer line counts as that is an owner question (catalog overlay could mark it destructive).
- `crates/kcc-web/src/page_kit/change.rs` is ~406 pure LOC (was 411 before this todo), over the 250 ceiling; pre-existing.

## [2026-11-13] Todo 14 (worker r14)
- The Web wizard and preset restarting tests (`silent_extender_wizard_rollback_reports_restarting`, `silent_extender_preset_rollback_reports_restarting`) fail on this branch alone: the finish routes' 30 s `TimeoutLayer` (todo 17 scope) answers 408 and drops the rollback before `wait_restored` (120 s) ends. With the layer lifted (scratch, reverted) both pass. They need todo 17 merged first (and its budget must let the rollback run to its end).
- CLI one-shot `kcc migrate apply --finish rollback` on a silent extender is not covered at process level: the binary has no clock seam, so the restore wait costs 120 s real time. The engine path is covered by kcc-migrate `finish_recovery` (fake clock) and the CLI mapping by `apply_failure`.

## [2026-11-14] Todo 52 (out of scope, left for follow-ups)
- Web router audit (`router.profile_create/update`, crates/kcc-web/src/router_access.rs) still logs `credentials_changed: bool`, not the `credentials` kind list the CLI now writes; and the Web edit form cannot handle a token profile (storing a password leaves `token_file` set, so `validate` refuses it). Both belong to todo 53 (Web router form).
- `kcc router edit --url` runs no outbound-policy check on the new URL (pre-existing; `router add` does).

## [2026-11-14] Todo 53 (found, not fixed: out of scope)
- `/ui/routers/test` (`crates/kcc-web/src/router_check.rs`) tests a typed password with automatic sign-in only: it ignores the selected sign-in mode and cannot test a typed API token (`RouterRegistry::test_connection_with` takes a password). A stored token profile tests fine with empty fields.
- The password/token switch rule exists twice: `crates/kcc/src/cli/router_edit.rs::plan` (clap-shaped) and `crates/kcc-web/src/router_form/plan.rs`; both reuse `ManagedRouterProfile::moves_endpoint`. A kcc-app credential-plan seam would make it one.
- `crates/kcc-web/src/router_form/address.rs::is_slug` duplicates `kcc_app::registry` `valid_router_id`/`is_valid_router_id`.
- `crates/kcc-web/tests/dashboard.rs` is ~1250 lines (pre-existing); the new tests went into `tests/dashboard/router_{credentials,readers}.rs`.
- No PNG screenshots for todo 53 (no browser tooling for workers); todo 45's golden capture or the orchestrator's browser should look at the router form at 390 px dark / 1280 px light.

## [2026-11-14] Todo 34: kit changes needed to finish the migration (submit.rs is todo 33's)
1. Outcome recast: `Submission` needs a hook to replace a successful run's headline (secret pages' `reply::verified`/`confirmed`, VPN import's `confirmed`) and to add an extra region (VPN import's skipped-field notes, `Answered::notes`). Blocks wifi_psk, wan_password, user_password, vpn_server password, vpn_import.
2. Landing for the run's answer only: user_delete shows a refused plan in its dialog (no retarget) but lands the run's outcome in #page-outcome; `landing_in` retargets both. Blocks user_delete.
3. `Form::answer_refused` gets only `Failure`; pages whose refusal words depend on the DomainError (router users' ProtectedAccount text) or on a router read (DNS dialog lists) keep them in a local OnceLock/Mutex filled by the plan closure. Passing `&DomainError` (or letting the plan return its refusal answer) removes those slots.
