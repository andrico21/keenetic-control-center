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
