# decisions - kcc-review-remediation (append only)

## [2026-11-13] Todo 1 progress (worker r1)
Changed-expectation list (default fake = mode not reported, fail-safe object with boolean `active`; D-Q2 now gives it the fail-safe timer on CLI and MCP):
- crates/kcc/tests/cli/migrate.rs `failed_verification_reports_the_completed_automatic_rollback`: the automatic rollback is now the native `system configuration fail-safe rollback` instead of `system reboot`.
- crates/kcc/tests/cli_domain_writes/admin.rs `management_port_needs_yes_and_runs_inside_the_fail_safe_bracket`: audit entries name the `system configuration fail-safe timer` operation instead of `system reboot`.
- crates/kcc-mcp/tests/support/bracket.rs `management_bracket_disarm_failure_reports_applied`: disarm attempted is `no system configuration fail-safe timer`.
- crates/kcc-mcp/src/domains/write/common/tests.rs `synthetic_management_operation_brackets_both_apply_entries`: first/last command are the timer arm/disarm.
New tests (one per surface, same five-row table): kcc/tests/cli/bracket_mode.rs, kcc-mcp/tests/support/bracket_management_fate.rs `recovery_mechanism_follows_the_reported_mode`, kcc-web/tests/explorer_pages/bracket_mode.rs; inline table test `decide_follows_the_recovery_table` in kcc-domain configuration.rs.
Design notes: (1) CLI finish paths (config failsafe commit/rollback, migrate finish, preset finish) need the mode before any change set exists (they pick permissions and the rollback command first), so they use `change::recovery_mode(target)`: the target's fresh per-invocation detect plus a fresh `show last-change` fed to the same `SafetyMode::decide`. The arming path (run_completed), Web apply_with and MCP raw_change use `SafetyMode::for_change(&changes)`. (2) Web: `Refused` gained a `mode_unknown` flag (toast key management-mode-unknown, audit outcome id mode_unknown); the decision runs after `begin` and before `brackets::hold()`. (3) kcc-testkit `migration::Fixture.omit_fail_safe` removes the fail-safe object from show last-change. (4) The MCP QA filter `bracket_management_fate` matches no test path (module is bracket_failures::management_fate); the filter `bracket` was used.

## [2026-11-13] Todo 19 decisions
- The engine does NOT call `SessionManager::with_options_and_client_builder`: it forces `HttpTimeouts::default()` and would drop configured timeouts. Both paths now share the crate-private `SessionManager::with_auth(options, password_configured)` (same validation as before); `with_options_and_client_builder` stays `#[doc(hidden)]` since it is not the production path.
- The engine marks credentials as password-configured always; a token-only registry profile passes placeholder credentials (profile login, empty password). Password fallback needs `token_fallback`, which kcc never enables, so this is inert.
- Config `token_file` with `auth = "auto"` (accepted by config validation) is converted to `auth = Token` in the registry profile.
- Read-only polling credentials never carry the token; their mode is the profile's mode with Token -> Auto.
- `RouterRegistry::transition` persists a replacement password only when the profile has a `password_file`; `ChangeSet::restore_connection` passes `None` for profiles without one.
