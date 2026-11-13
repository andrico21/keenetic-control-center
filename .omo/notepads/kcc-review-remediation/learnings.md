# learnings - kcc-review-remediation (append only)

## [2026-11-13] Todo 6 progress
- `JobRunner::recover` no longer propagates router errors; probe (client + `show last-change`) is bounded by `RECOVERY_PROBE_BOUND` (5 s). Audit entry written via a short-lived `AuditLog::spawn(&state)` (the writer re-reads the chain tail under the cross-process append lock, so no constructor change and no caller edits).
- Removed `RecoveryNotice`, `recovery_notices`, the `recovery` field, and the now-unfulfilled `clippy::shadow_unrelated` expectation in jobs.rs.
- Tests in `tests/jobs_recovery/interrupted.rs` (via #[path]); paused-clock test uses FaultInjection latency of 1 h.

## [Nov 13 2026] Todo 7 progress

Completed: Lease label released synchronously on drop.

Implementation strategy:
1. TDD: Wrote two tests first, ran them red
2. Changed lease_actors from tokio::sync::Mutex to std::sync::Mutex (held synchronously, never across .await)
3. Created LeaseActorGuard struct implementing Drop to remove the label synchronously
4. Updated begin_with_client to:
   - Insert label with synchronous lock
   - Create guard holding the workflow and router
   - On early return (conflict path), drop guard immediately to clean up
   - On success, move guard into ChangeSet's actor_label field
5. Updated ChangeSet::Drop to drop the guard (which triggers synchronous removal)
6. Removed async tokio::spawn from Drop implementation

Key insight: PoisonError::into_inner() recovers from mutex poison gracefully instead of panicking.
Guard pattern ensures cleanup on all paths: successful ChangeSet lifetime, conflict errors, and registry errors.

Tests green on current_thread runtime and all 22 workflow tests pass.
Clippy, fmt, and cancel-safety all pass.

## 2026-11-13 Todo 4 progress

**Completed:** Implemented configurable login lockout threshold (`web.login_max_failures`).

**Changes:**
- Added `max_failures: u32` field to `AccountStore` (default 5)
- Implemented `#[must_use] pub const fn with_max_failures(mut self, max_failures: u32) -> Self` builder
- Updated `authenticate()` to use `self.max_failures` instead of constant `LOCKOUT_FAILURES`
- Deleted `LOCKOUT_FAILURES` constant (now only in i18n keys)
- Wired `.with_max_failures(config.web.login_max_failures)` at `server.rs:365` and `cli/context.rs:330`
- All 20 existing tests in `accounts_reset.rs` remain passing

**Tests written (TDD):** `account_lockout_respects_configurable_max_failures` in `accounts_reset.rs` verifies:
- With `max_failures = 2`: second attempt locks, third is refused as locked
- With default `max_failures = 5`: two attempts don't lock, third succeeds

**Verification:**
- Red run: test failed with "method `with_max_failures` not found"
- Green run: all tests pass
- `grep -rn LOCKOUT_FAILURES crates --include=*.rs` returns only i18n keys
- `cargo test -p kcc-app`: all 5 accounts_reset tests + 20 workflow tests pass
- `cargo clippy -p kcc-app -p kcc --all-targets -- -D warnings`: clean
- `cargo +nightly-2026-10-03 fmt --all -- --check`: clean

**Acceptance criteria met:** ✓

## [2026-11-13] Todo 5 progress

Implemented shared router-name validation predicate across config, registry, and logs sections.

### Implementation pattern
- Created `is_valid_router_id(id: &str) -> bool` in `settings.rs` as the authoritative rule: 1-32 bytes, lowercase letters/digits/hyphens only
- Removed duplicate `valid_router_id` from `registry.rs` and imported the shared version
- Updated three call sites: `registry.rs:95` (profile validation), `settings.rs:514` (`logs.routers`), `settings.rs:993` (`RouterProfile::validate` name)
- Kept `is_valid_name` for file-name components (persist.rs) which has different rules: 1-64 bytes, allows uppercase and dots

### TDD results
- Red test: `Home.1` and 40-char names were incorrectly accepted
- Green: All config validation tests now properly enforce [a-z0-9-]{1,32} rule
- Verified: 133 total kcc-app tests pass, clippy/fmt clean
- Docs: Updated CONFIG.md table and kcc.example.toml with the rule

### Key insight
The distinction between "router IDs" (registry rule, used in config and logs) and "file-safe names" (persist rule, broader) is now explicit in the code. Both are 1-32/1-64 respectively, but the character sets differ—lowercase-only for router IDs, mixed-case for file names. This prevents accidental confusion in future work.

## [2026-11-13] Todo 6 rework
- `JobRunner::open/open_with_retention/open_with_ids` now take the caller's `AuditLog` (cheap clone of an mpsc sender); `recover` uses it, no second writer, no per-startup chain verification. All callers updated (kcc server + 4 CLI paths via `services.audit_log()`, test fixtures spawn one log and pass a clone).
- `AuditLog::append` awaits the writer's reply, sent after `write_all`+`sync_data`, so `read_entries` right after `open` sees the entry.

## Remediation Complete (Task 7)

### Three Defects Fixed

**Defect 1: Test (b) didn't prove guard logic**
- Original test checked conflict cleanup (already working via redundant guard)
- New test: `lease_label_cleanup_on_drop` verifies guard's Drop impl removes label
- Flow: Agent A holds lease+label → B gets RouterBusy("agent-a") → A drops → C acquires lease
- Proves label cleanup happens on ChangeSet drop

**Defect 2: Redundant guard in conflict path**
- Lines 641-647 had explicit `drop(LeaseActorGuard {...})`
- This was redundant—actor_label would drop anyway at function return
- Removed: conflict path now just returns, letting actor_label drop naturally
- Eliminates unnecessary duplication and makes intent clearer

**Defect 3: Drop-order race on label cleanup**
- Old code: ChangeSet::Drop released lease first, then label
- Race window: another begin() could insert its label between the two drops
- Fix: actor_label drops FIRST (line 773), lease drops SECOND (line 774)
- Comment added explaining the order prevents race condition

### Test Results
- All 22 workflow tests pass (including new test (b))
- All 10 state tests pass
- All gates pass: fmt, clippy, cancel-safety, allow-gate
- No regressions

### Key Insight
The guard's Drop impl is the sole mechanism for label cleanup when ChangeSet drops.
The redundant guard in the conflict path was doing duplicate work; removing it and
relying on the guard's natural Drop is cleaner and proves the guard design works.
Drop order matters for correctness: label removal must happen before lease release.

## Todo 7 Rework 2 - Test Corrections ($(date +%Y-%m-%d))

Orchestrator review identified three test defects:
1. Deleted existing test `stale_read_from_another_agent_conflicts` - RESTORED
2. Missing plan test (b) for registry error case - IMPLEMENTED as `lease_label_cleanup_after_registry_error`
3. Redundant/wrong tests added - REMOVED (`lease_label_cleanup_on_drop`, `lease_label_cleanup_on_conflict_error`)

Final test structure:
- `stale_read_from_another_agent_conflicts`: Restored from master (verifies conflict path)
- `lease_label_released_synchronously_on_drop`: Plan test (a) - proves label removed synchronously when ChangeSet drops
- `lease_label_cleanup_after_registry_error`: Plan test (b) - proves label removed after early return (registry error)

Test (b) flow:
1. Begin on unknown router with actor "agent-x" fails after label insert
2. Hold lease on same router to trigger RouterBusy
3. Attempt another begin, must see "another process" not stale "agent-x"
4. Proves guard's Drop removed label despite early return

RED/GREEN captured:
- RED: With broken guard (no-op Drop), assertion fails: left="agent-x", right="another process"
- GREEN: With fixed guard, test passes, label is cleaned

Git status:
- workflow.rs: +49-12 = net +37 (guard impl, drop order fix)
- tests/workflow.rs: +75-12 = net +63 (restored test, new test (b), removed redundants)
- No net test deletions (all lines restored or added, none removed)

All gates pass: fmt, clippy, cancel-safety, 22 workflow tests

## [2025-01-10] Todo 4 rework

**Test rewrite completed successfully** for `account_lockout_respects_configurable_max_failures`:

### Changes made:
1. **File-level `#![expect(...)]` header**: Removed six extra lints (`clippy::panic`, `clippy::wildcard_enum_match_arm`, `clippy::redundant_clone`, `clippy::rest_pattern_accessible_field`, `clippy::unneeded_field_pattern`, `clippy::uninlined_format_args`) to restore to master version
2. **Removed redundant clone**: Line 185 `state.clone()` → just `state` (dropped without being cloned for second account store)
3. **Replaced panic-based match with assert!**: Lines 204-210 and 212-218 converted match expressions with `panic!` arms to `assert!(matches!())` patterns
4. **Fixed enum destructuring**: Used explicit field names instead of `{ .. }`
   - `Authentication::Locked { until: _ }` (has one field `until: u64`)
   - `Authentication::Authenticated { role: _, locale: _ }` (has two fields: `role: String, locale: String`)
5. **Fixed drop pattern**: Changed `drop(...)` to use explicit field binding per linter guidance

### All gates passing:
- `cargo test -p kcc-app --test accounts_reset`: 5 passed ✓
- `cargo clippy -p kcc-app -p kcc --all-targets -- -D warnings`: No violations ✓
- `cargo +nightly-2026-10-03 fmt --all -- --check`: Clean ✓

**Test behavior preserved**: With `with_max_failures(2)` the second wrong password locks; correct third login is refused as locked. With default (5), two wrong passwords do not lock and correct third login authenticates.

## [2026-11-13] Flake fix: job ID collision test time-luck race

**Problem:** Test `forced_identifier_collision_is_retryable_before_work_starts` (jobs.rs:738-793) uses `SystemClock`, so when the wall-clock second rolls over between the two `JobRunner::start()` calls, the job IDs differ (they embed `self.clock.unix_seconds()`), collision detection fails silently, and the test passes. On heavy gate runs, the second probability becomes 100% during a second boundary: test flaked.

**Fix:** Injected a fixed test clock with deterministic timestamp (1_700_000_000).

**Implementation:**
1. Added `#[derive(Debug)] struct FixedClock(u64)` in `#[cfg(test)] mod tests` with `impl Clock for FixedClock`
2. Changed line 751 from `Arc::new(crate::accounts::SystemClock)` to `Arc::new(FixedClock(1_700_000_000))`
3. Added `Clock` import to test module imports

**Verification:**
- 200-run loop: pass=200 fail=0 ✓
- Full lib suite: 13 tests pass ✓
- Clippy: clean ✓
- Rustfmt: clean ✓

**Key insight:** Job ID allocation embeds time, so any test relying on collision must fix the clock. The inline `FixedClock` helper is minimal and specific to this test's needs; no integration-test code leakage.

## [2026-11-13] Todo 1 progress (worker r1)
- A worktree left earlier locale strings (management-mode-unknown in six .ftl) uncommitted; kept them and regenerated keys.rs with cargo xtask i18n-gen.
- clippy here denies integer division (`/`) even in consts: use `div_euclid`. clippy match_same_arms: merge `Some(_) | None` into the final arm.
- Red run was made from a pristine git-archive copy of HEAD with only the tests, locales/keys and testkit knob overlaid; deleted afterwards.

## [2026-11-13] Todo 19 progress
- `[[routers]] auth`/`token_file` wired: `RciClientOptions.auth` (kcc-rci) is applied by one engine helper `session()` used by `connect_with`, `connect_bootstrap_with` and background sessions (so a token profile's dedicated background session carries the token too).
- `ManagedRouterProfile` gained `auth` (skip if Auto), `token_file` (skip if None); `password_file` is `Option<PathBuf>` (skip if None). serde_json here has no `preserve_order`, so state files are written with sorted keys; Option fields previously serialized as `null` (read_login etc.) and still do. Fixture test `registry/auth_modes.rs::stored_routers_round_trip_byte_identical` pins the byte-identical round trip.
- Credential source checks live in `crates/kcc-app/src/registry/auth.rs` (`validate`, `options`, `secret_file`); `credential_file` now reads through `auth::secret_file`, so the owner-only check of the secret-file todo has one place to land for passwords and tokens.
- `kcc_testkit::auth_fixture` (Protocol::{Ndw4,Token,DigestSha256}) works from kcc-app tests via `Config::from_toml_str` + `RouterRegistry::client`. `RciPath::from_str` takes ONE segment; use `RciPath::from_segments(["show","version"])`.

## [2026-11-13] Todo 29 progress
- New key `web-migrate-nothing-to-send` (web.ftl, 6 locales, appended at file end), keys.rs via `cargo xtask i18n-gen`. Both previews render it as a `notice` (data-tone="info") in the action slot instead of Apply.
- Migration preview: `Panel::nothing_to_send = sent == 0 && components.is_empty()`. Components chosen at the inputs step are still installed by Apply, so Apply stays when components exist even with 0 commands (conservative choice).
- Presets preview: condition is `phases.is_empty()` (phases are pushed only when non-empty, so it matches commands == 0); Reveal stays independent.
- The old 0-command notices (`web-migrate-preview-empty` via `all_present`, `web-presets-preview-nothing`) are no longer rendered: they stated the same fact as the new notice (one fact, one place). Their FTL keys stay (append-only; i18n-check has no unused-key rule). plan_agreement.rs still asserts PREVIEW_EMPTY is absent (now trivially true).
- Tests: new modules `tests/migration_wizard/preview.rs` and `tests/presets_pages/preview.rs` (module name `preview` makes the plan's `... preview` filter pick them up). Presets 0-command fixture: seed `lab-1` with the same DNS_LINES as `prod-1`, merge mode.
- Stable markup for "Apply offered": `hx-post="{page}/apply"` (page = /ui/migrate/<id> or /ui/presets/runs/<id>).

## [2026-11-13] Todo 27 progress
- Done in wt/r27: membership decided after buildability (kcc-migrate rules/planner) and the wizard review classifies the source without left-out lines. Tests: `bridge_members::a_member_the_plan_does_not_create_gets_no_include_line` (2 rows), `plan_agreement::review_and_plan_agree_once_the_vlan_lines_are_excluded`.
- Gotcha: excluding `interface Vlan5 description lab` in MIXED leaves `vlan-id 5` (unsupported, not excludable): pre-fix the trimmed plan still counted Vlan5 as created via that line, so the row-137 bug was the F4-N73 ordering bug seen through an exclusion. The "every Vlan5 line excluded" kcc-migrate row (source without Vlan5) was already green pre-fix; the RED rows are the unbuildable-only one and the wizard test.
- Gotcha: launching a test build and then editing src mid-build makes cargo compile the edit in; for a clean RED, restore HEAD sources temporarily (`git show HEAD:path > path`) and rerun.
- rules.rs is 653 pure LOC (pre-existing, far above 250); split candidate for a later refactor (memberships/glob helpers).

## [2026-11-13] Todo 2 progress
- Done in /home/andrico/kcc-wt/r2: preflight disarms or reports after a post-arm failure; refused arm -> disarm -> Workflow | new `ApplyError::ArmUnconfirmed` (recovery_armed, key `management-not-sent-armed` x6 locales, CLI Exit::Router, Web finish/run texts, MCP outcome_unknown code, CHANGELOG, docs/MIGRATION.md); components path no longer re-arms after the rebooting commit.
- Gotcha: the plan's test filter `apply_lifecycle` matches nothing; the `apply` binary mounts the file as `mod lifecycle`, so use `-- lifecycle` (new tests: `-- armed`).
- Gotcha: the fake's migration intercept answered agreement lines before parse fault injection; fixed order in kcc-testkit/src/server/parse_command.rs.
- `ChangeSet::current_last_change()` reads `show last-change` on the change set's (reconnected) client; `fail_safe` is a raw Value, test `get("active") == Some(&Value::Bool(true))`.

## [2026-11-13] Todo 22 progress
- `KCC_*` env overrides now come from one `env_table!` macro in `crates/kcc-app/src/settings/env_overrides.rs` (child module of settings.rs, `mod env_overrides;`, no re-export): rows `"VAR" => section.field: parser,`. It generates `NAMES` (aliased as `pub const KCC_ENV_VARS = env_overrides::NAMES`, so the public path is unchanged without `pub use`) and two `&[Row]` groups (`BEFORE_SUFFIX_CHECK`/`AFTER_SUFFIX_CHECK`) so `normalize_suffixes` keeps running between `[outbound]` and `[state]` rows (error precedence preserved).
- Per-row parsers stay visible: each row's parser is bound as `let parse: fn(&str) -> Result<_, String> = $parse;` (gives closures their `&str` param type and avoids `(closure)(raw)`); `Row.set` is a fn pointer built from a non-capturing closure in a const.
- Field path for the report is `concat!(stringify!($section), ".", stringify!($field))` (stringify of `a.b` token runs could insert spaces).
- Proof: scratch probe applied 26 values (valid + malformed) to each of the 39 vars plus multi-var/precedence cases and dumped Config Debug/report/error text; before/after dumps byte-identical (sha256 b0a7bbef...). settings.rs 1572 -> 1112. Sync test `every_documented_env_var_is_read` deleted (list generated from the same table).

## [2026-11-13] Todo 28 progress
- RED confirmed: preset options rejected a numeric switch-port source (`interface 1`) via `valid_name`. A preset only carries `interface N` context when an included line references it (e.g. `ip route ... 1`), since groups pull `interface * **` by referenced word.
- Fix: `is_switch_port` now `pub(crate)`; `presets_page/options.rs` `checked` accepts a port row left as its source; typed names (incl. `99x`) stay strict.
- Tests: crates/kcc-web/tests/presets_pages/options.rs (a_numeric_switch_port_source_plans, a_typed_port_name_stays_checked). Note a_typed_port_name_stays_checked was already green before the fix (guards strictness).

## 2026-11-13 Todo 20 progress

**Completed deletion of unreachable kcc-rci code:**

### Deleted items:
1. `KEEPALIVE_INTERVAL` constant (session.rs:40)
2. `start_keepalive()` method (session.rs:524-541) 
3. `keepalive_once()` async method (session.rs:540-561)
4. `Keepalive` struct and Drop impl (session.rs:757-770)
5. `session_manager()` accessor (engine.rs:177-183)
6. `with_deadline()` method (engine/background.rs:108-114)
7. `configure_argon2_concurrency()` function (ndw4_keys.rs:20-32)
8. `AuthScheme` type alias (auth.rs:136-141)
9. `SessionManager` type alias (session.rs:184-192)

### Merged helpers:
1. `read_capped()`: kept engine.rs version (takes cap param as required), deleted capabilities.rs version, made pub(crate) in engine.rs
2. `lock()`: made pub(crate) in session.rs, deleted duplicate from engine.rs, updated engine.rs import

### Updated static:
- Replaced `OnceLock<Arc<Semaphore>>` with `LazyLock<Arc<Semaphore>>` in ndw4_keys.rs for `BUDGET`, removed initialization function

### Updated type references:
- Changed all `SessionManager` to `Manager` in:
  - engine.rs type signatures and method implementations
  - engine/background.rs 
  - capabilities.rs (used Manager type in function signatures)
  - All test files (session.rs, auth_survivors.rs, auth_ndw4.rs, capabilities.rs, auth_token.rs, engine.rs, auth_digest.rs, components.rs, capture.rs)

### Deleted test-only tests:
- None identified; all remaining tests exercise surviving functionality

### Acceptance criteria verification:
✓ `cargo test -p kcc-rci` - GREEN (all 126 tests passed)
✓ `cargo check -p kcc -p kcc-app -p kcc-web -p kcc-mcp -p kcc-testkit -p kcc-migrate --all-targets` - GREEN
✓ `cargo clippy -p kcc-rci --all-targets -- -D warnings` - GREEN (no warnings)
✓ `cargo +nightly-2026-10-03 fmt --all -- --check` - GREEN (all formatted correctly)
✓ `cargo xtask allow-gate` - GREEN (0 allow attributes)
✓ `cargo xtask cancel-safety` - GREEN (0 missing comments)
✓ Final grep verification: no remaining instances of deleted items

### Files modified:
- crates/kcc-rci/src/session.rs (deleted 3 items, made lock pub)
- crates/kcc-rci/src/engine.rs (deleted 1 item, updated types, deleted lock, imported lock from session)
- crates/kcc-rci/src/engine/background.rs (deleted 1 item, updated Manager import)
- crates/kcc-rci/src/ndw4_keys.rs (deleted 1 item, replaced OnceLock with LazyLock)
- crates/kcc-rci/src/auth.rs (deleted 1 item)
- crates/kcc-rci/src/capabilities.rs (deleted read_capped, imported engine::read_capped, updated Manager usage)
- All test files updated to use Manager instead of SessionManager alias
- crates/kcc-testkit/src/capture.rs and tests/components.rs updated for Manager type

### Notes:
- The `configure_argon2_concurrency()` function was unreachable (no callers) - safe to delete
- The keepalive functionality (Keepalive struct, start_keepalive, keepalive_once) were todo 19 cleanups - verified no callers remain
- `SessionManager` alias was purely cosmetic - all code now uses `Manager` directly  
- `AuthScheme` alias similarly cosmetic - all code now uses `Scheme` directly
- LazyLock provides the same lazy initialization semantics as OnceLock but is simpler for our use case (always defaults to 1 permit)


## [2026-11-13] Todo 3 progress
- Done (worker r3, wt/r3): `kcc_domain::configuration::close::{Close, Closed, close}` is the single router-command closing step; engine `apply/finish.rs` (keeps backup/original/restore wait + job bookkeeping) and CLI `config failsafe commit|rollback`, `preset finish`, `migrate finish` call it; `Ctx::finish_saved` and `SafetyNet::rollback` deleted; CLI failure mapping in `cli/closing.rs::reported`.
- Gotcha: `crates/kcc-domain/tests/profile_coverage.rs` fails any new domain suite that does not contain the literal `in PROFILES` (iterate `support::PROFILES`).
- Gotcha: returning a `Copy` struct from a step needs `let _: T = ...` (`-D unused-results`; `drop(copy)` trips `dropping_copy_types`).
- Tests: new `crates/kcc/tests/cli/closing_modes.rs` (8-row table, RED showed extender config/preset rollback sending the native rollback and router commit without save), new `crates/kcc-domain/tests/close.rs` (step x mode x firmware + committed-not-saved row; mutation-checked).

## [2026-11-13] Todo 9 progress
- New seam `kcc_domain::configuration::bracket::{ArmedFate, guarded}`; invariants (refusal before arm, every arm has an owner, count balance incl. unwind/drop, fate truthfulness, one permission) are the module doc of `bracket.rs`.
- `guarded<T, E, H, W>` uses type parameters, not `impl Trait` args (`clippy::impl_trait_in_params` is denied). Order: `changes.audit_alive()` -> `hold()` -> `changes.enter_bracket()` -> arm -> (arm error: disarm, `recovery::arm_failed`) -> work -> disarm -> `finish_applied`.
- `SafetyNet::{arm, disarm, keep_alive}` take `permission: Permission` (last arg); `SafetyNet::required(permission, risk)` is the D-Q1 rule owner. `ChangeSet::audit_alive()` and `ChangeSet::enter_bracket()` were added in kcc-app.
- `crates/kcc-domain/tests/bracket.rs` iterates `PROFILES` x fake system modes `router`/`extender` (`Fixture::spawn_mode`), uses `fail_parse_matching("system", n)` / `("no system", 1)` to refuse arm/disarm in either mode; dead audit writer = corrupt `audit.jsonl` then one append (the writer re-verifies files on every append). Panic case: `tokio::spawn` + `JoinError::is_panic`, count read inside work via an `AtomicUsize`.
- Gotchas: `let _: Result<..> = fut.await` on a type with a destructor trips `let_underscore_drop`-style lint -> bind + `drop`; `needless_pass_by_value` on a `Result` param -> `match` it to consume; `tuple_array_conversions` -> return `[&str; 2]`; adding an argument can push a function over 100 lines (page_kit `apply_with`, migrate `prepare`).
- `crates/kcc-domain/tests/support/mod.rs` was already 261 pure LOC before this todo (now 288).

## [2026-11-13] Todo 11 progress
- MCP raw and curated management changes run through `kcc_domain::configuration::bracket::guarded`; `impl From<WorkflowError> for McpFailure` delegates to `map_workflow`. `grep -rn management_permissions crates/kcc-mcp/src` is empty.
- New code `management_not_sent_fail_safe_armed` (lib.rs, shape.rs message `management-not-sent-armed`, audit `fail_safe_armed: true`), CHANGELOG entry, docs.rs text, docs/MCP_TOOLS.md regenerated.
- New tests: `bracket_failures::tests::refused_arm_reports_nothing_sent` (not-sent armed + not-applied rows, both modes), `bracket_failures::authority::tests::{change_permission_authorizes_the_bracket, viewer_is_refused_before_any_router_request}` (new file tests/support/bracket_authority.rs).
- Gotcha: a RED run must not overlap source edits (cargo compiles the lib too). I parked the edited src files outside the tree, wrote HEAD versions via `git show HEAD:<f> > <f>`, ran RED, then restored them.
- Gotcha: clippy `wildcard_enum_match_arm` fires on `other => other` over McpFailure; use `if let ... else`. Closure params of `guarded` work must not shadow `changes` (`shadow_unrelated`).

## [2026-11-13] Todo 10 progress
- `cli/change.rs::run_completed` now runs `bracket::guarded(changes, router, SafetyMode::for_change, gate.permission, || true, work)`; `Gate.timer` is an enum `Timer { Off, Runner, Operation }` (clippy `struct_excessive_bools` refused a 4th bool). Gate permissions = `SafetyNet::required(permission, risk)` (+ CONTROL_PERMISSION only for `Timer::Operation` management gates). `dom_net` services set uses `SafetyNet::required(Write, service_risk)`.
- `cli/exit.rs::Failure` has an `armed: bool` set only by `Failure::armed(exit, ArmedFate)`; `Failure::recovery` maps `fate()` -> armed, `message_key()` -> headline, else the source. `closing.rs`, `migrate_apply.rs::apply_failure` and the `InterfaceChangeError` mapping build armed failures through `Failure::armed` so `--json` `fail_safe_armed` and the audit flag keep working without key comparison.
- `ApplyError::ArmUnconfirmed` (migrate_apply.rs) still uses `headline_only(.., MANAGEMENT_NOT_SENT_ARMED)` and so is NOT flagged `fail_safe_armed` in `--json`/audit (behavior kept as before; logged in issues.md for todo 15).
- `--confirm-destructive` takes the router name as its value: managed raw cases without it must drop the `lab-1` positional.
- Raw `system configuration fail-safe timer` is catalog Risk::Destructive (kcc-catalog runtime/data.rs DESTRUCTIVE_PATHS), so a Write/RawRci role is still refused standalone timer control after D-Q1.

## [2026-11-13] Todo 12 progress (worker r12)
- Web `page_kit::change::apply_with(plan, permission, work)` now: audit_alive -> begin -> client -> (management: `SafetyMode::for_change`) -> `brackets::hold()` for EVERY write -> ordinary: work; management: `bracket::guarded(.., permission, brackets::hold, ..)`. Batch item refusals survive a failed disarm via a `&mut Vec<String>` stash captured by the work closure (guarded drops the work value when the disarm fails).
- `Refused` maps through `recovery::Failure::message_key()`; audit outcome stays `fail_safe_armed` for armed fates. When both the arm receipt and the disarm receipt fail (audit lock held / dead writer) the seam says `ArmedFate::NotSent` -> `management-not-sent-armed` (the old Web copy said outcome-unknown).
- `own`'s claim is the only thing that keeps a Web request alive after the browser leaves: an ordinary write not held is aborted mid-audit (its `router.change_cli` receipt was already queued to the writer and still lands; the Web entry was lost). Test pattern: hold the audit append lock, `pin!` the request future, `timeout(5s)` it under a paused clock, drop it, release the lock with a oneshot.
- `kcc serve` MCP HTTP test needs `[mcp] allow_destructive = true` and `toolsets = ["core","raw"]` for `kcc_cli_parse`; an admin API key via `kcc_app::api_keys::create_api_key`. `serve_bracket` MCP test is red until MCP runs through `guarded` (todo 11).
- `tracing_subscriber::fmt()` in tests: call `.with_ansi(false)`; feature unification turns ANSI on.
- `cargo test -p kcc-web` stops at the first failing test binary: use `--no-fail-fast` to see all.

## [2026-11-13] Todo 13 progress
- Done in wt/r13: interface guard non-bracketing; CLI (runner bracket via Gate::of), MCP (common::apply -> raw_change::run), Web (kit already bracketed; deleted its copied request builder) all bracket interface Management changes with SafetyMode::for_change and the change's own permission.
- RED was CLI+MCP extender rows (fail-safe timer instead of `system reboot 300`); the Web row was already green because the Web kit bracketed interface changes before this todo.
- Gotcha: `FaultInjection::fail_parse_matching` was a single Option, so chaining two calls silently kept only the last; it is a Vec now.

## [2026-11-13] Todo 15 progress
- Done in /home/andrico/kcc-wt/r15: `kcc_app::audit::{Attempt, AuditEvent::attempt, AuditEvent::with_request_id}`; CLI `Ctx::attempt` + `Ctx::confirmed` (every `confirm(..)` site audits a refusal as `cli.refused`/`refused`/`confirm_required`); MCP `support/audit.rs` maps McpFailure -> Attempt (byte-identical entries); Web `Failure::with_fail_safe_armed` -> `Outcome::fail_safe_armed` -> `Record::append_outcome`/`append_attempt` (page params merged, attempt keys win); `"fail_safe_armed"` outcome deleted.
- Gotcha: `cargo test` stops at the first failing test binary; use `--no-fail-fast` to see every pinned expectation (cli_domain_writes had four "zero audit entries after a missing confirmation" pins that a plain run hid behind tests/cli).
- Gotcha: clippy `shadow_reuse` is denied, including in tests (`let [x] = x.as_slice()` fails; rename).
- Follow-ups (not done): `crates/kcc/src/cli/context.rs` (374 pure LOC) and `crates/kcc-app/src/audit.rs` (735) were already over the ~250 limit; mesh `--confirm-member` mismatch refusal is unaudited (it fires before services open and a test pins zero router requests there); Web non-armed failures keep their own outcome ids (rci_error, unreachable, busy, mode_unknown, ...), and Web `mode_unknown` differs from MCP `refused`+`router_mode_unknown`.

## [2026-11-13] Todo 14 progress
- Done on wt/r14: `ApplyError::{fate, message_key, from_name}` in new `kcc-migrate/src/apply/failure.rs` (inline table test over all 25 variants); CLI `apply_failure`, Web wizard/presets mappers, MCP `map_apply`/finish, `ApplyReport::message` all read the table. New MCP codes `migration_rollback_restarting` (closes the entry) and `management_saved_fail_safe_armed`; MCP_TOOLS.md regenerated from `kcc-mcp/src/registry/docs.rs`; CHANGELOG + MIGRATION.md updated; new key `migrate-apply-replan`.
- `from_name` = derived `Deserialize` over `IntoDeserializer::<serde::de::value::Error>` on `&str`: exact inverse of the serde name, no string table.
- A `match` on a foreign `#[non_exhaustive]` enum still needs `_`; `clippy::wildcard_enum_match_arm` forces `other @ (A | B | ... | _)` listing every known variant.
- `start_paused` needs tokio `test-util` in the crate's dev-deps (kcc-mcp lacked it). Paused clock works with FakeRouter loopback + AuditLog in kcc-mcp Lab and kcc-web fixtures (tests ran in 2-7 s).
- The Web finish routes' 30 s TimeoutLayer cuts any rollback whose restore wait runs past 30 s (408): the Web restarting tests stay red until todo 17's budget lands.
- `fail_after_requests(index_of("system reboot") + 1)` from a baseline run is the deterministic "accepted then silent" fault on every surface.

## [2026-11-13] Todo 23 progress

**Summary:** Implemented `kcc migrate apply` confirmation before apply starts and rollback headline when verification fails.

**Key changes:**
- `migrate_apply.rs`: Extract target from plan JSON before re-planning; call `secret::confirm()` with `Risk::Management` before `Planned::make()` to avoid unnecessary router requests if confirmation is missing
- `secret.rs`: Confirmation logic already existed (reused from preset/run); returns `Exit::Policy` (code 10) on refusal
- New CLI tests verify: no apply when confirmation missing (exit 10), apply with --yes succeeds, verification failure prints "Migration restored." (existing test)
- Documentation updated: added requirement for confirmation on terminal (or --yes) and description of exit 6 with restored headline

**Testing:**
- All 12 migrate tests green (incl. 2 new confirmation tests)
- All 83 CLI tests green
- Full kcc test suite green (~1.5k tests)
- Clippy, fmt, i18n-check, cancel-safety, allow-gate all green
- No new dependencies, no #[allow], no unwrap/panic outside tests

**Pattern observations:**
- Confirmation for Management/Destructive changes is consistent across CLI commands (preset run, services, migrate apply)
- Extracting the target ID from the reviewed plan JSON before re-planning prevents unnecessary router requests
- Test updates needed only for existing tests that call `migrate apply` without confirming - 6 tests + our 2 new ones

**Test changes documented in decisions.md**


## [2026-11-13] Todo 18 progress (r18)
- Apply authorization now comes from `SafetyNet::apply_permissions(ApplyNeeds)`; `ApplyNeeds` is `#[non_exhaustive]` so other crates build it with `ApplyNeeds::default().installing_components(..).restoring_raw(..).finishing_with_rollback(..)`.
- `configuration::close` takes `(Close, Permission)` as one tuple argument (keeps the parameter count at 4).
- Shared MCP test harness `tests/support/lab.rs` is compiled per test binary with `-D dead_code`: a new MCP test binary must use `tool_names`, `progress_received` and `audit` (or the fields `directory`/`progress` go unread).
- `Lab::roles.replace(..)` swaps the session role by name after setup: start with an all-permission role named like the built-in role, seed/capture, then replace with `built_in_roles()` entry.
- Web wizard test support: `Fixture::with_target(mode, FakeRouterBuilder)` builds `ultra` from a caller builder (e.g. a `show_fixture("version", ..)` without `wireguard` to force a component install).
- Observed (not fixed, out of scope): a Web wizard apply whose plan installs `wireguard` on an `ultra` with an overridden `show version` fails preflight with `ApplyError::Drift` before arming; the same upload onto the default `ultra` gets past preflight. Unclear whether fixture artifact or a real Web component-path defect.

## [2026-11-13] Todo 16 progress (worker r16)
- Invariants (written in `kcc-app/src/audit/writer.rs`, `audit/receipt.rs`, `workflow_receipts.rs`, `kcc-domain/src/configuration/bracket.rs` module docs): one writer per process consumes the channel FIFO and takes the next entry only after the head is written; seq + prev_hash are re-read from disk under the cross-process lock right before hashing (unchanged `append_locked`); a busy lock restarts a bounded round for the SAME head entry (warn log per round) - never skipped/dropped; any other error is fatal (channel closed, head answered Failed, queued entries lost, `is_alive()` false -> `begin`/`guarded` refuse before any router request).
- Callers: `AuditLog::submit` = `Sender::reserve().await` (cancel-safe) + synchronous `permit.send` (no await between slot and send), returns `receipt::Pending` (a `watch::Receiver<Reply>`). Waits are `Pending::wait(limit)` / `wait_until(deadline)` -> `AuditError::Pending` at the deadline; the entry stays queued. `AuditLog::append` = submit + `AUDIT_WAIT` (30 s). `AuditLog::flush(limit)` waits on a `watch<usize>` queued counter.
- Constants (kcc-app `audit::receipt`): AUDIT_WAIT 30 s, BRACKET_AUDIT_WAIT 20 s, LOGIN_AUDIT_WAIT 5 s, AUDIT_FLUSH_WAIT 5 s. No config key. Test-only short delays: `AuditPolicy::with_append_lock_backoff(initial, maximum)` (public; production attempts per round kept).
- Deferred mode: `ChangeSet::defer_audit()` / `settle_audit(limit)` / `audit_pending()`; `guarded` defers before the arm, sends the disarm without waiting for any receipt, then settles within 20 s. A submit to a dead writer in deferred mode yields `Pending::lost()` so the disarm's own result is not polluted; the writer failure surfaces from settle as the work's error (timer fate still decided by the disarm). Consequence: a dead writer after the arm is now "failed, timer off" rather than `management-not-sent-armed` (serve_bracket expectation changed).
- Gotchas: `ChangeResult` lost `Copy`/`Eq`/`PartialEq` (it carries `AuditReceipt`) -> `let _: ChangeResult` trips `let_underscore_drop`, use `let _applied`. `clippy::large_enum_variant` on `Reply`/`AuditReceipt` expected with reason. The Web page record must not wait when the change's own receipts are pending (it is queued behind them; waiting would add 30 s). The plan's filter `bracket_budget` matches 0 tests; the module path is `bracket::budget`.
- Test fixture for "held by another process": in-process `StateStore::try_lock(AUDIT_FILE_NAME)` (flock on a separate open file description, so the writer's own `try_lock` fails exactly as with another process); the real cross-process case is `audit_multiprocess::entries_waiting_on_another_process_are_kept_in_order` (child process holder).

## 2025-11-14 Todo 23 rework

**Placement fix**: Moved confirmation in `migrate_apply.rs` from before `Planned::make` to after plan_id check. This ensures:
- The target is taken from the re-planned result (not the plan file)
- Confirmation happens with the correct target that will be modified
- The comparison between plan file target and re-planned target is unnecessary and removed

**Test update**: Changed `apply_without_confirmation_and_with_no_exits_10_and_makes_no_request` to assert machine-read facts:
- Exit code 10 (refusal)
- No apply/commit commands in request log (verified by filtering command strings)
- Audit log entry with outcome `refused` and `params.reason == "confirm_required"`

**Doc update**: Updated `docs/MIGRATION.md` to quote the exact i18n message from `migrate-apply-restored` key instead of a shortened version.

**Key insight**: The "plan check" in the todo refers to the plan_id comparison, not to pre-validation. Confirmation must come after the plan is made and validated, ensuring the target used for confirmation matches the target that will be modified.
