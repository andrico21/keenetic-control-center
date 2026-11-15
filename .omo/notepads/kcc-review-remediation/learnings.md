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

## [2026-11-14] Todo 24 progress
- Done: `cli-done` key in 6 locales (+ i18n-gen), `ChangeSet::unsaved()`, `Gate::headline`, `run_headlined`, rci `saved_note`. Tests: cli/unsaved.rs `headline_says_unsaved_only_when_the_router_has_unsaved_configuration`, cli_presets/copy.rs `copy_finishing_with_save_never_says_unsaved`.
- Gotcha: the fake router's raw `rci post` does not change its last-change `unsaved`; curated CLI writes do.
- Gotcha: `rci::send` sits at the 100-line clippy limit; keep helpers outside it.

## [2026-11-14] Todo 26 progress
- Done: CLI `migrate apply`, `preset apply` and `copy` take the target lease (`ChangeWorkflow::reserve`) before
  `JobRunner` creates a record; busy -> exit 5, `cli.refused`/`refused`/`router_busy`, no job record. Test
  `crates/kcc/tests/cli/busy.rs::busy_router_refuses_every_apply_before_a_job_exists` (one table, three commands).
- Gotcha: a CLI test holds a cross-process lease simply with `StateStore::open(state_dir)?.try_lease("<router>")`
  in the test process (flock is per open file, the `kcc` child sees `StateLocked`).
- Gotcha: editing sources while a detached RED build compiles makes the RED run build the edited tree; take RED
  from pristine files (restored with `git show HEAD:<path> > <path>`, then put the edits back).
- `preflight::prepare` sits at ~97/100 lines; any further growth needs a split.

## [2026-11-14] Todo 54 progress
- Secret file rule landed: `kcc_app::secrets::files::{open_secret_file, read_secret_file, read_secret_file_async}`
  (module is `files`, not `file`: clippy `module_name_repetitions` fires on `open_secret_file` inside a `file` module).
- The host umask is 0022, so every `fs::write` fixture that kcc later reads as a secret is 0644 and now fails; use
  `kcc_testkit::write_secret_file(dir, name, &str)` (takes `&str`: `impl AsRef<[u8]>` trips `impl_trait_in_params`).
- Replacing `std::fs::write` in tests can leave `#![expect(clippy::absolute_paths)]` unfulfilled (poller.rs,
  metrics.rs): drop the expectation in the same change.
- `match` arms that bind `path` inside a fn whose parameter is `path` trip `shadow_unrelated`; rename one side.
- Do not `pgrep -f`/`pkill -f` with a pattern that appears in your own command line: it kills the tool shell.

## [2025-11-14] Todo 25 progress

**Implemented router-aware missing-permission messaging for CLI apply refusals:**

### Changes made:
1. Added `cli-router-out-of-scope` i18n key with translations in all 6 locales (en, ru, uk, de, be, kk)
2. Updated `authorize_apply` in `context.rs:215-261` to detect when a role holds all permissions but the router is out of scope
3. When detected, shows "Your role does not cover router { $router }." instead of empty permission list
4. Exit code stays 10 (unchanged)

### Test coverage:
- New test `scoped_role_with_all_apply_permissions_shows_router_out_of_scope` verifies the case
- All 90 CLI tests pass, all 14 i18n tests pass
- No changes to other CLI apply/refusal paths (only one location in the codebase uses this pattern)

### Key design decision:
Separated permission check from scope check in authorization logic:
- First check if all required permissions are granted (no scope)
- Then check if router is in scope
- Only show router-out-of-scope message if both conditions are met: permissions OK, but router not in scope

This ensures we don't show an empty permission list when the real issue is the router scope.

## [2026-11-14] Todo 21 progress (worker r21)
- Done: one `ChangeRequest` (ChangeMethod Post/Delete), one `CliChangeRequest` (terminal flag), `apply` handles both methods, `apply_cli` handles terminal requests, `BatchItem::new(value)` only, `apply_batch` validates each item once and keeps the results for completion and audit target, read-back `verify` moved to workflow_verify.rs (now `Readback` + single exhaustive match; the dead `ConfigCommand|ConfigCommandAbsent|ConfigSecret => false` arm is gone because the configuration dispatch is that match's own arm). workflow.rs 1690 -> 1509 lines; workflow_verify.rs 228 pure LOC (warning band: split configuration matching out if it grows).
- New test `batch_outcomes::tests::batch_items_are_validated_from_their_values` (kcc-app --test workflow); RED was the compile failure of `BatchItem::new(value)` against the two-argument shape.
- Gotcha: removing `BatchItem.validated` ripples into every caller that computed gates/previews from it (kcc CLI rci.rs, kcc-web advanced/{deliver,rci,rci_check,execute}.rs, page_kit/change.rs, action.rs); `clippy::shadow_*` and `match_same_arms` fire on the mechanical rewrites.

## [2026-11-14] Todo 52 progress
- Done in worktree r52: per-kind sealed router credentials (`CredentialKind`), registry reads per kind, `transition` seals State-profile reconnect passwords and drops the cached client for token profiles, CLI `router add/edit` take every credential as input only (`--auth`, `--token-file`, `--read-login`, `--read-password-file`, `--new-token`, `--new-read-password`, `--clear-read-login`), endpoint rule shared through `ManagedRouterProfile::moves_endpoint`, audit `credentials` kinds, external-file warning (CLI note + serve tracing warn), 9 i18n keys x 6 locales, docs + CHANGELOG.
- Gotchas: the kcc CLI has no tracing subscriber, so a CLI "log" line must be `Out::note` (i18n) on stderr; `field_scoped_visibility_modifiers` forbids `pub(super)` fields (use accessors / `into_parts`); `kcc_i18n::keys::MessageKey` is private, import `kcc_i18n::bundle::MessageKey`; `auth_fixture` token counts: `router test` detection GETs `/auth` once even with a token, so assert no ndw2/ndw4 login instead of `auth_get == 0`; FakeRouter's request log has no login name, so "poller logs in as reader" is proven by a fake whose admin password differs from the sealed primary (only the reader login can succeed).
- Audit params: `reject_secret_parameters` refuses keys containing password/token/secret, so the audit key is `credentials` with kind names as values.

## [2026-11-14] Todo 53 progress
- Web router form now has a sign-in mode select (`auth`), a `token` field (`data-show="token"`) and a read-only polling group (`read_login`, `read_password`, `clear_read` on edit when a reader is stored). Code: `crates/kcc-web/src/router_form.rs` (form, draft, errors, parse) with children `router_form/{address,page,plan}.rs`; `routers.rs` handlers call `Plan::new(stored, fields, typed)` -> `point` -> `seal` -> registry -> `remove`; audit via `router_access::ProfileAction::{Create,Update}{profile, credentials}`.
- CSS `data-show` works with a select through `.form:has(select[name="auth"] option[value="X"]:checked) [data-show]:not([data-show~="X"])` (app.css next to the `kind` radio rules). `cargo xtask assets-check` does not pin first-party `app.css`; it stays green after edits.
- Child modules see the parent's private fields, which keeps `field_scoped_visibility_modifiers` happy when a template struct moves to a child file (`router_form/page.rs` reads `Draft`/`FieldErrors` fields directly).
- Integration-test child modules of an inline `mod tests` in a test crate root resolve under `tests/tests/`; declare them at the crate root with `#[path = "dashboard/x.rs"]` and reach the fixture through `crate::tests::...` with `pub(super)` items (no `pub(super)` fields: add accessor methods).
- No browser on this host (no chromium, `npx` missing for @playwright/mcp, podman off-limits for workers): visual QA fell back to curl captures of the rendered forms (`.omo/evidence/task-53-router-form-markup.log`).

## [2026-11-14] Todo 45 progress
- Golden net: `.omo/evidence/golden/` (333 .html + .status, MANIFEST.txt, SKIPPED.txt, capture.sh, README.txt), from clean master 578b17c.
- Invocation from each consolidation todo's own worktree:
  `CARGO_TARGET_DIR=/home/andrico/kcc-target-<id> bash /home/andrico/keenetic-control-center/.omo/evidence/golden/capture.sh /home/andrico/keenetic-control-center/.omo/evidence/golden-after-<N> <worktree>`
  then `diff -r -x capture.sh -x README.txt .omo/evidence/golden .omo/evidence/golden-after-<N>` (empty except intended changes). ~15 s + build.
- Route set comes from a multi-line-aware parse of crates/kcc-web/src (286 method+route pairs; the one-line grep in the plan sees only 127 lines): 224 covered, 62 skipped with reasons (SSE streams, later migrate/preset-run steps needing a second router-mode target, uploads, raw restore, job cancel, mesh, storage/components actions, secret-field POSTs, API key revoke, second-WAN actions). A new route shows up as UNCOVERED in MANIFEST/SKIPPED, so it surfaces in the diff.
- Normalizer token classes: CSRF tokens, generated password, per-run ports, scratch path, wizard ids (<ID_MIG>/<ID_DRAFT>/<ID_PRESET>/<ID_RUN>/<WIZARD-ID>), job id middle part, CSP nonces, audit hashes, `cli:<OS-USER>`, unix seconds / ISO / displayed date-times within 2 days of the run (fake router's fixed 2026-01-01 clock is kept), "N s ago" ages (they use U+00A0, not a space), kcc server uptime on /ui/admin/server only.
- Gotchas: POST needs x-csrf-token + Origin; first login lands on forced password change; migrate/preset source steps are multipart; the fake KN-1811 startup-config has 0 settings per preset group, so the preset capture runs after config/save of the UI changes; Pool2 from the DHCP POST collides with segment id 2 (use 3); router delete has no confirm field (kept last).

## [2026-11-14] Todo 41 progress (worker r41)

**Completed:** Macro-based Localize impl generation and Toast consolidation.

### Macro implementation:
- Added `#[macro_export] macro_rules! localized!` to `crates/kcc-web/src/lib.rs` (lines 35–51)
- Generates `impl Localize for Type { #[inline] fn shell(&self) -> &Shell { &self.shell } }`
- Supports variadic syntax: `localized!(Type1, Type2, ...);`

### Trivial impl conversion:
- Python conversion script identified 164 trivial impls across 123 files (all `fn shell(&self) -> &Shell { &self.shell }`)
- Replaced all 164 with `localized!(Type);` macro calls
- No manual rewrites needed; macro expansion is identical to original code

### Toast consolidation:
- Created `ToastView` template wrapper in `page_kit/outcome.rs` (lines 107–127)
- Added `Toast::info(locale, key)` constructor for "info" tone variant
- Removed local Toast structs from:
  - `advanced/jobs.rs`: Removed 11-line struct + impl, updated cancel endpoint to use `Toast::{success,info}` + `ToastView::new()`
  - `system_pages/jobs.rs`: Removed 11-line struct + impl, updated cancel endpoint to use `Toast::{success,info}` + `ToastView::new()`
- Imports simplified: removed `Localize` where only macro-generated impls use it, replaced with `Localize as _` in 117 files

### Verification:
- ✅ Tests: 92/92 passing (kcc-web lib suite)
- ✅ Clippy: Clean (no warnings or errors)
- ✅ Format: `cargo +nightly-2026-10-03 fmt --check` passes
- ✅ Golden diff: Empty (333 HTML pages captured, zero rendering changes)
- ✅ Impl count: 3 occurrences (trait def, test Page, macro doc example) ≤ 5 ✓
- ✅ Trivial impls: 1 (macro example doc) + 1 (test Page non-trivial)
- ✅ Macro calls: 164 localized!() calls across codebase

### Key insights:
- Variadic macros with `$($ty:ty),+` work well for bulk codegen when all impls are identical
- Toast consolidation eliminates duplication: two files had identical template logic, now shared through `ToastView`
- Clippy's `unused_trait_names` warning forced explicit `as _` imports, making intent clear (import for trait bounds only, not direct use)
- Golden snapshot harness proved HTML rendering unchanged despite macro expansion (333 pages, all identical byte-for-byte)

### Files modified:
- `crates/kcc-web/src/lib.rs`: +15 lines (macro definition + doc)
- `crates/kcc-web/src/page_kit/outcome.rs`: +25 lines (Toast::info, ToastView struct + impl)
- `crates/kcc-web/src/advanced/jobs.rs`: -12 lines (local Toast removed), +3 lines (Toast usage updated)
- `crates/kcc-web/src/system_pages/jobs.rs`: -12 lines (local Toast removed), +3 lines (Toast usage updated)
- 123 files: 164 trivial `impl Localize` → `localized!(Type);` replacements
- 117 files: Imports updated to use `Localize as _` where only template trait bounds use it

## [2026-11-14] Todo 30 progress
- New kit module `page_kit/request.rs`: `Params` (new/of/get/text/object/confirmation), `last(pairs, name)` (the one last-value scan, untrimmed), `with_query`, `shown_url` (only HX-Current-URL reader), `shown_uri`, `shown_query`, `rendered`, `missing`. Pages import from `crate::page_kit::request`.
- Kept on purpose: `table::pager::shown_page` (first `page` wins), `firewall_page::views::spot_of` (path match), system_pages `value`/`values`/`merged`, `secret_pages::dialog::plain_value`, `advanced::request::path_of` (trimming wrappers over `last`), `errors::refusal::missing`, `config_page::diff::missing`. dns_vpn flow builders renamed `with_table_query`.
- Gotcha: a use-tree rewriter (flatten `use` statements, remap absolute paths, let rustfmt `imports_granularity=Crate` re-merge) made the ~100-file import move mechanical and re-runnable; qualified calls (`super::shared::x(`, `flow::shown_query(`) and items used inside their old home module need hand fixes after `cargo check`.
- Golden net (333 pages) diff empty; clippy `absolute_paths` rejects `crate::a::b::f(` calls in bodies, import instead.

## [2026-11-14] Todo 31 progress
- API: `page_kit::respond::changed(outcome, refreshed: Option<String>, extra: Option<String>, locale) -> Response`
  renders `respond::Changed` (`partials/kit_result.html`): `kit::result(outcome)`, then `"\n" + extra`, then
  `"\n" + refreshed`, status = outcome's, shared dialog closed. `Changed::new(..).with_report(html)` shows a page's
  own report in place of the outcome's notice (signals = toasts + badge still rendered). `Changed::status()`.
  `Outcome::with_unsaved(bool)` added (the guard's restore can leave unsaved changes on a failed outcome).
- net/system/system_general/config/secret pages call `changed(.., None, ..)` directly (the per-family `answer`
  fns of net_change, system_pages::shared and system_general are gone). Regions that used to be rendered inside
  the parent via Display (system_general `Facts`, dns_vpn `Region`) are pre-rendered with `request::rendered`.
- Per-family differences kept outside the shared template (all byte-identical, golden proves it):
  - lan: `clients_pages::answer` renders `note` with an inline template `Note` into `extra`.
  - routing: these pages always sent a blank line before the outcome (`{%- else %}\n{{ kit::result }}`), so
    `routing_page::reply::Answered` (inline source "\n{{ changed|safe }}") wraps `Changed`; the guard banner moved
    to `partials/routing_guard.html` and goes in as `with_report`, its unsaved badge via `outcome.with_unsaved`.
  - dns_vpn: `screen::Answered` stays a builder (same call sites); notes -> `partials/dns_vpn_notes.html` (extra),
    region + page actions -> `partials/dns_vpn_refreshed.html` (refreshed string).
- askama 0.16 pops ONE trailing newline from template files (askama_derive input.rs), so a fragment file ending in
  `</section>\n` renders without it; `{{ x|safe }}` of a Template uses its Display (= render()).
- Byte diffs are easy to miss by reading templates: `-%}`/`{%-` decide leading newlines; check the golden
  (`head -c 600 <capture> | cat -A`) before choosing a template shape.

## [2026-11-14] Todo 32 progress
- New kit module `crates/kcc-web/src/page_kit/submit.rs`: `Submission::new(action, &params, form)` [`.confirming(risk, resubmit)` | `.confirming_planned(resubmit)`] [`.landing_in("#page-outcome")`] `.submit(check, plan, refresh) -> Response`.
  - `check: FnOnce(&Params) -> Result<T, Invalid>`; `Invalid::at(field, MessageKey)` or `Invalid::from(Vec<(field, key)>)` (create dialog reports several fields at once). Failure: audited `validation_failed`, answered by `Form::answer_invalid`.
  - `plan: AsyncFnOnce(T, &RouterCtx) -> Result<Planned, DomainError>`; `Planned::of(&[ChangeOp], Change)` is the only constructor, risk = max of the ops' risk, so no page passes a literal run risk. Failure: audited `plan_failure(..).audit()`, answered by `Form::answer_refused` (default: outcome region via `respond::changed`).
  - `refresh: AsyncFnOnce(&RouterCtx) -> Option<String>`, called only after success (network pages: `net_change::refreshed(call, domain)`).
  - Why a builder struct instead of a free fn: the network pages confirm at two different points (Bridge0 down / security level ask before anything is read, at Management; the IPoE address asks after planning, at the planned risk), the delete dialog retargets only the change's answer, and one-field dialogs show a plan refusal in the field. Trait `Form` (`answer_invalid`, `answer_refused`; names avoid clippy `same_name_method` against `FormDialog::invalid`) covers the placement; `Formless` = 404 on invalid.
  - `net_form::FormDialog` implements `Form`; `FormDialog::refusing_at("value")` -> `FieldDialog` shows plan refusals under the field.
- `Action::run_planned(Planned)` (pub(super)) runs at the planned risk; `Action::run(risk, ..)` still public for 16 call sites in 14 files (system_pages, secret_pages, dns_vpn, system_general): todos 33-34 migrate them and then delete `run`. `run_with(risk, ..)` (mesh restart, firewall, routing, clients, NAT, config safety, reset) also still takes a literal risk: not covered by this todo.
- The network family already audited plan failures via `plan_failure` in `net_change::finish`; its 7 `abandon("validation_failed")` were genuine input-check failures, now inside `submit`. No network domain plan returns `DomainError::PermissionDenied`, so the forbidden-plan test is the kit unit test `page_kit::submit::submit_tests::a_plan_the_domain_refuses_is_audited_with_its_reason` (wan MTU write). A planned change that RUNS cannot be unit-tested without `brackets::own` (task-local request owner): "This change has to come from a page request"; the success path stays with the page suites.
- wifi toggle's own pre-check `allowed(Write, plan.risk)` (403 page) dropped: identical condition to `Action::plan` (wifi up/hide descriptor permission is Write); only the unreachable refusal's rendering differs. Golden diff empty.
- Gotcha: a python splice `s[:a] + new` without `+ s[b:]` truncated net_internet_order.rs (lost `reorder` + tests); restored from `git show HEAD:<path>` (read-only).

## [2026-11-14] Todo 34 progress
- Moved onto `page_kit::submit::Submission`: DNS form submit + interception (`dns_vpn/dns_pages.rs`), VPN dialog submit (`vpn_pages.rs`), VPN switch/service/delete (`vpn_actions.rs`), KeenDNS book/drop/access/proxy (`keendns_forms.rs`, `keendns_access.rs`; the local `run` helper and `reply` are gone), schedule create/action, components check/queue, service toggle, storage eject/check/format (the local `run` now wraps a Submission), router-user create and tags (`user_forms.rs`), system general one-field edit (`system_general.rs`). `dns_vpn::flow::apply` deleted; `vpn_checks::PlannedRequest` (+ its `allowed`) deleted, `Planned::request` returns `(ChangeOp, CliChangeRequest)`.
- Form impls: `dns_vpn::form::FormDialog` (in flow.rs), `page_kit::dialog::FieldDialog` (system general), `NameDialog`, `ScheduleDialog`, `ActionDialog`, `user_answers::UserForm`, `flow::Answers` (DNS, choices read), `flow::InRegion` (interception: invalid in outcome region), `system_pages::shared::NoDialog` (404 on invalid, refused plan as `Outcome::invalid` in the outcome region, the old local behavior).
- Pattern for checks that need the router BEFORE the plan (VPN name taken, connection known, account taken, schedule known): compute the pure check first, read only when it passed, fold the result into the value the `check` closure returns (so `validation_failed` stays inside the kit); a read error is carried into the `plan` closure as its `Err` (audited with its own reason). Not-found/forbidden/unchanged/confirmation_required pre-checks stay page-level `abandon(..)` before the Submission (same order as before).
- A refusal whose words come from the DomainError (users' `refusal_message`, DNS dialog with lists read through the plan's ctx) cannot be built from `Failure` alone: the plan closure keeps them in a local `OnceLock<String>` / `Mutex<Option<..>>` that the Form reads in `answer_refused`. Kit follow-up: give `Form::answer_refused` the `&DomainError` (or let the plan return the refusal answer) and these slots go away.
- The VPN `request_plan.allowed` 403 pre-check was dropped (same as todo 32's wifi toggle): `Action::plan` checks the identical SafetyNet (descriptor permission, max(planned risk, descriptor risk)); only a custom role with Write but not the planned risk's permission sees the kit's forbidden outcome instead of the 403 page. service_toggle keeps its 403 pre-check (its risk is known before planning).
- LEFT (need a kit change, recorded in issues.md): secret pages (wifi_psk, wan_password, user_password + vpn_server password via `user_password::run`) rewrite the success headline with `reply::verified`; vpn_import rewrites it with `confirmed` and adds notes; user_delete retargets only the run's answer to #page-outcome while its refusal stays in the dialog (`landing_in` lands both). run_with sites (vpn_credential, vpn_server psk, system_general reboot, reset) wait for todo 33's work-carrying Planned. diagnostics.rs is a job start, not a change.
- New test `system_pages::user_changes::a_tag_change_the_domain_refuses_is_audited_with_its_reason`: removing `cli` from a router account named `admin` (domain ProtectedAccount) was audited `validation_failed`, now `failed`; dialog text unchanged. Gotcha: the fake's `show rc user` lists no account, so the test first creates `admin` through the page.
- Golden: new baseline dir `.omo/evidence/golden34/` = golden/ (333, byte-identical) + 24 snapshots of the secret POSTs and router-user create with run-time `{SEC_*}` secrets (leak scan covers them; they are NOT normalized, so a leak would also show as a diff). On KN-1811 created PPPoE/PPTP connections are not listed back, so the valid internet/password and vpn/credential submits answer 404.
- Clippy `shadow_unrelated` fires on a closure param named like an outer `domain`/`checked`: name closure params `ctx`, `change`, `submitted`.

## [2026-11-14] Todo 33 progress
- Kit extension (additive; `Planned::of`, `Submission::{new,confirming,confirming_planned,landing_in,submit}`, `Form::{answer_invalid,answer_refused}`, `Invalid`, `Formless` unchanged):
  - `Planned::working(&[ChangeOp], work)` and `Planned::assessed(risk, work)`: the domain's own run on the leased change set (`work: for<'s> FnOnce(&'s mut ChangeSet, &'s RouterCtx) -> Working<'s>` + Send + 'static, `Working<'s>` = pinned boxed Send future; write `move |changes, context| Box::pin(async move { .. })`). Stored as `submit::work::Job::{Change, Work}` inside the non-generic `Planned`, run by `Action::run_planned` (now pub(crate)) through `run_with` at the planned risk (floor: descriptor risk). Why boxed and not a generic `Planned<J>`/`submit<J>`: `async |..| Err(DomainError::..)` callers (submit_tests, todo 34) would lose type inference of `J`.
  - `assessed(risk, ..)` exists for the firewall, whose risk is `firewall::management::interfaces_risk` (no ChangeOp: the page builds its own CLI lines until todo 42).
  - `Submission::submit_reading(check, plan, refresh)`: `check: AsyncFnOnce(&Params, &RouterCtx) -> Result<T, submit::rejected::Rejected>`, run after `action.context()`. `Rejected::{Invalid (form, validation_failed), Refused(Failure) (form.answer_refused, its audit), Failed(Failure) (outcome region via form.answer_changed(Outcome::failed), its audit: gone/unreachable/not_found), Missing (404, unaudited)}`; `From<Invalid>`/`From<Failure>` (=Failed) allow `?`.
  - `Form::answer_changed(outcome, refreshed, locale)` (default `respond::changed`), `Submission::refreshing_after_failure()` (policies, segments create read back after a failed change too).
  - Bug fixed in todo 32's code path while splitting: none; but beware `mem::replace(&mut self.ask, Never)` in a let-else drops `Ask::Planned` (caught by firewall_bind tests).
- Page adapters: `routing_page::reply::Replying::new(form)` (answers refusals/changes with the routing blank-line `answer`), `firewall_page::run::{Sender::submission/assess/refreshed, Firewall<F>}` (403 page when a plan refusal audits `forbidden`; management pre-check is `Err(DomainError::PermissionDenied)` in the plan step), `clients_pages::client_actions::ActForm`, `impl Form for {PoolDialog, LeaseDialog}`, `segment_create::Creating` (403 for forbidden, step note via Arc<Mutex<Option<String>>>), `policy_actions::Confirming` (typed-name dialog).
- NAT/routing plan refusals: the only reachable refusal over HTTP is the catalog's `DomainError::Validation` (e.g. an interface name with a space, via `FakeRouter::builder(..).show_fixture("interface", json!({"Uplink One": {..}}))`), whose real audit reason IS `validation_failed`; it is now answered in the outcome region (200, `hx-trigger: kcc:dialog-close`) instead of a 422 field error. `forbidden` is covered by the kit unit test.
- Still on `run_with(`: `clients_pages/segment_delete.rs` (risk from `view.deletion_plan`, not a literal; its not-found read-back, unaudited plan refusal and per-step note were left as is). `routing_page/route_remove.rs` uses `action.run_planned(Planned::working(..))` outside `Submission` (its route-wipe guard answer needs reads and an extra audit after the run) and audits its pre-reads through `reply::refused`.
- RED without changing git state: `git archive HEAD | tar -x -C <scratch>`, copy the new test file in, build with the same CARGO_TARGET_DIR (only workspace crates rebuild).

## [2026-11-14] Todo 34 part 2 progress
- Kit designs (crates/kcc-web/src/page_kit/submit*):
  1. Outcome recast = the existing `Form::answer_changed(outcome, refreshed, locale)` (doc says so); no new kit API. The page's form holds what it needs, all computed before the Submission: `secret_pages::reply::Secret { dialog, what }` recasts a success with `verified`; `dns_vpn::vpn_import::Importing { dialog, keyed: Option<headline>, notes }` with `confirmed` + `Answered::read_back(..).notes(..)`. The form never holds the secret/file: values go check -> plan only.
  2. Run-only landing: `Submission::landing_run_in(target)`. `submit/flow.rs::Course` now holds ask + landing (`Landing::{Own, Every, Run}`) + refresh_failed; `refused()` retargets only for `Every`, `ran()` for `Every|Run`. user_delete uses it.
  3. `Form::answer_unplanned(self, Unplanned<'_>, locale)` (async trait fn, default -> `answer_refused(failure)`); `submit::unplanned::Unplanned { error: &DomainError, failure, domain: &RouterCtx }`. Async because the DNS dialog re-reads its lists with the plan's ctx. Impls without an await must NOT be `async fn` (clippy `unused_async_trait_impl`): write `fn answer_unplanned(..) -> impl Future<Output = Response> { core::future::ready(..) }` (not refining: 2024 capture rules). The OnceLock (user_forms/user_answers) and Mutex (dns_pages/flow Answers) slots are gone.
  4. Invalid-only path: `Submission::checked(check) -> Result<(Action, T), Answer>` (diagnostics job start).
  Also `Planned::described(work)`: work at the operation's descriptor risk (Risk::Read floor; Action takes max with the descriptor) for work without ChangeOp (reboot, reset, mesh restart, config save/commit/rollback). `impl Planned` + `highest` moved to `submit/work.rs` (submit.rs was 263 pure LOC). `Action::run`/`run_with` are now private to page_kit::action.
- Migrated: secret pages wifi_psk, wan_password, user_password (+ vpn_server password via generic `user_password::run<T, P>`), vpn_server psk + vpn_credential (`Planned::working(slice::from_ref(&op), ..)`), dns_vpn/vpn_import, system_pages/user_delete, system_general reboot + reset, net_mesh restart (Submission + confirming_planned + described), config_page/safety save/commit/rollback (`action.run_planned(Planned::described(..))`, custom answers), clients_pages/segment_delete (Submission, landing_in + refreshing_after_failure, step note via Arc<Mutex> as segment_create), diagnostics (`checked`).
- Left: routing_page/route_remove stays outside Submission but on `run_planned(Planned::working(..))` (its route-wipe answer needs reads + an extra audit after the run). Remaining `Action::confirm(Risk::..)`/`confirming(Risk::..)` literals are confirmation risks, not run risks (component_commit job, storage, keendns access, interface edits).
- Behavior notes: audit-only corrections: user_delete/vpn_import plan refusals were `validation_failed`, now the domain's reason; segment_delete plan refusal was unaudited, now audited. Unreachable corners: vpn_import 403 pre-check dropped (kit SafetyNet is identical; only rendering of the refusal differs); user/vpn-server password plan ProtectedAccount audited `failed` instead of `protected_account` (pre-checked before, so unreachable); reboot/reset/mesh-restart ask after `context()` (differs only when the router has no client).
- Counts (crates/kcc-web/src): abandon("validation_failed") 16 -> 1 (page_kit/submit.rs); Risk::Write non-kit 8 -> 4 (services.rs:211 permission display, advanced/detail.rs:114 catalog fallback, advanced/check.rs:201 label, dns_vpn/dns_checks.rs:82 validation op: none is a run risk); `.run(`/`run_with(` grep 30 -> 16 (rest: page_kit/action.rs internals, record.run()/work.run/fleet self.run, not Action runs); Action run/run_with call sites outside page_kit 14 -> 0.
- Tests: system_pages::user_changes::a_delete_the_domain_refuses_is_audited_with_its_reason (red: audited validation_failed; green). Kit: page_kit/submit/answer_tests.rs (refused plan in words of the domain error, recast of a run's answer, run-only landing, checked) using an operator whose Planned::assessed(Destructive) run is refused `forbidden` (no brackets owner needed); mutation-checked. World helpers in submit_tests are reachable through pub(in crate::page_kit::submit) fns (clippy forbids scoped field visibility).
- Clippy gotchas: `rest_pattern_accessible_field` (write `Ask::First { risk: _, resubmit: _ }`), `too_long_first_doc_paragraph`, `shadow_*` on `let (action, ..) = Submission::new(action, ..)` (rename the first binding `opened`).

## [2026-11-14] Todo 35 progress
- Engine: `page_kit::form` (`form.rs` data types + template binding; `form/dialog.rs` the one `impl FormDialog`; `form/input.rs` `impl Input`/`impl Choice`; `form/answer.rs` the one `impl submit::Form for FormDialog`; `form/form_tests.rs` the moved one-field test). Template `partials/kit_form.html`. Clippy forbids scoped field visibility, so the structs live in `form.rs` with private fields and the impls in child modules (children see the parent's private fields); template helper methods in `form/dialog.rs` are `pub(super)`. Askama passes method args by reference: `opens_group(&usize)` carries `#[expect(clippy::trivially_copy_pass_by_ref)]`. `struct_excessive_bools` (max 3): the button tone is a `&'static str` class modifier.
- API: `FormDialog::{new(locale, MessageKey, post_to), titled(locale, String, post_to), network(locale, String, post_to)}`, `.ids(prefix)` (default `form-<name>`; network `net-<name>`), `.with_input(Input)`, `.intro/.closing/.submit/.danger/.multipart/.leading_break/.problem_at(Problem::{Above,Top,Below})`, `.refusing_at(field)`/`.refusing_in_dialog()` (default: outcome region), `.with_value(name, v)`, `.values(&Params)`, `.with_error` (replace), `.error` (append), `.errors(&Errors)` (unknown name -> problem), `.problem`, `.show()`, `.invalid()`. `Input::{new (required, <=128 chars), text, field (ui::field component), file, secret, hidden(name, value), check}` + `.value/.select/.radio/.checks/.number/.typed/.max_chars/.optional/.rule/.help/.shown_for/.id/.mono/.grouped`. `Choice::{word(locale, value, key), plain(&str), .checked(bool)}`.
- Byte-identity quirks kept as explicit switches: network forms name help before error in aria-describedby, select an empty option for an empty value, and retarget their GET into the dialog (`network`); dns selects with an empty value choose nothing; plain `ui::field` fields (2-space label indent) vs the rich `div.field` (4-space); dhcp `lan-fields` group (`grouped`); KeenDNS dialogs start with a line break (`leading_break`); problem notice above form (dns), top of form (dhcp), `role=alert` under inputs (KeenDNS).
- Moved: 12 net_form files, dns_vpn (dns_forms/vpn_forms + imports), FieldDialog users (client_act/client_actions/system_general), the seven hand-written dialogs (page adapters UserForm, NameDialog wrapper, ActForm stay). SecretDialog left: its typed-twice pair has its own markup (autocapitalize, minlength/maxlength rule on both fields, help under the first only, ids secret-new/secret-repeat) and a refusal replaces the whole form; the engine's secret kind is kit::secret_field markup, not byte-identical.
- Uncovered-dialog net: throwaway tests/zz_dialog_dump.rs (removed) replaying capture.sh's /ui/r/home lines + 3 auto POST variants per dialog form (empty, "x y!", 300 chars) = 446 answers; before (unchanged tree) vs after identical after normalizing backup times/job ids (two unchanged runs differ in the same 5 files).

## [2026-11-14] Todo 36 progress
- Merged API, `page_kit::confirm` (root holds the types, children the impls: `confirm/{dialog,prompt,stakes}.rs`, tests `confirm/confirm_tests.rs`):
  - `Confirmation` reads `confirm`/`confirm_name` (`from_pairs`, `new`, and now `Deserialize` via a private `Sent` + `#[serde(from)]`, so the wizards take `Form<Confirmation>`; `migrate_wizard::confirm::Confirm` is gone). `Gate`, `Resubmit`, `FAIL_SAFE_MINUTES` unchanged.
  - `Stakes`/`Guard` moved in from `page_kit/stakes.rs`; the confirmation half of `Family` moved onto them: `Family::gate(risk, ..)` -> `Stakes::new(risk).gate(family, ..)`, `Family::ask(stakes, ..)` -> `stakes.ask(family, ..)`, `Family::dialog(guard)` -> `guard.words(family)`, `Family::confirm()` -> a match in `Prompt::render`. Callers changed: page_kit/action.rs, advanced/{cli,execute,rci,rci_check}.rs, config_page/confirm.rs.
  - `Dialog` (the one `partials/kit_confirm.html`): `Dialog::new(locale, Words::new(title, text, button), Resubmit)` + `.asking(Ask::{Button, Acknowledge (default), Typed(Typed::router(locale) | Typed::object(locale, name))})` + `.with_text_key(key)` (kit marker `data-message-key`), `.saying(Saved::{Unsaid, Persists, Mixed(text)})`, `.with_list(lead, items)`, `.with_button(key)`, `set_error`, `show()`. Button tone comes from `Ask::danger()` (Button/Typed danger, Acknowledge primary), so no tone flag. `Dialog::typed_name(locale, action, name, (title, text))` replaces `TypedNameDialog::new(shell, ..)`; `Prompt::render` builds the kit's dialog.
  - `TypedNameForm` (moved, deny_unknown_fields, all fields required): `object`, `confirm`, `confirm_name`; `confirmed()` reads through `Confirmation::new` (confirm=yes AND typed == object). Handlers unchanged except imports (they still call `form.name()`/`form.confirmed()`); vpn/internet `Invalid::at("confirm")` -> `"confirm_name"`.
- Stayed: `Family` (page_kit/family.rs) is the page family + outcome wording used by ~40 files (done/invalid/rejected/...); only its confirmation methods moved. `config_page::confirm::ConfirmDialog` and `routing_page::reply::ConfirmDialog` stay as thin wrappers over `confirm::Dialog` (their 3 and 6 call sites unchanged). `migrate_wizard::confirm::refused` (a wizard step answer, not a confirmation) moved to `migrate_wizard::screen::refused`. `migrate_wizard::target_confirm::Confirm` is the firmware-tier acknowledgement, not a confirmation dialog: untouched.
- Field contract: every typed name is `confirm_name` next to `confirm=yes`; the typed-name dialog's object travels as hidden `object` (was hidden `name`; the typed text was `confirm`). Object in the action query was rejected: it renames golden snapshot files (POST slugs) and changes nothing else.
- Golden: capture.sh posts the old typed-name bodies, so the run used a translated COPY (8 lines: `name=X&confirm=Y` -> `object=X&confirm=yes&confirm_name=Y`). Diff = 12 files, all rename: 7 GET typed-name dialogs + 4 refused POST echoes (hidden name -> confirm=yes + object; field confirm -> confirm_name) + segments empty-body rejection "missing field `name`" -> "`object`". Keeping `TypedNameForm` fields required keeps axum's rejection BEFORE the handler (no audit entry, so the audit export stays identical).
- Uncovered dialogs: throwaway `src/page_kit/zz_dump_tests.rs` (env `ZZ_DUMP_DIR`, removed) rendered 272 variants before/after (config's private `mod confirm` made pub(crate) temporarily, restored). Identical except typed-name rename and the migration dialog's stray 2-space indent before `<form` (dropped; inter-element whitespace).
- Askama: `{%- match x %}{%- when A %}{%- when B with (v) %}` with `{%-` on every arm reproduces `{%- if %}` output byte for byte; a template `keys::` path needs `kcc_i18n::keys` imported in the module of the Template struct.

## [2026-11-14] Todo 37 progress (design, written before the move)
- Duplicated surface (file:line, unchanged tree 5a6d5ea): record.rs machine mw 124-359 / pp 120-346 (current,id,owner,created_at,step,preview,run,run_mut,finished,start_run,show_results,finish,preview_ready,go_back,previous: identical but for the step enum, the Finish enum and the fixed-source rule: restore vs saved preset); access.rs Visit mw 89-222 / pp 316-401,470-513 (open/services/record/record_mut/session/save/passwords/seal_passwords identical, pp loads with load_named(FILE)); resume.rs mw 38-113 / pp 151-229 (preamble + Back identical, step->panel match differs); screen.rs mw 29-127,163-173 / pp 199-285 (identical but title, summary, prefix, list link, steps label; templates pages/{migrate,presets}_wizard.html differ only in those + migrate's `if !summary.is_empty()`); report.rs mw / pp (same head, presets add keys/kept, downloads differ; templates differ in those sections); landing list mw store.list vs pp runs() (same sort).
- Serde contract decides the record design: both records are flat structs with deny_unknown_fields and interleaved field order (mode/origin before step; keys/kept_keys between run and finished). `#[serde(flatten)]` silently drops deny_unknown_fields, and a generic Record<F> with a proxy wire struct costs more than it saves. So each side KEEPS its derived on-disk struct verbatim (field list, order, attributes untouched) and implements `wizard::flow::Flow`; the shared machine is the trait's provided methods over two field projections (`head()` read view, `moves()` &mut view of step/preview/run/finished).
- Flow (implemented by each side's Record): types Step, Finish, Analysis (migration's analysis; presets `()`), View (resume query); consts STEPS, PREVIEW/APPLY/RESULTS/REPORT, FILE (record file), PREFIX (run page prefix), LIST/ALL/STEPS_LABEL/SECTION (page chrome), CLOSED; required head/moves/fixed/routers/title/summary/slug/label/finish_text/success/show; provided the machine above.
- Generic over F: Store::{load,save,list}<F>, Wizards<F>/Session<F> (manual Default), Visit<'_, F> (side extras in a per-side extension trait), screen::page/moved/href, resume::{page,back}, report::Panel; one page template pages/wizard.html and one partials/wizard_report.html (output byte-identical, checked by the dump net).
- Moved whole: ids, store(+tests), run (Run/Ended/failure fns; migration Finish -> migrate_wizard/kinds.rs, next to the presets' Finish in steps.rs, both move again with finish), live, service, Services, analysis's shared half (Problem, shown_line, parse_source, inventory_problem; the migration Analysis stays).
- Net: throwaway dump in tests/{migration_wizard,presets_pages}/support.rs `send` (R37_DUMP: <binary>.<test>/<seq>.{head,html} + record/report/plan json of every run after each request); two unchanged runs normalized identical (ids, job ids, ports, backup names, CSRF). Old-record fixtures tests/fixtures/{wizard-record,preset-run-record}.json from that dump (report step, every field, RFC 5737 reconnect URL), tests records.rs in both suites: green on the unchanged tree.

## [2026-11-14] Todo 37 progress (done, worker r37)
- Final shape: `wizard/flow.rs` holds `Stage` (Step: ALL, slug, label, provided number) and `Flow` (implemented by each side's `Record`: types Step/Finish/Analysis/View; consts PREVIEW/APPLY/RESULTS/REPORT, FILE, PREFIX, LIST, ALL, STEPS_LABEL, SECTION, CLOSED, STOP; required accessors (schema,id,owner,created_at,step,target,preview,run,finished,moves) generated by `record_fields!()` (lib.rs, next to `localized!`, needs `Moves` and `Run` in scope), plus fixed/routers/finish_text/succeeded/ended_words/title/summary/show; provided current/run_mut/preview_ready/start_run/show_results/finish/go_back/previous). `Moves<'_, F>` lends &mut step/preview/run/finished.
- Generic over F: Store::{load,save,list}, Wizards<F>/Session<F> (manual Default: derive would demand F: Default), Visit<'_, F> (per side `type Visit<'call> = visit::Visit<'call, Record>` + extension trait `Migration` (seal_source/analysis/hardware) / `PresetRun` (preset/inventory)), screen::{page,moved,href::<F>,refused}, resume::{page,back,results}::<F>, events::events::<F>, running::{Panel,stop::<F>}, report::Panel (+with_downloads/with_keys). Templates merged: pages/wizard.html, partials/wizard_apply.html, partials/wizard_report.html (6 removed).
- Moved whole into wizard/: ids, store(+tests), run (migration Finish -> migrate_wizard/kinds.rs), live, service, beats, events (Feed), Services (from access.rs), analysis's shared half. Side files left: migrate_wizard/summary.rs (title, source_text, summary) and presets_page/summary.rs (title, settings_text, summary); side resume.rs = `show` (step -> panel) only.
- Gotchas: a pub(crate) record's `impl Flow` leaks its assoc types (E0446 / private_interfaces), so migration Step/View/Analysis are pub(crate) (the store test needs the migration Record). `same_name_method` forbids an inherent `target()`/`step()` next to Flow's: remove the inherent ones and add `use crate::wizard::flow::Flow as _;` where called. Generic axum handlers work (`get(resume::page::<Record>)`) when Flow::show returns `impl Future<Output = Response> + Send`. too_long_first_doc_paragraph fired on a 3-line `//!` paragraph of long lines.
- Behavior notes: presets' run list now goes through `Store::list` (adds the record-id == directory check the migration list had); the preset events' end reads through `Store::load` (adds the schema check). Unreachable through the UI.
- Sizes: dirs 14414 -> 11768 (-2646); wizard/ 2565 + 55 (macro in lib.rs): net -26 lines of Rust and -3 templates. Net: dump before/before2 identical after normalizing; before/after identical (3147 files incl. every record json after each request).

## [2026-11-14] Todo 38 progress (design, written before the move; worker r38)
- Duplicated surface (base fe97aa2 = master f6aecbd + todo 37):
  - results panel: migrate_wizard/results.rs:28-190 vs presets_page/results.rs:31-190 (ROLLBACK const, BEFORE_CHANGES list, STEP/DIALOG targets, Act, Panel fields, Panel::new tone/key/pending/rollback/failed_before/buttons, refusing, act, facts): identical but for the keep buttons (migration Commit primary vs presets Keep primary + Save secondary), migration's Replan button (and close hidden when replan shows), the three words (verified/failed/interrupted keys), recorded_text (wizard::run vs presets events.rs) and the template.
  - end words: migrate_wizard/results.rs:194-206 vs presets_page/events.rs:15-27 (same shape, the three keys and recorded_text differ).
  - templates partials/migrate_results.html vs presets_results.html: identical but the URL prefix (sse-connect + hx-post), presets' extra `page__text` paragraph while pending (WEB_PRESETS_RESULTS_TEXT), and the forbidden key (WEB_MIGRATE_ROLLBACK_FORBIDDEN vs WEB_PRESETS_ROLLBACK_FORBIDDEN).
  - finish core: migrate_wizard/finish.rs:112-182 vs presets_page/finish.rs:98-166 (step check, audit action, allowed() -> audited 403, live applier or 409, brackets::hold, applier call, Attempt::Failed audit, RollbackRestarting -> end + moved, failure panel 422, end + "done" audit) identical but: the choice table (migration commit/rollback; presets keep/save/rollback), failure_text (wizard::run vs presets events.rs) and presets' audit params {"finish": slug}.
  - end(): migrate_wizard/finish.rs:188-206 vs presets_page/finish.rs:172-192 (presets also saved::discard).
  - rollback dialog: migrate_wizard/finish.rs:86-104 vs presets_page/finish.rs:99-116 (keys and prefix differ).
  - settle: migrate_wizard/finish.rs:214-262 vs presets_page/finish.rs:200-246 (migration: replan forgets the session analysis and plans from the maps; unknown way answers 404 AFTER the step/pending checks; presets: retry/close only, discards sealed files on close).
- Route-level differences that must stay (routes/extractors frozen): migration has /commit (no form body), /rollback (Form<Confirmation>, dialog asked BEFORE the step check) and /{way} settle (no form); presets has one /{way} (Form<Confirmation>; unknown way 404 BEFORE opening the run; rollback dialog AFTER the step check). So the shared module offers generic entry handlers per route shape (commit/rollback/settle for migration, choose for presets) over one shared core.
- Finish enums: kept as `Flow::Finish` associated types, not one enum: the variant sets differ (presets KeptUnsaved/Saved vs migration Committed), the serialized names are the on-disk record format (deny_unknown_fields; a merged enum would let a migration record load "kept-unsaved"), and their text keys differ. The shared code names the variants it needs through the new trait.

## [2026-11-14] Todo 38 progress (done, worker r38)
- Merged API (crates/kcc-web/src/wizard/):
  - `finishing.rs`: `ROLLBACK` (Migrate + Destructive, both wizards), `Choice::{Keep, Commit, Rollback}` (router finishes), `Settle::{Replan, Retry, Close}` (no router request), `type Keeping = (Choice, way, label key, button style)`, trait `Finishing: Flow` implemented by each side's Record: consts KEEPING (migration [Commit "commit" primary]; presets [Keep "keep" primary, Commit "save" secondary]), REPLANS, VERIFIED/FAILED/INTERRUPTED, WAITING (presets' WEB_PRESETS_RESULTS_TEXT), ROLLBACK_FORBIDDEN, ROLLBACK_WORDS, ROLLBACK_RESTARTING, ROLLED_BACK_BY_ROUTER; fns choice(Choice) -> Option<(audit action, permissions, Finish)>, failure_text, audit_params (default None; presets {"finish": slug}), plan_anew(replan), discard (default no-op; presets saved::discard); provided recorded_text, ended_words (moved out of Flow; events.rs now bounds F: Finishing).
  - `results.rs`: one `Panel::new::<F>` + `partials/wizard_results.html` (prefix, optional waiting text, optional forbidden note; buttons = KEEPING then replan/retry/rollback/close).
  - `finish.rs`: generic entries per route shape: `commit::<F>` / `rollback::<F>` (migration routes: no form / dialog before the step check), `choose::<F>` (presets' one {way} route: unknown way 404 before opening the run, dialog after the step check); one `ask` (typed-name dialog), one core `finish` (permission -> audited 403, live applier or 409, brackets::hold, applier call, Attempt::Failed audit, RollbackRestarting -> end + moved, 422 panel), one `end`.
  - `settle.rs`: `way::<F>` (migration {way} route; unknown way 404 AFTER the step/pending checks) + one `settle` core.
- Finish enums stayed `Flow::Finish` associated types (variant sets and serialized names differ; on-disk format). Side files: migrate_wizard/finish.rs and presets_page/finish.rs now only `impl Finishing for Record` (+ presets KEEP/SAVE). Deleted: migrate_wizard/results.rs, presets_page/results.rs, partials/{migrate,presets}_results.html, wizard::run::recorded_text (its unit test now calls the migration Record's), presets events::{end_words, recorded_text} (its test calls Record::ended_words).
- Sizes (wc -l): dirs {migrate_wizard,presets_page}/*.rs 11768 -> 10976 (-792); wizard.rs + wizard/*.rs 2565 -> 3270 (+705); combined 14333 -> 14246 (-87); results templates 57 -> 31 (-26). Lines identical in sequence between the old pairs: results 158, finish 145, template 24. So the combined drop (-113 incl. template) is LESS than the identical lines merged: the price is the Finishing vocabulary (finishing.rs 107 + two side impls 136) and keeping BOTH frozen route shapes (migration /commit, /rollback, /{way} vs presets /{way}, each with its own extractor and check order: 3 extra entry handlers, ~70 lines). Unifying migration onto `choose` would change edge behavior (commit then requires a form content type; rollback dialog after the step check; unknown way 404 before the refusal/409) and needs an owner decision.
- Nets: R38_DUMP in tests support send() (head/html/state json/audit/router CLI log per request): 5515 files, before==before2, before==after after normalizing. Uncovered corners (retry/close/replan/unknown way/keep on migration/commit on presets/route order at preview step, fail-safe arm refused, line refused, operator) via throwaway zz_r38 tests run on `git archive` of the base and on the change: 2075 files, identical. Gotcha: base archive and worktree share the test binary hash in one CARGO_TARGET_DIR (nm proves which tree built it); never run them concurrently. A `disconnect_before_parse` scenario hangs the apply stream (dropped).
- Permission proof: migration operator_guards::an_operator_applies_and_commits_but_cannot_roll_back and presets guards::an_operators_rollback_is_refused_before_any_router_request (403, no router request, audit forbidden) both green unchanged; no new test needed.

## [2026-11-14] Rust 1.100.0 adoption
- What 1.100 flagged (clippy, default toolchain): (1) `clippy::map_unwrap_or` (pedantic) now also fires on
  `map(f).unwrap_or_default()` for Option and Result, suggesting the new stable `map_or_default(f)`: 51 sites
  (kcc-catalog 1, kcc-config 2, kcc-testkit 2, kcc-domain 2, kcc-rci tests 2, kcc-migrate 1, kcc-mcp 1,
  kcc-web 33 incl. 2 tests, kcc 4, xtask 2). Rewritten 1:1 (semantics identical: closure runs only on Some/Ok,
  else Default). `cargo clippy --fix --allow-dirty -p <crate> --all-targets --all-features` applies them
  mechanically. (2) `clippy::integer_division_remainder_used` no longer fires inside `tokio::select!`, so
  every `#[expect]` for it with a "tokio::select expansion" reason became unfulfilled: removed in
  kcc-rci engine/background.rs, kcc-telemetry logs/pipeline_delivery.rs + logs/service.rs (2),
  kcc/src/server_shutdown.rs and the `#![expect]` list of kcc/tests/serve_bracket.rs. The ones in
  kcc-config ns3.rs/config_text.rs (real `%`) still fire and stay. (3) `clippy::module_name_repetitions`
  no longer fires on a `pub use` re-export: unfulfilled expect removed in kcc-migrate/src/apply.rs.
  (4) `clippy::redundant_clone` (nursery) newly caught `vec![path.clone()]` in kcc-domain tests/profile_coverage.rs.
- Cargo 1.100 warns `unused_workspace_package_fields` for `[workspace.package] publish` that no member
  inherits; removed the key (all 12 members set `publish = false` themselves; metadata shows publish == []).
- Pins moved 1.99.1 -> 1.100.0: Cargo.toml + xtask/Cargo.toml rust-version, ci/release/container workflows,
  MSRV job name + `cargo +1.100.0 build`, scripts/ci-local.sh, AGENTS.md, CONTRIBUTING.md,
  deploy/podman/README.md, Containerfile builder (rust:1.100.0-alpine index digest). rustfmt stays on
  nightly-2026-10-03. Not touched: docs/rust-guidelines/overlays/projects/keenetic-control-center.md still
  says 1.99.1 (excluded dir), spikes/lint-macros rust-version 1.99.0.
- Gotcha: `cargo fmt` run inside `xtask/` reformats seccomp*.rs (xtask is not fmt-clean on its own); the gate
  only runs root `cargo fmt --all`, so do not run fmt inside xtask/.
- Correction: the map_unwrap_or site total above is 50 (1+2+2+2+2+1+1+33+4+2), not 51.

## [2026-11-14] Todo 39 progress
- Module API (`crates/kcc-web/src/table/`): `view::TableView` (builder: `new(class)`, `labelled`, `search(label, &Table)`, `count(class, text)`, `blank(class, text)`, `head(Head)`, `row(Vec<Cell>)`, `paged(Pager)`, `nested()`; shapes `filtered(class, &Table, (locale, empty))` = filter + `.page__text` empty/no-match + pager, `counted(class, &Table, (locale, label, empty))` = filter + `net-region__count` "N of M" + `.panel__note` empty/no-match + pager), `view::Head` (`sorted`, `plain`, `hidden`, `with_class`), `cells::Cell` (row header or data cell, attributes in the order the page sets them, body = pieces / `ul.cell-lines` / `Ordered` list with buttons / actions with `Layout::{Inline, Block, Wrapped(div class)}` and `aria-describedby`), `cells::Piece` (bare text or span with attrs + optional inner span), `cells::Pill`, `acts::Act` (open, form post, htmx `sends`, link, `note`, `menu` of `MenuItem`). Template `partials/kit_table.html` (included with the view bound to `table`); macros `kit::piece`, `kit::act(action, described_by, indent)` moved from the deleted `dns_vpn_macros.html`.
- Byte-identity tricks: askama never re-indents an include, so every kit_table line starts with `{{ p }}` (the view's pad, "  " for a table inside a section) and lines ending before a trimming tag use `{{ table.indent(n) }}` (an expression is not eaten by `{%-`); attribute order differs per page (DNS `id` before `class`, everyone else `class` before `id`), hence ordered attribute lists instead of fixed fields; `{% match %}` arms in an included template need full paths (`crate::table::cells::Layout::Inline`); imports inside an included template work; several tables in one template bind `{%- let table = self.radio_table() %}` inside the `if` block.
- Feature matrix: DNS/VPN (aria-label, table-empty/table-count, id-first row header, cell-lines, pills, muted, row-actions div with form/open/link); routing static/table (mono cells, inline Remove, source span), policies (ordered permits with ids + per-item Remove described by two ids, popover menu with post/open/danger entries); NAT rules (block cell: Remove or muted note), interfaces (narrow class), sessions (own filter form + router pager stay in the page; table and blank through kit_table); firewall rules (nested, numeric plain head class, colspan cell, note spans incl. nested schedule span, wrapped actions with move buttons + menu), bindings, UPnP; network interfaces/internet (row header not first, status pill, wrapped admin-actions with sends/open/danger), ping (nested plain table), mesh, Wi-Fi radios (inline Settings), points, stations (nested counted).
- Converted all 14 templates of the five families; none left (the only remaining non-table markup is the internet `dl.facts` sheet, never a table). `grep -rln '<table' templates` 42 -> 29 (kit_table.html + 28 for todo 40).
- Sizes: family templates 1009 -> 408 lines; Rust pure LOC of the touched modules 2416 -> 3530 (the markup became typed builders); largest new files table/cells.rs 240, routing_page/tables.rs 236 pure LOC.
- Nets: golden34 copy with the 8 typed-name bodies translated, base from `git archive HEAD` before any edit: diff empty (357 files). Throwaway variation test (24 pages x 3 roles x full/HX, crawled sort and pager links, filters hit/miss/`<`, pages 2/999/0/garbage, 6960 bodies on a seeded fixture): before vs before2 differ only in the CSRF meta token; normalized diff after each family and after the clippy fixes: empty. Test binaries moved to `target/debug/build/<pkg>/<hash>/out/` under cargo 1.100.
- Gotcha: rustup stable switched to 1.100.0 mid-session (17:21). cargo 1.100 warns "unused field `publish` in `workspace.package`" and `[build] warnings = "deny"` turns every cargo run into exit 101; clippy 1.100 fails kcc-rci (`unfulfilled lint expectation` at engine/background.rs:115) and kcc-catalog (`map(_).unwrap_or_default()` at request.rs:242). The warm caches were 1.99.1, so all gates here ran with `cargo +1.99.1` (and `RUSTUP_TOOLCHAIN=1.99.1` for the golden capture).

## [2026-11-14] Todo 40 progress
- Converted 23 templates in six families onto `partials/kit_table.html`: clients (`clients_landing`, `clients_region`, `dhcp_region`; segments has no table), system (`system_components/schedules/services/users_region`, `system_storage` media + USB), configuration (`config_backups`, `config_landing`), admin (`admin_audit`, `admin_server`, `admin_keys/roles/users_region`), explorer/advanced/dashboard (`advanced`, `navpicker`, `explorer_command`, `router_live` WAN + access points), wizards/presets (`migrate_landing`, `presets_runs`, `presets_list`, `wizard_report` keys). `grep -rln '<table' templates` 29 -> 6.
- Exceptions (kept, 5): `migrate_mapping.html`, `presets_macros.html` (rename grids: every cell a `select`/text `input` with `aria-labelledby`, `aria-invalid` and a per-field error paragraph), `migrate_review.html`, `presets_review.html` (review grids: hidden `shown` inputs, Include checkboxes, a radio `fieldset` per conflict, auto-saving form) - form-control grids, the kit would need a form-field cell kind serving only the wizards; `config_diff.html` (side-by-side diff: one `tbody` per hunk and empty cells for unpaired lines; the kit renders one `tbody` of rows).
- Module additions: `table::piece` (Piece moved out of cells: optional tag `span`/`a`/`time`/`code`/`details`/`summary`/`pre`, ordered attrs, one valueless `flag` such as `data-kcc-time`, text, child elements one level deep; `attr` on bare text still makes a span; `Line::{Piece, Open}` for cells holding elements one per line), `Cell::stack`, `table::head` (Head + Search moved out of view), `TableView::{wrapped, bare, compact, noted}`, `Layout::{wrapper, depth}`, `Act::{download, quiet}` (quiet = form with hx-swap none, admin users), `Act::menu_of` (menu class), `MenuItem::{hides, link, download, form}` (+ `lead`: the clients form entries start two columns left, as the page always rendered), `table::fleet::routers_table` (the four landing pages), `wizard::runs` (migrate + preset runs tables).
- Byte-identity tricks: kit_table rows/thead now use `table.break_at(n)` (newline + pad + n spaces, empty when compact) and `table.lead(n)`/`lead_at(Option)` instead of literal newlines, so compact and multi-line tables share one cell renderer; one `kit::act` call per action cell instead of one per layout. That restructure also fixed clippy `large_stack_frames` on `net_wifi.rs` (three kit_table includes in one template): every include inlines the whole kit, so keep kit_table small. Askama `if let Some(x) = method()` binds `&&T` for method args: pass `method()` results straight into another method instead.
- Admin row types are private to their modules: their tables live in child modules (`admin_keys/table.rs` etc.), which see the parent's private fields; system tables in `system_pages/{tables,storage_tables}.rs` with accessors bumped to `pub(super)`.
- Sizes: the 23 templates 1323 -> 520 lines (kit_macros 127 -> 167, kit_table 76 -> 76); Rust pure LOC of the 54 touched files 8017 -> 9463. Pre-existing oversize admin files grew by the `mod table;` line and rustfmt's nested import (admin_roles 643, admin_users 622, admin_keys 341, admin_audit 324 pure LOC): follow-up to split them.
- Nets: golden34 copy with the 8 typed-name bodies translated; base from `git archive wt/r40` before any edit; final diff empty (716 files). Throwaway `tests/zz_r40.rs` + `zz_r40b.rs` (copies of explorer/presets support with pub cookie/csrf, admin services attached): 17 table pages crawled (sort + pager links two levels, filters, pages 2/999/0/x, clients state/link) + 20 single pages (landings, pickers, explorer commands, migrate) as admin/operator/viewer, full and HX, then 11 POSTs (service toggle, component queue, schedule, backup, admin user/role changes) and the regions after; presets fixture: 2 presets (one with a WireGuard tunnel for the keys table), runs kept/saved/unfinished, 2 migrations, 4 roles. 2820 bodies; noise before/before2 = 2744 raw files (CSRF, ports, tmp paths, times, backup names, wizard ids), 0 after normalizing; backups created a second apart (equal timestamps tie randomly) and no digit filters on the backups page. Normalized diff after each stage: 0.

## [2026-11-14] Guidelines sync adoption
Core 49898c9 (Rust 1.100) adopted in worktree rgl. What it requires and what was done:
- Cargo lint table: `[workspace.lints.cargo]` (root) and `[lints.cargo]` (xtask) added verbatim (default + pedantic deny at priority -1, non_kebab_case_features/packages deny). First clippy run: 0 Cargo-lint findings in both workspaces, so no manifest or code fix was needed. Liveness was proven on a scratch workspace with the same table: `unused_dependencies` and `manual_readme` fired as errors on cargo 1.100.0.
- `cargo xtask profile-eq` already compares every tool table generically (so the cargo table is covered). New `xtask/src/lint_inheritance.rs` adds the member check the core asks for: every `[workspace] members` entry (plain path or `dir/*`, minus `exclude`) needs `[lints] workspace = true`. An empty `[lints]` satisfies `cargo::missing_lints_inheritance` but fails this check. Tests: `inheriting_members_pass`, `member_without_inheritance_fails` (RED first).
- `cargo xtask lint-completeness` gained the Cargo leg in `xtask/src/cargo_lints.rs`. It reads `<sysroot>/share/doc/rust/html/cargo/reference/lints.html` from rust-docs, mirrors the core's Python regex without the regex crate, and requires the missing set to be exactly non_snake_case_features/packages. An unreadable reference exits 2 (proven with a rustc shim). `help_text` moved to `xtask/src/tool_output.rs` as `stdout_of` so lint_completeness.rs drops under 250 pure LOC.
- Cooldown: `.cargo/config.toml` `[registry] global-min-publish-age = "3 days"` + `[resolver] incompatible-publish-age = "deny"` (taplo wants a single space before trailing comments). Dependabot `cooldown: default-days: 3` for cargo `/` and `/xtask`. CONTRIBUTING has a short paragraph pointing to the core's emergency path.
- Gate tool pins in ci.yml (taiki-e `tool: x@ver`): cargo-deny 0.19.9, cargo-audit 0.22.2, cargo-vet 0.10.3, cargo-machete 0.9.2, taplo 0.10.0. The core pins only the first three; machete/taplo are recorded as overlay deviation 2. scripts/ci-local.sh installs nothing, so it needed no change.
- Overlay deviations opened: 2 (extra pins, accepted), 3 (latest-past-cooldown re-check left to the [workspace.dependencies] todo), 4 (YAML Rust versions unquoted; `1.100.0` already parses as a string).
- Gotcha: `cd xtask && cargo fmt` reformats xtask/src/seccomp*.rs. The xtask workspace is NOT rustfmt-clean at the base commit, and root `fmt --all` does not cover it. I reverted the drift and formatted only the touched files with `rustfmt --edition 2024 --config-path rustfmt.toml`.
- Gotcha: `tail -5` is rejected by this host's tail wrapper; use `tail -n 5`.

## [2026-11-14] Todo 42 progress (worker r42)
- Domain read model (`kcc_domain::firewall`): `read::firewall(&RouterCtx) -> Result<lists::Firewall>` reads the running configuration with the SAME single request the page sent (`GET /ci/running-config.txt` via `download_config(ConfigKind::Running)`), parses it, `redact`s it before anything else looks at it and keeps only lines made of plain words (a line with an `ns3` token is dropped whole), so no secret reaches the model, a log or an audit parameter. `lists::{Firewall, AccessList, ListEntry, Binding}` (IPv4 lists, IPv6 lists, bindings in configuration order; `ListEntry` = index, stored rule, `disable`, `description`, `schedule`; `ListEntry::configured()` = the planner's `ConfiguredRule` for a structured rule) and `rule_words::{StoredRule, RuleForm, Side}` (stored words + the structured form when the words have one: documented form or kcc's earlier bare form; ranges/`lt` etc. keep only their words). `Binding.direction` is the typed `model::Direction`.
- Why a text read and not `show rc` JSON like `configured_rules`: the JSON route needs three requests (access-list, ipv6 access-list, interface access-group) and has no IPv6/unparsed-rule semantics matching the page; the text read keeps the page's request log byte-identical. `configured_rules` and its CLI caller are untouched.
- Deleted from the page: the config-text parser (`snapshot.rs` 310 -> 24 lines, now only the domain call + the error -> message mapping: `DomainError::Rci` -> `WEB_KIT_UNREACHABLE` with the same warn log, anything else -> `WEB_KIT_FAILED`), the rule-word parser (`rule.rs` 250 -> 58: only presentation remains, `PROTOCOLS` (typed `Protocol` + label key, dialog order), `action_label`, `protocol_label`, `address_text`), `rule_actions::configured`. The old `rule_tests.rs` assertions were split: parser ones to `kcc-domain/src/firewall/rule_words_tests.rs`, address/label ones stay in the page's `rule_tests.rs`.
- One semantic narrowing: a configuration line `interface X ip access-group L <dir>` whose direction is neither `in` nor `out` is now skipped (the old page kept it and labelled it "in"). The firmware only writes in/out; no net covers the other case.
- Testkit: the fake's CLI engine now accepts `ipv6 access-list <name> ...` (same leaf grammar as `access-list`; BEHAVIOUR.md bullet), needed for the IPv6 read tests and the variation net. Applied BEFORE the before-dumps.
- `impl Row for Binding` now needs `#[inline]` on `key`/`matches` (clippy `missing_inline_in_public_items` fires because the domain type is `pub`). Module name `stored` tripped `module_name_repetitions` on `StoredRule`, hence `rule_words`.
- Sizes (pure LOC): page snapshot 217 -> 14, rule 180 -> 41, rule_tests 45 -> 32; domain read 176 -> 206, new lists 194, rule_words 149, rule_words_tests 50, tests/firewall_read 127.
- Nets: golden34 copy with the 8 typed-name bodies translated, base = `git archive wt/r42` before any edit: diff empty (716 files, 40 firewall). Throwaway `tests/zz_r42.rs` (+ support copy with pub cookie/csrf, `dead_code` expect): seeded fixture (3 IPv4 lists incl. structured/earlier/range/`lt`/ip/icmp/gre/esp/ipip rules with disable/description/schedule, 2 IPv6 lists, 5 bindings on Bridge0/ISP both directions, one list bound three times), 55 GET paths x 3 roles x full/HX + 46 POSTs + 9 regions = 385 dumps with status, hx-* headers, request-log delta, body, running config, plus audit; before vs before2: 219 raw files differ (CSRF meta only), 0 after normalizing; before vs after normalized: 0 (request logs, audit included). Removed before the final checks.

## [2026-11-14] Todo 43 progress
- Deleted (each grepped definition-only first; after: empty): `page_kit/reveal.rs` + its `expect(dead_code)` + `partials/kit_reveal.html` (only it used the template; its unit test `only_reveal_secrets_shows_a_secret_and_the_audit_never_holds_it` tested dead code and went with it; i18n keys `web-kit-reveal*` left for todo 44; DESIGN.md kit row and `secret.rs` doc fixed), `send_loki`, dns `with_hash`/`for_domain` (fields stay: parsing sets them), `read_startup_static_leases`, `Workflow::authorize_migration`, `NewAccount::with_disabled`.
- Kept: `workflow_last_change` (kcc-domain configuration.rs) has a production caller, `crates/kcc/src/cli/change.rs:299`.
- Loki retry test now drives `LogForwarder` (the production delivery path). Seam: `LogForwarder::start_with_clock` made `pub` (it was the private body of `start`). Deterministic on the current-thread runtime: push then shutdown, the worker first runs after the cancel so it skips the flush wait; RecordingClock sees exactly the Retry-After wait `[2s]`, fake Loki 2 requests (a flush wait would show as `[2s, 2s]`, so the assertion still discriminates).
- Moves: `kcc/src/cli/{coverage,exclusions}.rs` -> `kcc/tests/cli_domain_writes/{exposed,excluded}.rs` (name `coverage.rs` was taken by the test); `pub(crate)` struct/const, `pub` fields (clippy `field_scoped_visibility_modifiers` refuses `pub(crate)` fields).
- `RuleEngine` -> free `rules::classify` (pub) and `rules::classify_settled` (pub(crate)); `embedded()` was only a pre-check that `classify_settled` repeats. tests/rules.rs has its own `fn classify`, so it calls `rules::classify`.
- `expanded_words`: both copies identical in output (migrate's `_` arm is unreachable for kcc-config's two variants); one `pub fn kcc_config::secrets::expanded_words`.
- Quoting: new `kcc_config::quoting::quote_cli_text` (same encoding, control chars refused, no byte bound, returns String) beside `quote_cli_word`, both on one private `encoded`. kcc-domain `cli_token::{quoted, quoted_text}` map errors to `DomainError::InvalidCliToken`. Sites: `quote_cli_word` (256-byte bound) for mesh candidate/member, Wi-Fi ssid/country-code, WAN `authentication identity`; `quote_cli_text` (no bound) for interface description, firewall rule description, segments ownership marker (WorkflowError::InvalidResponse as before). Left: diagnostics.rs (JSON values), segments/discovery.rs:169 (builds the JSON marker). Catalog kind of all these fields is unbounded `String`.
- Differential corpus (old serde_json vs new): identical for ASCII, spaces, `"`/`\`, `/`, unicode, emoji, NBSP, U+2028, empty, 255/256 bytes; differ only for control chars (TAB, LF, CR, NUL, DEL, C1 0x85: old sent `\t`/`\u0000` escapes the CLI parser reads as letters, or raw DEL/0x85) and >256 bytes on the word path. RED: only the control-char tests failed before; the `"`/`\` tests passed before too (JSON escaping coincides for those two chars), kept as characterization.
- Counts: workspace tests 1428 passed / 0 failed / 7 ignored; golden diff empty (716 files); diff 32 tracked files +281 -779 plus 2 moved test files (260 lines).

## [2026-11-14] Todo 44 progress (worker r44)
- New unused-key check: `xtask/src/i18n/unused.rs` (child module of `i18n.rs`), run by `cargo xtask i18n-check` on the committed catalogs only (not with `--locales-dir`). Used = generated constant name as an identifier word, or `"id"`/`'id'` literal, in crates/**/*.{rs,html,js} except keys.rs. Test-only use (kcc-i18n bundle.rs tests, templates) counts as use. No code builds message ids at run time (grep of `format!("web-|cli-|...`, `MessageKey::new` only in bundle.rs tests with literals), so there is no dynamic-prefix rule. Failure line: `en/<file>:<line>: unused key <id>, ...`.
- Check on the unchanged tree found 44 unused keys: all 39 of the plan's list (none became used) plus 5 more.
- Deleted (41, six locales, keys.rs regenerated 7000+ -> -165 lines): the 39 plus `web-kit-reveal-title`, `web-kit-reveal-text` (family of `web-kit-reveal`, orphaned by the removal of page_kit/reveal.rs and kit_reveal.html in todo 43).
- FINDINGS for the owner, NOT deleted (unused, orphaned by earlier commits, not todo 43): `web-router-auth-text` (last used before 578b17c), `web-migrate-failure-replan` (563c9dc), `web-presets-preview-nothing` (e9baacb). `cargo xtask i18n-check` stays RED until the owner deletes them or wires them up (same deletion in six locales + `cargo xtask i18n-gen`).
- No bundle.rs test enumerates a deleted key (all_arguments lists variable names only); docs/I18N.md states no key count and lists no deleted key: unchanged.

## 2026-11-14 Todo 44 follow-up: deleted orphaned i18n keys

Three keys orphaned by prior remediation commits were deleted from all six locales (en, ru, uk, de, be, kk):
- `web-router-auth-text` (orphaned by commit 578b17c)
- `web-migrate-failure-replan` (orphaned by commit 563c9dc)
- `web-presets-preview-nothing` (orphaned by commit e9baacb)

Deleted from `crates/kcc-i18n/locales/{en,ru,uk,de,be,kk}/web.ftl` by editing each locale file, one key per locale per file, each removal confirmed in 5-line context.

Regenerated `crates/kcc-i18n/src/keys.rs` with `cargo xtask i18n-gen` (idempotent).

All verifications pass:
- `cargo xtask i18n-check`: GREEN - 0 problems
- `cargo test -p kcc-i18n --all-features`: 13 passed
- `cargo clippy -p kcc-i18n --all-targets --all-features`: passed
- `cargo +nightly-2026-10-03 fmt --all -- --check`: passed

## [2026-11-14] Todo 46 progress (worker r46)
- Inventory: 17 bracket files, 41 tests (core 4, CLI 13, MCP 13, Web 11). Classes: fate mapping (lost/applied/refused-both/refused-disarmed/not-sent, interface), batch completion + management-item fate, disarm-applied, permission wiring (rawdes/writer/viewer/server switch), mode (unknown mapping), curated command wiring, Web hold/budget/claim. Named classes outside bracket files: raw_management_brackets_both_modes, namespace_reads_bypass_change_workflow, mixed_read_batches_count_only_changes (kept, see ledger).
- Reduction: one fate table per surface (router mode + one extender interface row; NotSent/NotApplied rows added for CLI/Web), batch tests one mode with the management-fate rows folded in (CLI adds a --json row), mode tests keep only the ModeUnknown mapping rows (the decision table is kcc-domain configuration.rs::tests::decide_follows_the_recovery_table). Shared per-surface fixtures live in each surface's bracket.rs (CLI reuses permission_gates::{add_role,commands_after,edges}, now pub(crate); CLI TestResult got a default type parameter).
- Dead-writer fixture without touching the harness: a directory named like the rotation archive (audit-<n>.jsonl, n = entries so far) makes the writer's next append fail in verify_files (every append re-verifies all audit files) -> writer dead. MCP/Web: create it before the call (the arm receipt is the first append of a change). CLI child: created by the serve_bracket/proxy.rs relay hook when the arm passes (a directory present at startup would fail AuditLog::spawn instead). CLI dead-writer refusal is unreachable (no append before the arm in a one-shot process).
- Gotchas: a workspace test run compiles test binaries late; editing tests while it compiles contaminates the baseline (happened to tests/cli; reran cli on pristine files). git pathspec 'crates/*/src' matches no file: use $(ls -d crates/*/src). FaultInjection disconnect_* sets connection_lost for every later request, so the disarm of a lost row is never recorded. A refused arm (NotSent) leaves the fake's timer off although kcc reports it may be armed. Mutation 'drop the CLI batch recovery note' survives: the CLI prints the same headline again on its error path. Mutation 'reads count as changes' is not caught by the Web mixed test (CLI and MCP catch it).
- Counts: workspace 1428 -> 1416 passed (removed 20, added 8). Bracket files 2552 -> 1967 lines (-585); without the 219 lines of the three new dead-writer files 1748 (-804).

### Deletion ledger (removed test -> remaining test that covers the same scenario)
| # | removed (file::name) | covered by (file::name) |
|---|---|---|
| 1 | kcc/tests/cli/bracket.rs::management_bracket_with_write_only_role | kcc/tests/cli/permission_gates/curated.rs::curated_wifi_and_segment_changes_bracket_writers_both_modes (Read+Write role, curated management change, both modes, exit 0, first arm/last disarm) + kcc-domain/tests/bracket.rs::a_write_only_role_runs_a_whole_bracket |
| 2 | kcc/tests/cli/bracket.rs::management_bracket_disarm_failure_reports_applied | kcc/tests/cli/bracket_failures.rs::a_failed_bracket_names_the_timer_fate row (router, services port, "no system" refused: MANAGEMENT_DISARM_FAILED, exit 6, audit flag, port applied) |
| 3 | kcc/tests/cli/bracket.rs::wifi_disable_brackets_both_modes | kcc/tests/cli/permission_gates/curated.rs::curated_wifi_and_segment_changes_bracket_writers_both_modes (same `wifi enable --ap WifiMaster0/AccessPoint0 off`, both modes, first arm/last disarm) |
| 4 | kcc/tests/cli/bracket.rs::vpn_and_wan_management_changes_bracket_both_modes | kcc/tests/cli/bracket.rs::curated_management_commands_bracket (same vpn delete / wan priority, extender edges); router mechanism: kcc-domain configuration.rs::tests::decide_follows_the_recovery_table + every router-mode CLI bracket test |
| 5 | kcc/tests/cli/bracket_failures.rs::lost_change_reports_armed | kcc/tests/cli/bracket_failures.rs::a_failed_bracket_names_the_timer_fate row 1 (lost connection: OUTCOME_UNKNOWN, exit 6, flag); extender: kcc-domain bracket.rs::a_failure_says_whether_the_timer_may_still_be_armed (Unknown row, both modes) |
| 6 | kcc/tests/cli/bracket_failures.rs::applied_change_reports_armed | a_failed_bracket_names_the_timer_fate row 2 (same fault and command) |
| 7 | kcc/tests/cli/bracket_failures.rs::refused_change_and_disarm_reports_armed | a_failed_bracket_names_the_timer_fate row 1 (same Unknown key/exit/flag mapping) + kcc-domain bracket.rs Unknown row (work fails, disarm refused) + kcc/tests/cli/interface_refusals.rs::interface_refusals_preserve_armed_outcome (work and disarm refused: OUTCOME_UNKNOWN, exit 6, flag) |
| 8 | kcc/tests/cli/bracket_failures.rs::refused_change_disarmed_preserves_error | a_failed_bracket_names_the_timer_fate row 5 (same `router-users delete unused`, "no " refused once: CLI_ERROR_ROUTER, not armed, no flag) |
| 9 | kcc/tests/cli/bracket_failures.rs::interface_disarm_failure_reports_armed | a_failed_bracket_names_the_timer_fate row 6 (extender, interface security-level, disarm lost: DISARM_FAILED, extender edges, flag) + row 2 (disarm refused) + kcc/tests/cli/interface_refusals.rs (router-mode interface bracket) |
| 10 | kcc/tests/cli/bracket_management_fate.rs::refused_management_item_reports_unknown_armed | kcc/tests/cli/bracket_batch.rs::batch_completion_controls_recovery_message rows (refused, ordinary sibling, armed) plain and `--json`: exit 7, OUTCOME_UNKNOWN, `/error/fail_safe_armed`, `/error/message`, items 0 false / 1 true, flag |
| 11 | kcc-mcp/tests/support/bracket.rs::management_bracket_disarm_failure_reports_applied | kcc-mcp/tests/support/bracket_failures.rs::a_failed_bracket_names_the_timer_fate row 2 (cli_parse port, "no system": management_applied_fail_safe_armed, disarm sent, kcc_config_state unsaved=true) |
| 12 | kcc-mcp/tests/support/bracket_failures.rs::lost_change_reports_armed | a_failed_bracket_names_the_timer_fate row 1 |
| 13 | kcc-mcp/tests/support/bracket_failures.rs::applied_change_reports_armed | a_failed_bracket_names_the_timer_fate row 2 |
| 14 | kcc-mcp/tests/support/bracket_failures.rs::refused_change_and_disarm_reports_armed | row 1 (same code/message/flag) + kcc-domain bracket.rs Unknown row + kcc-mcp/tests/support/interface_refusals.rs::interface_refusals_preserve_armed_outcome |
| 15 | kcc-mcp/tests/support/bracket_failures.rs::refused_change_disarmed_preserves_error | row 5 (router_rejected, no message, not armed) |
| 16 | kcc-mcp/tests/support/bracket_failures.rs::refused_arm_reports_nothing_sent | rows 3 and 4 (management_not_sent_fail_safe_armed / router_rejected + MANAGEMENT_NOT_APPLIED, exactly [arm, disarm] sent, port not applied, flag); extender: kcc-domain bracket.rs NotSent/not-armed rows in both modes |
| 17 | kcc-mcp/tests/support/bracket_failures.rs::interface_disarm_failure_reports_armed | row 6 (extender, kcc_interfaces_write, disarm lost) + row 2 |
| 18 | kcc-mcp/tests/support/bracket_management_fate.rs::refused_management_item_reports_unknown_armed | kcc-mcp/tests/support/bracket_batch.rs::batch_completion_controls_recovery_message row (refused, sibling, armed): outcome_unknown code, responses 0 false / 1 true, message, flag |
| 19 | kcc-web/tests/explorer_pages/bracket.rs::management_bracket_disarm_failure_reports_applied | kcc-web/tests/explorer_pages/bracket.rs::bracket_failure_matrix_retains_recovery row 2 (same fault, CLI console: DISARM_FAILED, port applied) |
| 20 | kcc-web/tests/explorer_pages/bracket_management_fate.rs::refused_management_item_reports_unknown_armed | kcc-web/tests/explorer_pages/bracket_batch.rs::batch_completion_controls_recovery_message row (refused, sibling, armed): OUTCOME_UNKNOWN, injected refusal, flag, outcome failed |
Moved without change of name (kept): MCP bracket_authority.rs::{change_permission_authorizes_the_bracket, viewer_is_refused_before_any_router_request} -> MCP bracket.rs; MCP bracket_management_fate.rs::recovery_mechanism_follows_the_reported_mode -> MCP bracket.rs; CLI bracket_mode.rs::recovery_mechanism_follows_the_reported_mode -> CLI bracket.rs.
Rows dropped inside kept tests: every second-mode iteration of a kept surface test (rawdes x3, MCP authority, batch x3, Web matrix) -> kcc-domain bracket.rs runs every fate in router and extender mode and the surfaces' raw_management_brackets_both_modes run every raw entry point in both modes; mode rows router/extender/none+timer of the three mode tests -> kcc-domain configuration.rs::tests::decide_follows_the_recovery_table + core matrix (`SafetyMode::for_change` over router/extender fakes); Web matrix row "refused change and disarm" -> its row 1 (same key) + core Unknown row.
Named classes kept (surface adds its own assertion): raw_management_brackets_both_modes x3 (each surface's raw entry points incl. CLI `rci delete`, MCP kcc_rci_delete, Web console; only owner of destructive raw shapes' bracket per entry point), namespace_reads_bypass_change_workflow x3 (no confirmation needed: CLI without --yes and exit 0/7, MCP without confirm + responses, Web WEB_EXPLORER_DONE and no unsaved badge), mixed_read_batches_count_only_changes x3 (CLI exit code + CLI_APPLIED*/CLI_BATCH_REFUSED/CLI_MIXED_PERSISTENCE_BEFORE keys, MCP notice MCP_PERSISTS_IMMEDIATELY, Web WEB_EXPLORER_* keys + badge; core counting owned by kcc-app/tests/workflow/batch_outcomes.rs::mixed_read_batches_count_only_changes), batch_completion_controls_recovery_message x3 (kept as each surface's batch mapping test, one mode, management-fate rows folded in).
Added: CLI bracket.rs::curated_management_commands_bracket, CLI bracket_failures.rs::a_failed_bracket_names_the_timer_fate, MCP bracket_failures.rs::a_failed_bracket_names_the_timer_fate (replacing removed names), dead-writer: CLI bracket_dead_audit.rs::a_writer_dying_after_the_arm_still_disarms, MCP bracket_dead_audit.rs::{a_writer_dying_after_the_arm_still_disarms, a_dead_writer_refuses_the_change_before_any_router_request}, Web bracket_dead_audit.rs::{a_writer_dying_after_the_arm_still_disarms, a_dead_writer_refuses_the_change_before_any_router_request}.
CLI dead-writer refusal: not reachable through the CLI binary. A one-shot `kcc` process's writer can only die on an append, and the first append of a change is the arm's receipt, after the bracket's pre-arm `audit_alive` check; a writer that is already broken at start fails `AuditLog::spawn` before any command runs. The refusal is owned by kcc-domain bracket.rs::an_unheld_request_or_a_dead_audit_writer_arms_nothing and kcc-app tests/workflow.rs::dead_audit_writer_refuses_begin_without_a_router_request, and wired per surface for the long-running MCP and Web surfaces (the new tests).
Counts: removed 20 (CLI 10, MCP 8, Web 2), added 8 (CLI 3, MCP 3, Web 2).

### Mutation checks
| mutation (production edit, reverted) | failing remaining tests |
|---|---|
| M1 kcc-app workflow_batch: every applied item counts as management | CLI/MCP/Web batch_completion_controls_recovery_message |
| M2 kcc-domain recovery::finish_applied: Applied -> Unknown | core a_failure_says_whether_the_timer_may_still_be_armed; CLI+MCP a_failed_bracket_names_the_timer_fate + batch; Web bracket_failure_matrix_retains_recovery + batch |
| M3 kcc cli/rci.rs: bracket only when max risk == Management | CLI raw_management_brackets_both_modes, nested_management_arms_the_same_fail_safe_as_direct |
| M4 kcc cli/rci.rs: read-only batch through the change workflow | CLI namespace_reads_bypass_change_workflow |
| M5 kcc cli/rci.rs: drop the recovery note | none (headline printed again on the error path; replaced by M9) |
| M6 kcc-app workflow_batch: reads count as changes | CLI + MCP mixed_read_batches_count_only_changes (Web does not catch) |
| M7 kcc-domain guarded: ignore a writer that died after the arm | CLI/MCP/Web a_writer_dying_after_the_arm_still_disarms |
| M8 kcc-app AuditLog::is_alive always true | core an_unheld_request_or_a_dead_audit_writer_arms_nothing; MCP/Web a_dead_writer_refuses_the_change_before_any_router_request |
| M9 kcc cli/rci.rs: refused batch returns the recovery failure alone | CLI batch_completion_controls_recovery_message |

## [2026-11-15] Todo 47 progress (worker r47)
### Todo 47 ledger
Inventory (unchanged tree 1746b42): kcc-web tests 24760 lines; kcc-web passed 444 (unit 103 + 22 binaries); html() 7 byte-identical copies (cf5b793ffa) + 2 variants (routing_pages, system_general), form() 8 byte-identical (65d6bbba44) + page_kit (indent) + dashboard/router_credentials (Serializer); explorer_pages/support.rs (366, used by 12 binaries), presets_pages/support.rs (320) and migration_wizard/support.rs (322; 52 differing lines: names, boundary, with_target, post_source file part, request_counts vs backups); inline fixtures dashboard.rs:1-373, admin_pages.rs:1-327, auth.rs:1-172, foundation.rs:1-145.
Router-refusal copies named a_router_refusal_shows_only_what_the_router_said: 7 (system_pages/user_changes, clients_pages/clients, network_pages/{internet_checks,wifi,interfaces}, system_general, dns_vpn_pages/dns) + 1 variant (clients_pages/dhcp ..._of_a_pool_...) + 3 routing_pages/refusals copies of the same contract.
Typed-name tests (post a wrong confirm_name, the contract): 17 (plan says 24: the other confirm_name posters send only the right name as part of another contract: brackets, nested risk, raw management, jobs, recovery, segments delete, components, ...).

Shared support (crates/kcc-web/tests/support/, `#[path = "support/mod.rs"] mod support;` in 22 of 23 binaries; integrations keeps its own fixture):
- mod.rs (thin root), outcome.rs (TestResult), page.rs (html, en, en_with, said, form, text, header_text, cookie_pair, meta_content, router_said, assert_native_post), base.rs (Core: state, accounts, audit log, WebState; Frozen clock; ORIGIN, PASSWORD, Account), build.rs (Setup: accounts, roles, routers, outbound, now, Wiring::{Pages, Wizards, Fleet}; register; pages roles; admin; master_key), web.rs (Fixture + Browser: send/get/post/post_form/post_body/post_multipart/login, handle()/router(id)/request_counts/registry/audit/audited/outcomes/backups/backup_store/directory/state_dir), refusal.rs (Refusal rows + router_refusals), typed_name.rs (TypedName rows + typed_names).
- Parameterized wizard merge: presets_pages/setup.rs and migration_wizard/setup.rs keep only accounts, roles, routers and fixture()/with_faults|with_target_faults/with_mode/with_target over Setup{wiring: Wizards}; post_source(fields, file) -> post_multipart(path, browser, (fields, file)); handle(id) -> router(id); post(&[pairs]) -> post_form; migration backups() -> backup_store().
- dashboard: fleet()/with_outbound() over Setup{wiring: Fleet, now: 0} (credentials sealed in the registry, native posts, 303 login check); admin/auth/foundation build on base::Core.

Removed helpers -> shared: html x9 -> page::html; form x10 -> page::form; en (explorer, config, system_pages, migration) -> page::en; en(key, args) (presets, secret_fields) -> page::en_with; said(locale,key) (clients, dns_vpn, network, system_general, language_switch) -> page::said; said(key) (segments, routing) -> page::en; router_said (clients) -> page::router_said; audited (config, routing, system_pages) -> Fixture::audited; assert_native_post (presets, secret_fields) -> page::assert_native_post; text/header_text/cookie_pair/meta/meta_content/send/get/post/login/handle/registry/audit/state_dir of explorer/presets/migration supports and dashboard/admin/auth/foundation -> page::* and web::Fixture; config_pages sign_in/get/post/same_origin/cookie/meta/Signed -> Fixture::{login,get,post,post_body}; dashboard router_credentials form -> page::form; FrozenClock/FixedClock -> base::Frozen.

Removed or merged tests -> what covers them now:
| # | removed (binary file::name) | covered by (file::name[row]) |
|---|---|---|
| 1 | clients_pages dhcp::a_router_refusal_of_a_pool_shows_what_the_router_said | clients::a_router_refusal_shows_only_what_the_router_said[web.dhcp_pool] |
| 2 | config_pages files::delete_needs_the_router_name | files::typed_names_are_exact[web.config_backup_delete] (+ created, gone from the page) |
| 3 | config_pages safety::roll_back_needs_the_router_name_and_restores_the_saved_configuration | files::typed_names_are_exact[web.config_rollback] (+ rolled-change gone) |
| 4 | network_pages interfaces::a_router_refusal_shows_only_what_the_router_said | internet_checks::a_router_refusal_shows_only_what_the_router_said[web.interface_description] |
| 5 | network_pages wifi::a_router_refusal_shows_only_what_the_router_said | internet_checks::a_router_refusal_shows_only_what_the_router_said[web.wifi_ssid] |
| 6 | network_pages internet_checks::deleting_needs_the_connection_name | internet_checks::typed_names_are_exact[web.wan_delete] (+ created, #page-outcome, gone) |
| 7 | network_pages mesh::a_member_restart_needs_the_router_name | internet_checks::typed_names_are_exact[web.mesh_reboot] (+ router-said list) |
| 8 | page_kit tests::a_typed_name_is_posted_as_confirm_name_and_a_wrong_one_is_refused | network_pages internet_checks::typed_names_are_exact[web.wan_delete] (same /internet/delete route; the driver asserts hidden confirm=yes, confirm_name, hidden object, no field `name`, 422, id=confirm-name-error, nothing sent) |
| 9 | routing_pages refusals::a_route_the_router_refuses_shows_what_the_router_said | refusals::a_router_refusal_shows_only_what_the_router_said[web.routing_route_add] |
| 10 | routing_pages refusals::a_port_forward_the_router_refuses_shows_what_the_router_said | refusals::a_router_refusal_shows_only_what_the_router_said[web.nat_forward_add] |
| 11 | routing_pages refusals::a_firewall_rule_the_router_refuses_shows_what_the_router_said | refusals::a_router_refusal_shows_only_what_the_router_said[web.firewall_rule_add] |
| 12 | system_pages general::factory_reset_needs_the_exact_router_name | general::typed_names_are_exact[web.system_factory_reset] (+ reset button per role, router said) |
| 13 | system_pages storage::eject_needs_the_router_name_and_shows_the_router_refusal | general::typed_names_are_exact[web.storage_eject] (+ unknown medium 404, router said) |
| 14 | system_pages user_changes::tags_change_and_a_delete_needs_the_typed_name (renamed) | user_changes::tags_change_and_kccs_own_login_is_never_deleted (tags, protected admin, nothing sent) + general::typed_names_are_exact[web.router_user_delete] (+ #page-outcome, configured empty) |
Kept names whose body became a table call (same name): clients::a_router_refusal_shows_only_what_the_router_said[web.clients_register], dns::a_router_refusal_shows_only_what_the_router_said[web.dns_record], user_changes::a_router_refusal_shows_only_what_the_router_said[web.router_user_create], system_general tests::a_router_refusal_shows_only_what_the_router_said[web.system_reboot], system_general tests::restart_is_destructive_and_needs_the_router_name[web.system_reboot] (+ no badge, terminal audit target), dns_vpn vpn::a_connection_is_created_switched_and_deleted[web.vpn_delete] (create and switch unchanged; + #page-outcome, row left, router has none), routing policies::an_interface_is_taken_off_and_a_policy_deleted_once_its_name_is_typed[web.routing_policy_delete], explorer guards::destructive_commands_need_the_router_name[web.explorer_execute].
Tables per family: router refusal: clients [web.clients_register, web.dhcp_pool], network [web.wan_priority, web.wifi_ssid, web.interface_description], routing [web.routing_route_add, web.nat_forward_add, web.firewall_rule_add], system_pages [web.router_user_create], system_general [web.system_reboot], dns_vpn [web.dns_record]. Typed name: system_pages [web.system_factory_reset, web.storage_eject, web.router_user_delete], network [web.mesh_reboot, web.wan_delete], config [web.config_backup_delete, web.config_rollback], system_general [web.system_reboot], dns_vpn [web.vpn_delete], routing [web.routing_policy_delete], explorer [web.explorer_execute].
Driver assertions now universal (stronger than some old copies): refusal: 200, WEB_KIT_REJECTED, WEB_EXPLORER_ROUTER_SAID, the fake's refusal text inside the router-said list, request text absent from it, absent markup, no MANAGEMENT_OUTCOME_UNKNOWN_ARMED, rci_error audited, running config unchanged where the row says so (routing, wan priority, wifi, interface, reboot, dns, clients name). Typed name: denied account 403; dialog has hidden confirm=yes, confirm_name, hx-post of the post path, hidden object, no field `name`, title where the row names it, #dialog-content retarget for POST asks; wrong name: 422 for object dialogs, the mismatch message and id=confirm-name-error, running+startup config, backups and (unless the row rereads) request count unchanged, the change not audited; right name: 200, the row's message, audited outcome.
Typed-name tests kept separate (not expressible as a row): admin_pages::the_last_enabled_admin_stays (kcc's own users, admin fixture without routers, last-admin guards); migration_wizard apply_failure::a_refused_setting_stops_the_apply_and_the_rollback_restores_the_router (wizard rollback inside a stopped apply, aria-invalid); segments_page refusals::a_name_that_is_not_the_routers_deletes_nothing (tampered object, two confirmation_mismatch audit entries); segments_page refusals::a_segment_changed_after_its_dialog_opened_is_not_deleted (stale dialog); explorer destructive_management::destructive_management_requests_ask_for_the_name_and_run_inside_the_timer (both modes x raw inputs, fields read from the dialog, bracket lines); config restore::{a_raw_restore_refuses_another_model_before_anything_is_sent, a_backup_of_the_same_model_restores_raw_after_the_router_name} (no wrong name; hardware check). Refusal-like tests kept: explorer execute::router_refusals_show_what_the_router_said (console, no fault injection, item-numbered words), system_pages services::unknown_services_and_router_refusals (404s first).
Counts: kcc-web 444 -> 435 passed: removed 14 test names, added 5 (3 tables, 1 refusal table, 1 rename): 444 - 14 + 5 = 435. Per binary: clients 15->14 (2 tests -> 1 table), config 14->13 (2 -> 1), network 24->21 (5 -> 2), page_kit 3->2 (-1), routing 26->24 (3 -> 1), system_pages 34->33 (2 -> 1; rename keeps count); all other binaries unchanged.
### Mutation checks (reverted; 0 diff lines in crates/kcc-web/src + templates afterwards)
| mutation | failing table rows |
|---|---|
| TypedNameForm::confirmed ignores the object name | web.wan_delete, web.router_user_delete, web.vpn_delete, web.routing_policy_delete ("names are exact") |
| Guard::check accepts any typed router name | web.mesh_reboot, web.system_factory_reset, web.system_reboot, web.config_backup_delete, web.explorer_execute |
| Family::rejected (Changes) says DONE_UNSAVED | web.clients_register, web.wan_priority, web.routing_route_add, web.router_user_create |
| router-said list loses the router's words | web.dns_record, web.system_reboot, web.routing_route_add |
| shared builder: Fleet stops sealing credentials | dashboard: 6 tests (Rci Auth) |
| shared builder: account locale ignored | dashboard russian tests, admin_pages localized field errors |
### Gotchas
- clippy on test support: field_scoped_visibility_modifiers (pub(crate) fields need a narrow #[expect] or private fields), definition_in_module_root (mod.rs may only declare modules: TestResult lives in support/outcome.rs), absolute_paths (3 segments max in use trees too: `crate::setup::fixture()` -> `use crate::setup;` + `setup::fixture()`; header_text takes &str, callers pass `header::X.as_str()`), rest_pattern_accessible_field (no `Core { a, .. }` when other fields are visible), let_underscore_drop (`drop(dir.keep())`).
- htmx logins answer 200 + HX-Redirect, native ones 303: the shared login checks 303 only for the Fleet (native) wiring.
- Router-name dialogs answer a wrong name with 200 (the dialog again); object dialogs (TypedNameForm) with 422. VPN delete, eject, config rollback and policy delete read the router again to answer a wrong name, so their rows set `rereads` (configs, backups and audit still prove nothing changed). The config rollback creates a pre-change backup, so "backup gone" is checked by name, not by count.
- Multi-line refusals (dhcp pool, router user create) apply earlier lines before the refused one: their rows keep `unchanged: false`.
- Sizes: kcc-web tests 24760 -> 23633 lines (-1127; support/ 1113 lines in 8 files). kcc-web 444 -> 435 passed; workspace 1416 -> 1407 passed (1416 - 14 + 5), 7 ignored.
- Still over ~250 pure LOC (pre-existing, smaller now, not split here): dashboard.rs 862, admin_pages.rs 922, foundation.rs 444, auth.rs 268. integrations/ keeps its own fixture (different services: update check, log collector, poller).

## [2026-11-15] Todo 48 progress (r48)
Design: one binary tests/readback.rs (#[path] submodules in tests/readback/: model.rs row model+driver, access.rs, network.rs, system.rs rows, storage.rs own tests). Row = Row::new(name, planner fn returning boxed Send future of Vec<Step{Rci,Cli,Clients}>, Expect::Silent{path,field: Contains|Exact|StartsWith} | Expect::Saved{after: optional fresh-read check}). Two tests drive the table over PROFILES; row name + firmware in every assertion message. The driver stops at the first failing row.
| # | old | new |
|---|---|---|
| 1 | readback_clients::silent_hotspot_policy_names_failed_field | readback.rs::silent_writes_name_the_failed_field[clients.silent_hotspot_policy] (2 steps, one fixture instead of a fresh one per step) |
| 2 | readback_clients::hotspot_policies_are_visible_after_write | readback.rs::applied_writes_are_read_back[clients.hotspot_policies] |
| 3 | readback_keendns::silent_cloud_level_names_failed_field | T1[keendns.silent_cloud_level] |
| 4 | readback_keendns::remote_settings_are_read_back | T2[keendns.remote_settings] |
| 5 | readback_logging::silent_log_server_names_failed_field | T1[logging.silent_server] |
| 6 | readback_logging::logging_settings_are_read_back | T2[logging.settings] (6 steps: enable x3 then disable x3) |
| 7 | readback_mesh::silent_mesh_acquisition_names_failed_field | T1[mesh.silent_acquisition] (Field::Exact "show/mws/member") |
| 8 | readback_mesh::acquired_member_is_visible | T2[mesh.acquired_member] (+ after-check: member listed, change set still held) |
| 9 | readback_ntp::silent_ntp_server_names_failed_field | T1[ntp.silent_server] (path "ntp", Contains "server") |
| 10 | readback_ntp::ntp_settings_are_read_back | T2[ntp.settings] |
| 11 | readback_schedules::silent_schedule_create_names_failed_field | T1[schedules.silent_create] |
| 12 | readback_schedules::created_schedule_is_read_back | T2[schedules.create] (+ after-check: schedule listed) |
| 13 | readback_services::silent_service_toggle_names_failed_field | T1[services.silent_toggle] |
| 14 | readback_services::listener_fields_require_the_requested_values (faulted arm) | T1[services.silent_listener] (Field::StartsWith "/ip/") |
| 14b | readback_services::listener_fields_require_the_requested_values (unfaulted arm) | T2[services.listener] |
| 15 | readback_storage::unavailable_partition_writes_are_refused_without_dispatch | readback.rs storage::unavailable_partition_writes_are_refused_without_dispatch (own test, kept: counts router requests) |
| 16 | readback_storage::eject_requires_the_documented_action_exclusion | readback.rs storage::eject_requires_the_documented_action_exclusion (own test, kept: no write) |
| 17 | readback_users::silent_account_create_names_failed_field | T1[users.silent_account_create] |
| 18 | readback_users::account_and_tags_are_visible_after_write | T2[users.account_and_tags] (+ after-check: account gone) |
| 19 | readback_vpn_servers::silent_vpn_service_names_failed_field | T1[vpn_servers.silent_service] |
| 20 | readback_vpn_servers::vpn_server_settings_are_read_back | T2[vpn_servers.settings] |
| 21 | readback_vpn_servers::crypto_map_settings_are_read_back | T2[vpn_servers.crypto_map] (V4_3 DNS change asserted refused_by_catalog inside the planner) |
| 22 | readback_wan::silent_wan_create_names_failed_field | T1[wan.silent_create] |
| 23 | readback_wan::silent_wan_addressing_and_delete_name_failed_field | T1[wan.silent_addressing_and_delete] (3 steps, each must fail) |
| 24 | profile_coverage::every_domain_suite_iterates_both_firmware_profiles | profile_coverage::every_domain_suite_iterates_the_firmware_profiles (renamed; tokenised check) + new profile_coverage::the_profile_list_matches_the_fake_router_lines |
Table rows: 22 (11 silent no-op rows, 11 applied rows). Own tests: 2 (storage).
Sizes (wc -l): before readback_*.rs 855 (profile_coverage 85) -> after readback.rs 54 + readback/{access 190, model 154, network 213, storage 56, system 123} = 790 (profile_coverage 183). Largest pure LOC: network.rs 190, access.rs 167, model.rs 113.
Counts: kcc-domain 156 -> 138 = 156 - 23 old read-back tests + 4 (2 table tests + 2 storage) + 1 (new profile_coverage test). Expected workspace 1407 -> 1389 (1407 - 18; not run). Real kcc-domain total 138 (sum of per-binary results of the final run).
Mutations (all reverted, empty src diff, binary green): drop verification in system::plan_post -> ntp.silent_server; logging::change_request -> logging.silent_server; services::change_request -> services.silent_toggle; router_users::change_request -> users.silent_account_create; keendns::change_request -> keendns.silent_cloud_level; vpn_servers::plan_change -> vpn_servers.silent_service. Mutations need drop(x); Vec::new() (unused/never-used lints are errors in the lib).
profile_coverage: guard compiles support (mod support;) and checks PROFILES + UNPROFILED(V5_0, documented) == Model::Kn1811.firmware_lines(); suite source check strips comments and string literals and requires the whole token PROFILES after 'in' or before .iter()/.into_iter(). Demonstrated failing for: PROFILES without V5_1; scratch suite w/o PROFILES; suite mentioning it only in comment/string. Gotchas: root test file modules resolve relative to tests/, so submodules use #[path] (precedent verification_coverage.rs); clippy needs Row private fields + const fn new, 'ctx lifetime names, boxed futures must be Send (future_not_send).
Counts: kcc-domain 156 -> 138; expected workspace 1407 -> 1389.

## [2026-11-15] Todo 49 progress (r49)
Inventory per part (full list in .omo/evidence/task-49-kcc-review-remediation.log):
- (b) 20 unconditional stderr prints in 13 test files (kcc-mcp support curated_bracket/raw_management/runtime_bracket + src write/common/tests.rs funnel, kcc-web services/firewall_bind/explorer raw_management/destructive_management(+single_stake), kcc cli runtime_management/permission_gates raw_management/preset_finish, docs/config_keys.rs eprintln). All printed after their assertions: deleted; the funnel's command list moved into the `missing` assertion message; now-unused io imports, a `clippy::use_debug` expectation in 4 files (format args in writeln! only) and one empty `#![expect(reason)]` removed. Plan-named bracket sites (cli/bracket.rs, bracket_batch.rs, mcp support/bracket.rs, web explorer bracket.rs) no longer exist (todos 46/47). Kept: kcc-app jobs_recovery.rs println!("{id}") is child-process IPC. (b) grep is empty.
- (a) deleted 6 mock-echo tests (domain_fixtures x4, fake_router spawn_and_shutdown, diagnostic_process_kinds_complete_with_distinct_replies); kept bridge_membership_text_agrees_with_show_rc and every protocol/fault/projection test.
- (c) rewritten to keys: kcc-web auth.rs (3), admin_pages.rs (16 pins in 6 tests, full messages with args: audit intact count = audit lines, broken value = seq of the tampered entry), presets guards.rs (en_with version/value from Firmware titles), src/pages.rs unit test. Non-localized error text -> exit code + machine token: serve.rs lock (exit 1 + state path), stdio role (exit 1 + "nosuchrole"), stdio disabled (exit 10 + "mcp.stdio_enabled"), non-loopback (exit 1 + "server.listen_addr"); kcc-web auth.rs Config::validate -> ConfigError::Invalid { field: "server.listen_addr" }; cli_domain_writes/admin.rs firewall rule absent -> exit 4 + no write.
- (d) vpn_credentials.rs / vpn_secrets.rs: markers "<head>\n<tail>" built at run time (process id), both halves must be absent from Display+Debug, plus DomainError::Validation. Demonstrated: a mutation putting the JSON-encoded secret into the catalog issue (newline escaped as \n) is caught by the new check and would pass the old contains("invalid\ncredential"). state.rs: master key Debug checked against byte list, lower hex, upper hex and base64.
- (e) shared tests/support/settle.rs in kcc-telemetry (yield_now loop on the exact state, paused clock never advances while yielding, 5 s real-time bound via std Instant). metrics.rs rig: settle(light_rounds >= 1) + one yield (the publish queued the exporter follower); cadence test: settle(rounds >= 5) after the 134 s sleep. exporter_follow.rs: every 1 s / 1 ms sleep replaced by settle on keenetic_up{router} 1, watched() == [a], the flag in the scrape, the gauge value; WEB_SESSIONS_INTERVAL sleep kept (time under test) + settle. poller.rs: 135 s and 31 s sleeps kept (cadence), then a bounded yield loop until 5 rounds. timeout(5s, changed()) kept. Gotcha: exports(router) is already true while keenetic_up{router} is 0 (watched, no data yet); settle on `keenetic_up{router="x"} 1`.
- (f) the UsbLte0/UsbModem0/Ethernet<n>/WifiMaster0/WifiStation0 rows never existed in bridge_members.rs (BACKLOG F2-N77 proposed adding them); existing rows use documented-prefix names and stay. Added ONE unit test kcc-migrate src/interface_names.rs tests::names_follow_the_documented_shapes (prefix and shape rules; no WifiStation verdict, that stays an owner decision).
- (g) the fake's CLI engine kept `up` and `down` as two leaves in first-insertion order and a rewrite kept its position: `up, down, up` projected `down` (red recorded). Fix in kcc-testkit src/cli_engine/engine.rs (the projection cannot see write order): writing one removes the other. Test kcc-testkit src/projection/interface.rs tests::the_last_up_or_down_wins (6 orders). No consumer broke (3 workspace runs green).
Mutations (all reverted by re-editing, src diff back to the intended changes): M1 login key, M2 last-admin key, M3 preset args swapped, M4 non-loopback check off (auth.rs + serve.rs), M5 serve ignores the lock, M6 unknown stdio role -> admin, M7 FirewallRuleAbsent -> exit 6, M8 stdio_enabled check skipped, D1 secret in catalog issue (vpn_credentials + vpn_secrets), D3 hex Debug of the master key, E1 poller publishes None, E2 rounds not counted: every rewritten test fails; E1/E2 fail in 5.0 s (bound), none hangs. Gotcha: M8 let the disabled-stdio child create crates/kcc/state (relative state dir, cwd = crate dir); removed.
Counts: baseline 1389 -> 1385 (-6 deleted, +2 added); workspace green 3x (1385/0/7 each); `cargo test -p kcc-telemetry -p kcc-app` 3x 166 passed; 20x loops of 8 rewritten-wait tests 160/160.
Findings for the owner: (1) kcc serve/stdio refusals are untyped English ServerError strings (lock held, unknown stdio role, non-loopback TLS via ConfigError Display) - no key, no distinct exit code beyond 1; (2) the CLI prints DomainError::FirewallRuleAbsent as its English Display under exit 4 (not localized, no machine handle); (3) waits outside the named files still sleep: kcc-telemetry/tests/logs.rs:239,257,290,292, kcc/tests/metrics_serve/runtime.rs:249 (real-time 500 ms poll loop), kcc-web dashboard.rs:249,251, explorer_pages/bracket_ordinary.rs:54, bracket_budget.rs:39, preset/wizard_finish_recovery.rs; (4) serve.rs stdio tests run the child with the crate dir as cwd, so a regression writes state into the source tree; (5) metrics.rs is 261 pure LOC (251 before), admin_pages.rs 954 (922 before): pre-existing over the ceiling.

## [2026-11-15] Todo 50 progress
- Added `[workspace.dependencies]` (32 external crates used by >= 2 members, alphabetical, highest existing requirement each: serde_json 1.0.154, tokio 1.54.1, toml 1.2.0, md-5 0.11.0, sha2 0.11.1, thiserror 2.0.17, url 2.5.8, rcgen 0.14.10, tracing-subscriber 0.3.23). Members use `{ workspace = true[, features = [..]] }`; kcc-* path deps and single-member crates untouched.
- default-features: a member cannot re-enable what the workspace entry disables, so any crate that some member sets `default-features = false` carries it in the workspace entry (argon2, askama, axum, base64, clap, rcgen, reqwest, rustls, tower, tracing, tracing-subscriber). Members that relied on defaults list them explicitly: argon2 (kcc-app: alloc,getrandom,password-hash), base64 (std,simd-unsafe) in config/domain/rci/testkit/web, tracing (std,attributes) kcc-domain dev, tracing-subscriber (smallvec,fmt,ansi,tracing-log,std) kcc-domain/kcc-web dev.
- Proof: Cargo.lock byte-identical (cmp); resolve ids and resolved features identical; per-dependency effective feature closure identical (only `req` and declared-feature spelling differ). Snapshot script pattern: `cargo metadata --locked`, compute feature closure from each package's `features` map.
- G1 all green incl. per-library default-feature clippy/test, MSRV build, deny, audit (`--db ~/.cargo/audit-advisory-db`), vet (Vetting Succeeded), machete, taplo. Tool-call gotcha: several tool calls in one message run in parallel, so never batch `sleep` polls.

## [2026-11-15] Todo 51 progress (r51)
- BACKLOG ledger (27 bullets): 22 closed, 5 carried. Closed by todos: 32-34 (literal Web risk; one residual line carried for dns_checks.rs:82), 46 (+9/12) dead-writer tests, 13/46 interface armed report, 14 MCP rollback code, 25 permission wording, 9-12 refused arm/disarm wording, 16 audit_pending + bounded waits + login 5 s, 26 busy router, 27 membership, 27/28 wizard review and numeric ports, 12 mutant tests + unowned key, 29 empty preview, 24 CLI tense, 17 finish budget, 49 fake up/down. Carried: interface-name heuristic, max_concurrent_requests, serve exit lag, slow-header timeout, cosmetic items. Full table with file:line proof in `.omo/evidence/task-51-kcc-review-remediation.log`.
- New `docs/BACKLOG.md`: 39 plain-language items under Not proven on hardware / Upstream / Known gaps / Decisions kept on purpose / Cleanup / Tests. Process notes (weak red evidence of todos 7, 23, 25) and owner-facing disclosures left out on purpose.
- Docs: ARCHITECTURE gained "The shared bracket seam" (replaced a stale management_permissions paragraph); SECURITY raw-MCP/management wording fixed for D-Q1; CONFIG env-override sentence narrowed. CHANGELOG: Changed/Fixed additions, new Security and Upgrade notes sections. UPSTREAM: file already existed at docs/rust-guidelines/UPSTREAM.md; item 3 expanded and the overlay link fixed.
- Labels: plan grep 26 -> 0 (DESIGN.md headings, app.css, restore.rs, BEHAVIOUR.md). Wide grep: reworded todo/R-labels in FTL group comments (6 locales), DESIGN.md, BEHAVIOUR.md, rules.toml, app.css, a few Rust doc comments, live-e2e.sh. Left on purpose: `.omo/evidence/task-NN-...` strings in live tests and docs (functional file names, and AGENTS.md documents that convention).
- Not done: no hardware claims were added; the GET /rci/system/reboot 404 question is carried verbatim from the plan with no code reference.

## F2 r1 (2026-11-15)
- cargo-mutants on this workspace: `CARGO_BUILD_WARNINGS=warn` is not enough, because `[workspace.lints]` reaches rustc as `--deny=unused` and body-replacement mutants become unviable. Use `RUSTFLAGS=--cap-lints=warn` (env only).
- Restoring a mutated copy with `git archive | tar -x` keeps the old commit mtime, so cargo reuses the mutated artifact: `touch` the restored files before any control run.

## [2026-11-15] Final wave round 1 backlog
Backlog now has 52 top-level items (was 39). Added under Known gaps, Cleanup, Tests; merged 1 into the golden-page item. Skipped: F1 B1, B2, B3, B5 (covered), B6; F3 B12 kept as one Tests line.
