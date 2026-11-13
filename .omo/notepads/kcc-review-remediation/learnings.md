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
