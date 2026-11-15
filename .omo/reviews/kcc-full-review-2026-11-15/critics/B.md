## Lane B critic verdicts (HEAD 349b7fb)

I opened every cited `path:line` myself and re-derived the behaviour from the code. Nothing was edited and no `cargo` was run.

### B-01 ADJUSTED
- checked: `crates/kcc-app/src/audit.rs:34-39,443-472,582-629,711-783`, `audit/writer.rs:40-77`, `audit/append_lock.rs:76-93`, `crates/kcc/src/server.rs:355-371`, `crates/kcc/src/cli/context.rs:294-297`, `docs/SECURITY.md:313-327`, `docs/PRIVACY.md:26`
- reasoning: The mechanism is accurate. `append_locked` calls `audit_files` and then `verify_files`, which parses, hashes and collects every retained entry into a `Vec`, only to use `.last()`. It runs inside `spawn_blocking` while `writer_task` holds the `StateLock` from `locked()`. Startup does the same full pass synchronously, both in `kcc serve` and in every CLI run (`context.rs:294`). `SECURITY.md:315` says appends "re-read its tail", but the code re-reads everything, so the docs promise the cheap design. Pruning only removes complete rotated files older than 365 days, so the cost per append grows with a year of log. "High" depends on inferred figures, though. Reads are not audited: only logins, changes and refusals/failures are (`kcc-mcp/src/support/audit.rs`). Hitting `AUDIT_WAIT` (30 s) per append would take a very large log. The demonstrated consequence is a slowdown that grows over time, plus a growing pause for other processes, not a broken main flow. One aggravating factor: per `SECURITY.md:303`, refusals are audited per call with no MCP rate limit, so a low-privilege key can grow the log on purpose.
- severity: medium
- correction: The O(retained log) append under the cross-process lock is real and contradicts `SECURITY.md:315`. The latency and memory figures are unproven. The fix stays as proposed: read the tail of the newest file under the lock and keep full verification for `verify_chain` and startup.

### B-02 ADJUSTED
- checked: `crates/kcc-app/src/workflow.rs:574-586,672-724,853-867,985-997,1053,1076,1141,1169,1182,1267,1334-1347,1409-1440`, `crates/kcc-app/tests/workflow.rs:84-108`, `crates/kcc-testkit/src/config_state.rs:20-44`, `.omo/plans/keenetic-control-center.md:433`, `crates/kcc-migrate/src/apply/finish.rs:34,63`, all production `begin(` callers
- reasoning: The "both differ" rule is intended, not a typo. Plan step (3) at `.omo/plans/keenetic-control-center.md:433` says "if it changed since the actor's last read **by a different agent**, return `Conflict`". The save/commit wording there is "another agent changed". The code knows about the gap: `ensure_unchanged` (`workflow.rs:854`, "including the same agent") does a checksum-only check, but only the migration finish (`finish.rs:34,63`) uses it. No test or comment states a firmware reason for tolerating same-agent changes. The only test invents `"another-agent"`, and the fake reports `http/rci` for every writer. The impact needs correcting in two ways. First, every production `begin` passes `last_read = None` (`kcc-web/src/save.rs:64`, `page_kit/change.rs:405`, `system_pages/component_commit.rs:83`, `kcc-mcp/src/support/access.rs:113`, `kcc/src/cli/change.rs:220`, `cli/dom_jobs.rs:223`), so the begin-time check at `:692-700` never runs in production. Second, the live gap is `check_conflict` (`:1341`). Inside a set, `expected` is re-read after each of kcc's own writes (`:997,1076,1141`), and the cross-process lease keeps out other kcc writers. So the agent clause can only excuse a non-kcc client that reports the same agent. The window is short (baseline to write, or between writes), and kcc sends individual CLI commands rather than replacing the whole config, so "writes over a configuration it never read" overstates it.
- severity: medium (weakened conflict control; the real-firmware agent strings are unverified)
- correction: This is a plan-mandated rule that does not deliver the README/ARCHITECTURE promise ("refuses if someone else changed the router"). In `check_conflict`, the agent clause protects nothing from kcc's own writes, so use checksum only, as `ensure_unchanged` already does. Separately, the "since the actor's last read" check is unused (see NEW-1).

### B-03 CONFIRMED
- checked: `crates/kcc-app/src/audit.rs:443-451,593-624,750-783`, `audit/writer.rs:1-19,66-75`, `crates/kcc/src/server.rs:365-369`, `crates/kcc/src/cli/context.rs:294-297`, `docs/SECURITY.md:325-327`
- reasoning: `BufReader::lines()` returns a final unterminated fragment as a line. `serde_json::from_str` then fails, and `verify_files` returns `AuditError::Json`. That one path is used by `spawn_with_policy` (serve startup and every CLI services build) and by every `append_locked`, in every process sharing the state directory. A partial `write_all` (ENOSPC) or a crash before the data reaches disk can leave such a fragment. `SECURITY.md:325-327` says log I/O failures end the writer "so its supervisor can restart it". The restart then fails in the same check, so it loops until someone edits `audit.jsonl` by hand. I found no truncation or repair path (no `truncate`/repair in the audit code or CLI). Ending the writer on I/O failure is documented design. Never recovering from crash damage is not.
- severity: medium

### B-04 CONFIRMED
- checked: `crates/kcc-app/src/audit.rs:452,481-496,518-523`, `audit/receipt.rs:1-31,75-113`, `audit/writer.rs:79-104`, `audit/append_lock.rs:24-30,76-93`, `workflow_receipts.rs:1-61`, `crates/kcc-domain/src/configuration/bracket.rs:107-135`, `crates/kcc-web/src/auth.rs:466-495`, `docs/SECURITY.md:329-337`, `docs/ARCHITECTURE.md:118-123`
- reasoning: `submit` awaits `self.sender.reserve()` with no bound. Capacity is 128, and `locked()` retries forever while another process holds the append lock. Once the channel is full, every `submit` waits without limit. That includes `Receipts::record` in deferred mode, inside the bracket's arm, work and disarm, so the disarm can be delayed until the router's own timer fires. It also includes `audit_login`, whose `LOGIN_AUDIT_WAIT` only starts after `submit` returns, and failed-login `append`. `SECURITY.md:332` ("Callers wait for their entry a bounded time") and ARCHITECTURE ("another process holding the audit append lock cannot delay the disarm") both promise the opposite. Reaching the state needs a long-held lock in another process, such as a stopped or stalled CLI, or slow appends (B-01). That is uncommon but realistic.
- severity: medium

### B-05 ADJUSTED
- checked: `crates/kcc-app/src/accounts.rs:340-422`, `crates/kcc-app/src/persist.rs:180-224,240-255`, `crates/kcc-web/src/auth.rs:170-188`, grep for a login rate limit in `crates/kcc-web/src`
- reasoning: `authenticate` runs inside `StateStore::update`. That takes the blocking `users.json` flock, runs Argon2 (the dummy verify for unknown users, the real verify otherwise), and always calls `write_locked`: temp file, fsync, rename, directory sync. It does this even when nothing changed, and even when the closure returns `Err` (for example `DuplicateAccount` in `create`). I found no rate limit on `POST /ui/login`. The result is that unauthenticated attempts serialize every account operation behind one lock and one fsync each. One correction: `has_admin` uses `state.read` and takes no lock (`accounts.rs:429-437`), so it does not queue. The proposed fix also needs a caveat. Running Argon2 outside the lock with no other bound would allow parallel 19 MiB derivations, which is a worse memory DoS. Keep a concurrency bound.
- severity: medium
- correction: Remove `has_admin` from the impact. Fix: skip the write when nothing changed, and move Argon2 out of the file lock but behind a small semaphore.

### B-06 CONFIRMED
- checked: `crates/kcc-app/src/registry.rs:620-655,725-781`, `crates/kcc-app/src/poller.rs:350-357`, `crates/kcc-app/src/poller/extended.rs:70-79`, `crates/kcc-rci/src/engine.rs:255-291`, `crates/kcc-app/src/workflow.rs:701-705`
- reasoning: When `read_login` is set, `poll_client` builds a new `RciClient` on every call. `connect_with` creates a new session with no cookie, and sessions are "reactive" (`kcc-rci/src/session.rs:1`), so the first request signs in again. That happens on every light round (`fetch`) and again on each heavy round (`fetch_heavy`, via `poll_info`). `begin_with_client` (`workflow.rs:704`) also calls `poll_info`, so each change set opens one more read-only session. On ndw4 every sign-in costs a serialized Argon2 derivation (`BACKLOG.md:62`).
- severity: medium

### B-07 ADJUSTED
- checked: `crates/kcc-app/src/workflow.rs:1349-1384`, `crates/kcc-app/src/registry.rs:330-370,515-530,600-638`, `crates/kcc-app/src/jobs.rs:400-480,511-530,597-608`, `crates/kcc-app/src/persist.rs:206-255`, `crates/kcc-app/src/backups/store.rs:80-115`, `docs/rust-guidelines/RUST_GUIDELINES.md:1110-1125`
- reasoning: The calls are real. Blocking `flock`, fsync and rename run directly in async functions, which breaks §5 "DON'T: Call blocking I/O in async functions". `client()` holds the Tokio `clients` mutex across `connect_client(...).await`, and per the engine's own comment that includes synchronous DNS resolution. However, every cited flock guards a short critical section: a backup seal and write, a `routers.json` update, a job record write. The claim that a handful of waiting writes freezes all async work assumes long holds that nothing shown here produces. The DNS stall only affects hostname URLs.
- severity: low
- correction: This is a guideline violation with small, bounded stalls. Keep the fix (`spawn_blocking` for the store calls, and connect outside the `clients` lock).

### B-08 ADJUSTED
- checked: `crates/kcc-app/src/workflow_cli/command.rs:38-160`, `crates/kcc-app/src/workflow_replay.rs:60-90`, `crates/kcc-app/tests/replay.rs:90-112`, `crates/kcc-mcp/src/generic/rci.rs:425-465`, `crates/kcc-web/src/advanced/cli.rs:185-215`, `crates/kcc-migrate/src/apply/command.rs:20-110`, `crates/kcc-domain/src/logging.rs:175-195`, `docs/rust-guidelines/overlays/projects/keenetic-control-center.md:43-45`
- reasoning: The type weakness is real. `CliCommand::new` and `::secret` accept any line next to an unrelated `ValidatedRequest`, and replay validates only the request (the test pairs `Bridge9` with a validation that never saw it). But project rule (b) covers raw input, and every raw path builds the request from the line itself: MCP `validate_cli(&input.line)`, Web `validate_cli`, and the migrate `build` either tokenizes the line or runs `validate_cli` on it. That leaves about 40 domain sites that build the line with `format!` from values validated separately. No drift is shown. So this is a missing type-level guarantee with a hypothetical cost, not a demonstrated rule (b) bypass. The count is about 44 `::new`/`::secret` sites including the raw ones, not 35.
- severity: low

### B-09 ADJUSTED
- checked: `crates/kcc-app/src/jobs.rs:597-656`, `crates/kcc-app/src/jobs/job_ownership.rs:60-91`, `crates/kcc-app/src/persist.rs:240-255,280-292`
- reasoning: Confirmed. `persist` creates `<state>/job-<id>.lock` and ownership creates `job-owner-<id>.lock`. `prune_finished` deletes only `jobs/<id>.json`, and no code removes the lock files. The consequence is zero-byte files that accumulate at the rate operators start jobs. The `read_dir` cost they add to the state root is real but marginal, so this is minor quality, not medium.
- severity: low

### B-10 CONFIRMED
- checked: `crates/kcc-app/src/jobs.rs:452-490,511-596`
- reasoning: `drop(owner.persist(&record))` discards the final-write error with no log. The record stays `Running`. The next start's `recover` sees no live owner, marks it `Interrupted`, probes the router and appends `job.recovered`, all for a job that actually finished.
- severity: low

### B-11 CONFIRMED
- checked: `crates/kcc-app/src/workflow.rs:1-13,1296-1302,1474-1479`, `registry.rs:1-16`, `jobs.rs:1-9`, `poller.rs:1-9`, `backups.rs:1-9`, `docs/rust-guidelines/RUST_GUIDELINES.md:1650,2036-2100`, the project overlay `:101`
- reasoning: The guideline asks for `#[expect]` "on the narrowest item" (`RUST_GUIDELINES.md:1650`; overlay `:101`). The profile's own list of module-level exceptions covers only `pub_use` facades and `float_arithmetic` (`:2087-2100`). `workflow.rs` expects `wildcard_enum_match_arm` and `arithmetic_side_effects` for the whole module, which hides `_ =>` at `:1301` and `other =>` at `:1477`. Note that this is repo-wide: 156 files carry a module-level `#![expect]`. Other lanes probably report the same class.
- severity: low

### B-12 CONFIRMED
- checked: `crates/kcc-app/src/workflow.rs:509-511,701-707,1301,1366-1369,1411-1416`, `crates/kcc-app/src/workflow_verify.rs:150-167`, `crates/kcc-web/src/page_kit/failure.rs:47-55`, `crates/kcc/src/cli/exit.rs:305`
- reasoning: One variant whose text reads "invalid last-change response" covers a missing catalog, a non-UTF-8 config, an unexpected body kind, a running-config parse failure and an `RciPath` build failure. The Web shows a generic localized "failed" and logs the misleading `Display` (`failure.rs:53`). The CLI maps all of these to `Exit::Router`. So the wrong text reaches logs and the exit class, not the page text.
- severity: low

### B-13 ADJUSTED
- checked: `crates/kcc-app/src/settings.rs:640-650,950-1006,1068-1085`, `crates/kcc-app/src/registry.rs:100-134,819-854`, `crates/kcc-app/src/registry/auth.rs:15-31`
- reasoning: Confirmed: there are duplicate validators. Only the registry checks host, path, query and fragment, so `Config::validate` accepts `http://r/x`, and the failure only shows later from `RouterRegistry::new` with a different message. The doc at `:645` (`[A-Za-z0-9._-]`, 1..=64) contradicts the enforced `is_valid_router_id` (1-32, `[a-z0-9-]`). Refuted part: the `auth = auto` plus `token_file` "drift". `convert_config_profile` (`registry.rs:820-823`) maps `Auto` with a token file to `Token` before the registry validates, so both layers accept the same input.
- severity: low
- correction: Drop the auth/token_file claim. Keep the URL-shape gap, the doc mismatch and the duplicated id rule.

### B-14 CONFIRMED
- checked: `crates/kcc-app/src/audit.rs:108-115,423-472,582-597,685-704,785-800,888-904`, `crates/kcc-app/src/persist.rs:674-691`, workspace grep for `with_append_lock_backoff|spawn_with_limit|open_with_retention|light_rounds`
- reasoning: `read_entries` duplicates `read_file` in a loop. `json_error` duplicates `corrupt_json`. The chain fields set at spawn time are overwritten at the top of every `append_locked`. `with_append_lock_backoff` has no caller at all. `spawn_with_limit` and `light_rounds` are only used by tests (`light_rounds` also by `kcc-telemetry` tests). One small correction: `open_with_retention` is also the body of production `JobRunner::open` (`jobs.rs:261`). Only its direct public use is test-only.
- severity: low

### B-15 ADJUSTED
- checked: `crates/kcc-app/src/settings.rs:267-275`, `crates/kcc-app/src/audit.rs:615-620,652-671`, `docs/CONFIG.md:121-124`, `docs/PRIVACY.md:26`
- reasoning: The behaviour is as described, but the user documentation already says it accurately. `CONFIG.md:121` reads "maximum age of complete rotated audit files", and `PRIVACY.md:26` says such files "are pruned after rotation". Only the rustdoc line at `settings.rs:272` is imprecise.
- severity: info
- correction: This is a rustdoc wording fix only. The user docs match the code.

### B-16 ADJUSTED
- checked: `crates/kcc-app/src/registry.rs:950-996`, rmcp-server-kit 3.21.1 `src/rbac.rs:1105-1135`, `crates/kcc-app/src/permissions.rs:185-233`, `crates/kcc-web/src/admin_shared.rs:159-164`, `crates/kcc-web/src/admin_roles.rs:515-525`
- reasoning: The semantics do differ: the kit is case-insensitive and treats an empty list as matching nothing. But the divergence cannot be reached through supported paths. `load_roles` refuses empty scopes for custom roles (`permissions.rs:204`). Web-created globs are limited to `[a-z0-9-*]` (`valid_glob`). Router ids are lowercase-only. The empty-means-all rule only serves `[cli] router_scope`, which never reaches the kit. The `Lab-*` scenario needs a hand-edited `roles.json`.
- severity: info
- correction: Fix the comment. The behavioural impact needs state-file tampering.

### B-17 CONFIRMED
- checked: `crates/kcc-app/src/poller.rs:217-232,244-252,305-348`, `crates/kcc-telemetry/src/metrics/service.rs:91-112,160-180`
- reasoning: `run` reads `receiver_count()` and `metrics`, then awaits `channels.lock()` before removing the entry. `subscribe` can take the lock in between and hand out `sender.subscribe()` from a channel that is about to close. The consequence is worse than stated for metrics: `subscribe_metrics` can lose the same race, and the telemetry `follow` task returns on `changed()` error and never resubscribes. That router's metrics would then stop until it is watched again. The window is narrow (only at the idle timeout).
- severity: low

### B-18 ADJUSTED
- checked: `crates/kcc-app/src/poller.rs:305-306,350-351,437-452`, `crates/kcc-app/src/poller/extended.rs:70-153`, `crates/kcc-app/src/registry.rs:765-767`, `docs/BACKLOG.md:77`
- reasoning: The functions do lack annotations. But `BACKLOG.md:77` already tracks this exact class and its fix ("add the comments and extend the check to `pub(crate)` and private functions"). The finding only adds instances to a known item.
- severity: info
- correction: Treat it as a correction to the BACKLOG list, not a new finding.

### B-19 ADJUSTED
- checked: `crates/kcc-app/src/jobs.rs:396-420`
- reasoning: The code is as quoted. It is only reachable through a programming error (a `write = true` call with no router), and none is shown. It is a type-design nit under §3 "Use enums instead of boolean parameters", with no user-visible cost today.
- severity: info

### B-20 ADJUSTED
- checked: `crates/kcc-app/src/workflow.rs:417-445,1022,1097,1215-1223,1330,1397`, `crates/kcc-domain/src/system.rs:198-211`, `crates/kcc-web/src/page_kit/change.rs:433,474`, `crates/kcc/src/cli/change.rs:245`
- reasoning: Request ids are `change-{unix_seconds}`. They collide within a second and are not tied to the front-end request, so that half is confirmed. The receipt half is mostly wrong. `From<CliChangeResult>` does drop `audit`, but reboot and factory-reset callers hold the `&mut ChangeSet` (`system.rs:201-210`), and the front ends report pending entries through `ChangeSet::audit_pending()` (`page_kit/change.rs:433,474`, `cli/change.rs:245`).
- severity: low
- correction: Keep the request-id issue. The dropped field does not stop callers from reporting a pending entry.

### B-21 CONFIRMED
- checked: `crates/kcc-app/src/backups/store.rs:80-125,200-258`, `crates/kcc-app/src/persist.rs:449-468`, `crates/kcc-app/tests/backups.rs:200-233`
- reasoning: One unreadable `.txt` fails `list_unlocked`, and through it `list` and retention. `create` only logs a warning. Reachability is narrower than implied: `write_exclusive` is atomic (temp file, fsync, hard link), so a crash cannot leave a torn record. Only a corrupt or foreign `.txt` placed in the directory triggers it. Once triggered, the effect is permanent.
- severity: low

### B-22 ADJUSTED
- checked: `crates/kcc-app/src/settings/env_overrides.rs:28-150`, commit `0641529` (diff of `settings.rs`)
- reasoning: The split reproduces the pre-refactor order exactly (`normalize_suffixes` sat between the two groups in the deleted code). It keeps which error is reported first when a bad suffix and a later bad variable are both set. On success, the configuration is the same either way. It is a defensible choice that preserves behaviour, not a speculative abstraction.
- severity: info

### B-23 CONFIRMED
- checked: `crates/kcc-app/src/jobs.rs:396-420,805-845`, `crates/kcc-app/src/jobs/job_id.rs:1-70`, `crates/kcc-app/tests/jobs_recovery.rs:200-250`, `tests/audit.rs:311-327`, `tests/workflow.rs:140-150`, `audit.rs:711-783`, `tests/poller.rs:135-165`, `tests/backups.rs:200-233`
- reasoning: Each claim checks out:
  - The cancelled start is dropped at the first `active.lock().await`, before any reservation, so the test cannot fail.
  - Both runners share the pid, timestamp and sequence 1, so `assert_ne` holds only because of the 4 random entropy bytes.
  - The directory named `audit-…0001.jsonl` makes `verify_files` fail (EISDIR on read) before any rotation, so "forced rotation failure" is the wrong name.
  - The poller test spins on `yield_now` against a real-time `Instant`, and this file is not in the `BACKLOG.md:84` list.
  - `tests/backups.rs:231` asserts log prose.
- severity: low

### B-24 CONFIRMED
- checked: `crates/kcc-app/src/registry.rs:322-370,700-725`, `crates/kcc-app/src/registry/stored.rs:31-70`, `crates/kcc-app/src/workflow.rs:908-928`, en `.ftl` grep for `kcc.toml`
- reasoning: For a `kcc.toml` router, `store.update` finds no state entry, so the new URL lives only in memory. `replace_password` deliberately rewrites the operator's `password_file` (documented at `registry.rs:325-327`). Any reload or restart (not only SIGHUP) rebuilds the profile from `kcc.toml` with the old URL, while the file already holds the new password. No message tells the operator to edit `kcc.toml`.
- severity: low

## Summary
- **Confirmed (10):** B-03, B-04, B-06, B-10, B-11, B-12, B-14, B-17, B-21, B-23, B-24.
- **Adjusted (13):** B-01 (high to medium), B-02 (rule is intended; impact narrowed), B-05, B-07 (to low), B-08 (to low), B-09 (to low), B-13, B-15 (to info), B-16 (to info), B-18 (to info, known backlog), B-19 (to info), B-20, B-22 (to info).
- **Refuted:** 0. **Duplicate:** 0.

Correction to the counts above: CONFIRMED is 11 (B-03, B-04, B-06, B-10, B-11, B-12, B-14, B-17, B-21, B-23, B-24), and ADJUSTED is 13. Total 24.

**NEW-1: the "stale read" conflict check never runs in production.** `ChangeWorkflow::begin` only compares against a front end's earlier read when `last_read` is `Some`. Every production caller passes `None`: `crates/kcc-web/src/save.rs:64`, `crates/kcc-web/src/page_kit/change.rs:405`, `crates/kcc-web/src/system_pages/component_commit.rs:83`, `crates/kcc-mcp/src/support/access.rs:113`, `crates/kcc/src/cli/change.rs:220`, `crates/kcc/src/cli/dom_jobs.rs:223`. A change made between a user viewing a page and submitting it is therefore never detected. Plan step (3) and `ARCHITECTURE.md:70` describe that check. Only the within-set `check_conflict` exists, and it compares against a baseline read at `begin`.

**NEW-2: the security docs misdescribe the audit append path.** `docs/SECURITY.md:315,322` says appends "re-read its tail" and that the lock covers "tail verification". The code verifies the whole retained chain on every append (`audit.rs:587-588`), so the docs promise the cheap design that B-01 shows is missing.

**NEW-3: a lost race in the poller can stop a router's metrics for good.** If `subscribe_metrics` loses the B-17 race, the `follow` task returns on the closed receiver and never resubscribes (`crates/kcc-telemetry/src/metrics/service.rs:175-177`). That router's metrics export then stops until the router is unwatched and watched again.