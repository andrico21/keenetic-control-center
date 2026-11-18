# decisions - kcc-review-fixes (append only)

## [2026-11-15] Orchestration set-up
- Plan committed at 2099cd4 (plan, draft, review evidence). Boulder work kcc-review-fixes-ea2f0150 active; ledger goal entry written.
- Merge flow: worktree wt/rN from master, patch (git diff --binary master wt/rN) applied with `git apply --index` in the main checkout, G0 gate on the main target, one commit per todo. The main checkout is used for integration because tracked .omo state files cannot be committed from a side worktree without conflicts; every product diff is reviewed before it is applied. Disclosed.
- Capacity: at most 2 concurrent cargo builds (workers use CARGO_BUILD_JOBS=2); a gate counts as one build.
- Wave 1 first dispatch: todos 1 (H2) and 6 (masker seam). Next in the file-disjoint queue: 2, 3, then 4 (after 3), 5 (after 1), 7 (after 6).

## [2026-11-16] Todo 6
- Secret-name rule = union of MCP substrings + `passphrase` + Web exact names (`key`,`pin`,`community`) + suffix `_key`, after lowercasing and `-`->`_`. `authtoken`, `radiussecret`, `macpasswd`, `wpa-psk` fall out of the substring parts.
- C-04: `Interface.extra.authentication` is reduced to presence (`{name: true}`) rather than dropped, because the Web AP rows read password presence from it; every `ns3` member is dropped.
- `secrets::redact` keeps `Token::Ns3` with a `<redacted>` payload (shows `ns3 <redacted>`); `mask::redacted_config` prints the bare `<redacted>` word (download/backup/CLI form). Both are byte-identical to the deleted copies' output.

## [2026-11-16] Todos 1 and 6 reviewed; gate fx1 running on the combined tree
- Todo 6 behaviour changes to name in the commit body: MCP masks names ending `_key`/`-key` (so a WireGuard `public_key`/`public-key` member is masked on MCP; this follows from the plan's rule "Web is_secret with - and _ normalised" and is the safe direction); a secret member holding an object is replaced whole on the Web too; interface reads keep an `authentication` presence map and drop ns3 members; secrets::redact now masks every ns3 payload itself; anonymizer relies on redact for ns3 (still called first).
- Todo 7 is dispatched on a temporary base (commit 8953c9d = master + 1 + 6) so it sees the shared masker; its patch is applied after the fx1 commits land.

## [2026-11-16] Todos 3 and 5 committed (b57d6e9, 59a18c4); workers 4 and 8 started
- Workers r4 and r8 are cut from the temporary base 258998a = master 757b48b + todos 3 and 5; that tree equals master 59a18c4 on product paths. Their patches MUST be generated with `git diff --binary 258998a wt/rN -- <product paths>` (never against master with a different base).
- Golden HTML baseline: to be captured on master after todo 8 lands and before todo 10 starts (no template changed in todos 1-7).

## [2026-11-16] Todo 8 split (decision)
- Worker r8 finished C-07 and D-15 (ValidatedRequest.value read-only, ChangeOp.commands/push) and found B-08 (strict CliCommand::new binding line<->request through the catalog grammar) not shippable: it refuses real lines of ~33 command paths (request shapes that do not encode the line, e.g. `access-list rule N disable` with {index}; leading-group and argument-spelling gaps; cleanup lines `no ip policy X` paired with an unrelated request). Inventory in .omo/evidence/task-8-kcc-review-fixes-b08-attempt.log.
- Decision: B-08 is NOT dropped. Todo 8 is committed as the immutability part once the KeenDNS host-name regression is fixed (follow-up worker 8c in the same worktree); B-08 gets its own deep-high worker scheduled after todo 41 (catalog typed arguments and grammar fixes overlap) and its own commit; the todo 8 checkbox is ticked only when B-08 is closed. The funnel 8 -> 9/10 -> 11 -> 12 is not blocked on B-08: todo 9 uses CliCommand::new for word validation, not grammar binding. To be disclosed to the owner as a plan deviation (a todo closed in two commits).

## [2026-11-16] Commits 9eedbb7 (todo 8 part 1), b7e853d (todo 9), 95a9b4f (todo 10); B-08 dispatched early
- Gate fx5 (todos 8, 9, 10 together) was green except one test: the anonymizer guard flagged a MAC in the todo 8 follow-up test (`02:00:5e:...`), fixed by a quick worker to `02:00:00:00:53:43` and re-verified (no_secrets, fmt). Committed per todo from three patches (r8 vs 258998a, r9/r10 vs 58b76e9, applied with --3way for the shared CHANGELOG hunks); product tree equals the gated tree.
- Todo 8 stays unticked: B-08 (strict CliCommand::new binding) runs now as its own deep-high worker (wt/r8b, base 95a9b4f) because the capacity is idle and only todo 11 -> 12 is unblocked; it will land as its own commit and then tick todo 8.
- Dependency note: the matrix funnels everything through 12 (13 and 20 both need it); after 11 only 12 can run, then W3 fans out.

## [2026-11-16] Todo 8 part B-08 (wt/r8b) design
- One binding check, in kcc-catalog (`ValidatedRequest::renders_cli`, shared grammar with `validate_cli`), called by the only two literal constructors `CliCommand::new`/`secret` (now fallible, `SecretCommandError::Line`, new variant: no existing one says "line does not render its request"). No unchecked constructor.
- Drift is fixed at the planner by pairing each line with the request that describes it (segments carry a create and a delete request per step; `interface down`; static lease `{host, ip}`; firewall `new-index`), or by rendering the documented form (IPv6 route interface-before-gateway, DNS filter-profile description). Grammar gaps are fixed at the catalog source (generator bare-word promotion, `catalog/synopsis-errata.json`) or in the one shared matcher (leading group, keyword-subsequence parent, repeated synopsis lines, `a:b` join, `no` + positive form).
- `interface vlan-id` exists only as an erratum; migration keeps refusing `vlan-id` lines to keep its behaviour (owner decision to change).

## [2026-11-16] Commits e623772 (todo 11) and 034ec91 (todo 8 part B / B-08); todo 8 ticked
- Gate fx6 was green except one test again: the repository guard flagged an RFC1918 literal in the prose "reason" of catalog/synopsis-errata.json (a quote of the manual's example). A small worker reworded the string (the generator never reads `reason`), no_secrets 2 passed. Lesson for later worker prompts: workers' targeted checks skip kcc-testkit's no_secrets guard, so every worker prompt now says "no IP literals except RFC 5737, MACs 02:00:00:00:XX:YY, also in prose, JSON and docs" (kcc-agent-rules.md updated).
- Not proven on hardware (for the final report / BACKLOG): the ipv6 route argument order (interface before gateway), `ip route` metric on 4.3, `<address> <port>` vs `<address>:<port>` for `system log server` and `wireguard peer endpoint`, `interface down`, the `vlan-id` line, the new fqdn-typed `ip http proxy upstream` host name.

## [2026-11-16] Todo 16 (wt/r16)
- Compare-and-set token: sealed hash + disabled must equal the snapshot's; failure_count/lockout_until are re-read under the lock and the step is re-applied to them instead of failing the CAS and re-running Argon2 (a strict 4-field CAS would cost O(N^2) Argon2 runs under N simultaneous failures). A hash change restarts the sign-in (re-read, re-verify), at most 3 times, then Invalid without counting.
- The gate also covers password hashing (create, reset, own change), not only verification: one place, same 19 MiB cost.
- `update_if_changed` is used by sign-in and by `create` (duplicate name); other admin paths (administer/set_locale/reset on a missing account) still write unconditionally (authenticated, rare; not in the findings' scope).
- `web-admin-user-you` values were edited in place to include the parentheses (6 lines) instead of appending a new key, because the old key would become unused and i18n-check rejects unused keys.

## [2026-11-16] Todo 29 (wt/r29): audit page scope = filter, not fleet-wide
- SEC1-08 decided as a FILTER: `page` and `export` drop an entry whose `router` is not in the viewer role's `router_scope` (`scope_matches`); an entry without a router is shown only to a role scoped to all routers (empty scope or a `*` glob). Fleet-wide ViewAudit was rejected because a role scoped to router A would otherwise read router B's actions, targets and parameters. Documented in docs/SECURITY.md (Audit chain) and docs/USER_GUIDE.md.
- Cache (W1-08): one slot in `WebState` (`admin_audit::log::LogCache`), key = (path, length, mtime) of every file `kcc_app::audit::chain_files` lists (rotated archives + active file), captured BEFORE the read, so an append during a read can only cause one extra re-read, never a stale answer. A broken chain is cached as broken; an unreadable log is not cached. Cached value is the whole verified `Arc<Log>` (entries included), so a hit does no I/O besides the stat calls. New public fn `kcc_app::audit::chain_files` (list of chain files in order) avoids duplicating the file discovery in kcc-web.
- Known limit: a same-length rewrite inside one filesystem mtime tick is not seen (ext4 tick ~ms); any append changes the length, and tampering that keeps both length and mtime needs write access to the state dir.

## [2026-11-16] Todo 30 (wt/r30) decisions
- E-08 MCP success entries use action `mcp.<tool>` (same action as the tool's failure entries), outcome `success`, params ids only (backup: target = backup name; preset capture: {id, groups[, transient]}; preset delete: {id}, no router; job cancel: target = job kind, {id}, router = job router; diagnostic start: target = catalog path, {id}). Web and CLI disagree with each other on names (`web.config_backup_create` vs `cli.backup_create`, `web.preset_capture` vs `cli.preset.capture`, outcomes `success` vs `ok`), so "the same name as Web/CLI" has no single answer; pairing success and failure of one tool under one action is the queryable choice. Helper `support::audit::Success` (submit + settle(AUDIT_WAIT), result noted `audit_pending`; a failed append is logged, the action stands). Transient preset captures are audited too (params `transient: true`).
- E-09: the id is minted in `support::call::finish_with_context` (moved out of shape.rs with `finish`/`answer`, shape.rs stayed under the size ceiling) BEFORE the work, which now arrives as an unawaited future; the work runs inside `tracing::info_span!("mcp_tool", request_id = %id, tool)` and a `tokio::task_local!` REQUEST_ID scope. `KccMcp::begin_change` (the only MCP ChangeSet entry point: raw_change, curated writes, config save, component commit) passes it with `ChangeSet::with_request_id`, so router.change entries carry `mcp-...`. Spawned job tasks are outside the task-local (their later entries keep their own ids). The span is INFO level: with a log filter above info the span (and the id) is not printed.
- E-24 segments: no single receipt; new `ChangeSet::queued_audit() -> Vec<Pending>` (clones of the still-queued receipts) returned from the closure and checked after `apply` returns (after a bracket's settle), via `common::noting_queued`. VPN secrets: `client_secrets::apply` / `apply_ike_psk` now return `CliChangeResult` (critic correction); Web and CLI callers ignore it as before.
- N2: `batch::completion` now takes (item, accepted) pairs (shared by apply_batch and apply_cli); `Completion::refusal_params()` shared. A multi-line CLI change with a refused line writes `router.change_cli` (or `_terminal`) with the partial outcome only when at least one line was accepted; a fully refused one stays unaudited by the workflow (front ends audit the failure, as before).
- W2-10: `Services` now carries `&WebState`; `Visit::open` audits the Forbidden branch as `F::RUN` (`web.migrate_run` / `web.preset_run`, new `Flow::RUN`), router = first router outside the Migrate scope, target = run id. finish: 409 -> `Attempt::Refused{reason:"conflict"}`, 500 (no server owner) -> `Attempt::Failed{error:"internal"}` on the choice's own action. W2-03: "done" appended before `end` (binding row).
- F-13: one `Ctx::authorize_audited(services, perms, routers) -> Outcome<Role>`; authorize_recovery, authorize_apply and target_named now use it too (no behaviour change there).

## [2026-11-16] Todo 31 (wt/r31) decisions
- B-02: `check_conflict` = checksum only against `expected` (baseline, refreshed after each of kcc's own writes). The begin-time `last_read` check is deleted with the parameter (N1); `ensure_unchanged` is now equivalent to `check_conflict` minus `force`.
- C-02: new `ChangeSet::apply_recovery(CliChangeRequest)` (module `workflow_recovery.rs`): authorize(permission, router scope) kept, conflict check and backup skipped, accepts only requests whose every command is a recovery-timer path (fail-safe timer, keep-alive, rollback, system reboot). It reads last-change before sending without refusing: unchanged -> the state afterwards becomes `expected` (a failed read is no error of the step); changed or unreadable -> `expected` is kept, so the foreign change still refuses later writes/saves of the set. `SafetyNet::disarm`/`keep_alive` use it; the arm keeps `apply_cli`.
- Rollback also goes through the recovery path (close.rs `Close::Rollback`, Web standalone rollback in config_page/safety.rs): a rollback does at once what the armed timer does anyway, so a conflict refusal protects nothing. Forced by B-02: without it the migration/MCP rollback after a foreign drift (kcc-mcp `drifted_commit_remains_retryable_by_rollback`, kcc-migrate `commit_refuses_post_verification_drift`) was refused.
- `guarded` runs `ChangeSet::prepare(permission)` (the former private `prepare_cli`, now public) after the audit/hold checks and before entering the count and arming; a refusal there is `recovery::refused` (fate None, sent false = management-not-applied), nothing sent. `arm_failed` keeps its meaning for an arm that failed after its preflight. Cost: one extra `show last-change` read per bracket (the arm's own preflight re-checks; backup is cached).
- Not changed: kcc-migrate `Stop::arm` still sends a (now always sendable) disarm after a locally refused arm; result Workflow when accepted.

## [2026-11-16] Todo 33 (wt/r33) decisions
- E-03 binding row followed: no cross-identity finish; MCP finishing stays owner-only. The lease timeout is `Applier::recovery_left()` (kcc-migrate, shared): `safety_seconds + 1 - (now - armed_at)` on the apply's clock. Web: a per-apply expiry task (`wizard/expiry.rs`) ends an unfinished run as `ROLLED_BACK_BY_ROUTER` and frees the claim; MCP: per-record expiry task closes the record (applier dropped, report kept).
- MCP retention: a record without a lease (unapplied plan, closed record) is kept 1 hour; at most 64 unapplied plans (oldest forgotten first); eviction runs in `Migrations::record` (the only insert). New `Phase::Applying` mark (guard `Applying`) keeps a plan from eviction while its apply runs; a second apply of the same plan, or a new plan on a target with a running apply, answers `conflict` early (before, the second apply hit RouterBusy at the workflow lease).
- E-06: map is a `std::sync::Mutex<BTreeMap<String, Arc<Entry>>>` (never held across await); each `Entry` has its own `tokio::sync::Mutex<Migration>`; a phase readable without the record lock serves the conflict check and eviction.
- W5-01: busy is still checked before the reads (`held_by_other`, keeps the existing "busy" outcome when another run holds the target), the real reservation (`Claim` guard) is taken after the reads, then `brackets::hold()`, then `Applier::start`; the claim is disarmed right after the job started (the settler owns it from then; a failed record save after the start no longer frees the target while the job runs). `hold()` false answers 500 audited `failed`.
- W2-02/W5-12: `Visit::open` loads and checks the owner before `wizards.session(id)`, then takes the turn and reads again. Eviction past 64 skips any session with `Arc::strong_count > 1`, a locked turn, or a live apply; with none idle, the list grows (bounded by sessions in use).
- W5-06: per-wizard owner index (`index-wizard.json`, `index-preset.json` under `<state>/migrations/`), entered before the record's first write, validated against records on every list, rebuilt by a scan (<= 4096 dirs) when missing/unreadable; process-wide mutex around read-modify-write. Last change = record file mtime. Cap 10 unfinished runs per owner and wizard changed within a day (refusal 422 `Outcome::failed`, key `web-wizard-runs-limit`, audited `refused` with `reason: "limit"`); sweep deletes runs unchanged for 30 days, run from both wizards' landing pages (migrate GET /ui/migrate; presets GET /ui/copy, GET /ui/presets/{id}/apply, POST /ui/copy via `saved::sweep`). The copy-run sealed-parts discard now loads only runs that still have a sealed part.

## [2026-11-16] Todo 32 (wt/r32) decisions
- C-03 (binding row: refuse): `guarded` checks `changes.baseline().fail_safe["active"] == true` after `audit_alive` and before `hold`/`prepare`; refusal = `recovery::timer_in_use(WorkflowError::RecoveryTimerInUse)` -> `Fate::TimerInUse`, fate None, message key `management-timer-in-use` (new, six locales). `management-not-applied` ("timer is off") would be false there, hence the new fate. Scheduled reboots are not visible in `show last-change`, so a reboot an operator scheduled is still not detected (issues.md).
- C-21: new `WorkflowError::Unowned` (hold false; Web pre-check uses it too, `Said::Unowned` unchanged). Arm-failure path: when `settle_audit` fails, the audit error becomes the failure's source (the doc invariant "a writer that failed meanwhile is the bracket's failure"); fate still from the disarm.
- Front-end mapping: MCP RecoveryTimerInUse -> `conflict`, Unowned -> `internal`; CLI RecoveryTimerInUse -> exit 5 Conflict headlined `management-timer-in-use`, Unowned -> Generic; Web RecoveryTimerInUse -> audit id `conflict`, Unowned -> `web-bracket-unowned` "failed". No new MCP code, no schema change.
- C-15: close(Save, Router) = commit only; `Failure::committed` removed. kcc-migrate commit mapping `(None, true) => CommittedSaveFailed` folded (unreachable); the variant stays for stored records. CLI `closing.rs` `(Save, true, false)` arm is now unreachable but left (no behaviour).
- G-05 (binding row: FinishFailed): new `armed_context` in finish.rs maps ensure_unchanged and detect failures of commit and keep_unsaved to FinishFailed; rollback's detect failure too.
- C-11: job reads `show components pending` before the commit; waits with `tokio::time::timeout(15 min)` probing every 1 s for a failed probe (progress 60) then a successful one; compares staged installs/removals with `RouterInfo::components`. Fake: `FaultInjection::components_commit_answers(n)` (answers n `show version` probes after the commit before the reboot window) and `components_commit_discards(true)`.

## [2026-11-16] Todo 34 (wt/r34): wizard secrets
- One rule for "abandoned": the run record unchanged for `retention::ABANDONED_AFTER` (1 day, file mtime), for every origin. `retention::sweep` (already run from both landing pages) now also deletes the sealed parts (source, copied settings, passwords) of every run past that age, and keeps the run. The copy-only sweep in `presets_page/saved.rs` (age = created_at + 1 day) and `TRANSIENT_SECONDS` are gone: a copy run in active use no longer loses its settings a day after its start, only a day after its last change. `PresetRun::preset` refuses a copy run's settings when `retention::idle`, so an old copy run is refused before any sweep.
- `Finishing::discard` default now deletes all three sealed parts (`retention::forget_secrets`); both wizards use the default (finish, settle Close, expiry). The presets override and `saved::discard` were deleted; `Store::sealed` had no user left and was deleted.
- Deleting is idempotent (`Store::discard` ignores a missing file) and a failure is logged and never fails a finish. Choosing the source/target again (`Visit::forget_passwords`) does fail the request (internal error before the record is saved): silently keeping stale passwords is the bug.
- W5-16: strict. A migration inputs submit must carry `user-N` equal to the server's N-th user, a missing field counts as a mismatch (new key `web-migrate-inputs-password-user`, six locales). The two helpers that post inputs (`flow::to_preview`) and `plan_steps` now send `user-0` as the page does.
- Cost: a migration left idle for a day loses its sealed source; resuming it answers the existing Problem::Source and the user starts again (documented in USER_GUIDE).

## [2026-11-16] Todo 35
- New public variant `RciError::Cancelled` (`#[non_exhaustive]` enum). Exhaustive matches updated: `kcc-rci/src/observe.rs` (RequestOutcome::of -> Transport). The matches in kcc-mcp `map_rci`, kcc-web `rci_failure` and `advanced/deliver`, and kcc `cli/exit.rs` already end in a wildcard or list variants without Cancelled-specific meaning; none needed an edit (the compiler accepted all). Cancelled only comes from `Handle::poll` with a caller token.
- `RciClient::logout()` is public (main-session sign-out, used by the read pool). Primary-credential clients are still not logged out at shutdown (out of the todo's scope).

## [2026-11-17] Todo 36
- B-21: `BackupStore::list` unchanged in shape (skips unreadable files, one warn per file per scan, file name only); new `BackupStore::listing` returns `BackupListing { backups, unreadable }`. CLI/Web/MCP surfaces do not show the count (would need an i18n key in six locales plus per-surface plumbing); the warning log is the report. Unreadable files are never moved or deleted.
- B-09: per-record `job-<id>.lock` dropped; `JobOwnership::discard` removes `job-owner-<id>.lock` (only when it can take the lock) when a finished record is pruned.
- B-10: final-write failure logged (`job`, `error_kind`); the record stays Running so the next start still reports the job interrupted (not changed, only made visible).
- B-19: `JobRunner::start(kind, JobTarget, work)`; all callers updated.

## [2026-11-17] Todo 37 (wt/r37; B-07, W2-08, W5-05, G-22)
- One helper per crate over `spawn_blocking`: kcc-app `blocking::run(place, work)` (JoinError -> `StateError::Io { path: place }`, so every kcc-app error with `From<StateError>` keeps its variants), kcc-web `blocking::run(work, failed)` (JoinError logged, -> `failed(io::Error)`: `StoreError::Io`, `PresetError::Io`), kcc-mcp `support::blocking::run` (-> `Internal`, logged). A panic in store code becomes that error instead of unwinding the request task.
- Wizard `Store` (binding W5-05 row): async methods over `Store::run(|files| ..)`; the sync bodies are `wizard/store/files.rs::Files` (index.rs and retention's internals use `&Files` inside the closure). `save`/`save_named` serialize on the async side and move bytes; `seal`/`open` move `key.duplicate()` and a `SecretString` clone (both zeroize on drop). `Store::root`/`Store::delete` removed (only `Files` needs them). `retention::{may_start, idle, forget_secrets, sweep}`, `Finishing::discard`, `PresetRun::preset`, `Migration::seal_source`, `Visit::{save, passwords, forget_passwords, seal_passwords}`, the SSE `Ending` (now returns a `BoxFuture`) and the panels that read became async.
- PresetStore keeps its sync API (the CLI runs one command); Web reaches it through `presets_page::saved::{list, get, load_for_apply, delete, capture}`, MCP through `Presets::stored(work)`. `get_for_apply` deleted (Web now calls `load_for_apply`; identical body). `list` skips and logs every unreadable record, I/O errors included.
- Registry `transition(.., replacement: Option<Credentials>)` takes the credentials by value (moved into the blocking closure, no plain-String copy); the profile is cloned under the std read lock and inserted under the write lock after the write, with the tokio `clients` lock held across, as before.
- Jobs: `start` writes the initial record before it fills the `active`/`write_jobs` maps (both tokio locks still held across the write), so a dropped start leaks no slot; `recover` reads/marks/writes one record per blocking call, keeping the per-record order write -> probe -> audit.

## [2026-11-17] Todo 38 (wt/r38; C-19, W4-13, W4-07, W2-07, W5-11)
- C-19: `diagnostics::POLL_INTERVAL` = 500 ms (public const, the only place); tests that run the production path pause the tokio clock (kcc-domain dev-dependency gains the existing tokio feature `test-util`).
- W4-13: shared poller per router (`system_pages/log_poller.rs`, `PolledLogs` in `WebState`); the page's one-off tail also goes through it (a lone page view starts and, on drop, aborts a poller after one read; with open streams it is served from their window, at most 5 s old). `PollingLog` is gone.
- W4-07: caps keyed by username, per user: 8 downloads, 32 explorer job slots; over the cap only that user's own oldest (finished, for jobs) goes. No global cap, no refusal, no new i18n key. Slot end is signalled by a drop guard (`Ended`) created before `jobs.start`, so even a dropped job future frees its slot for eviction.
- W2-07: `BackupInfo.size` (plaintext bytes) derived from `SealedSecret::plaintext_len` (ciphertext length minus the 16-byte tag), no format change. The decrypting `store::sizes` helper is deleted; the page shows a size even for a backup that no longer opens (it used to show none).
- W5-11: only `decide` was quadratic (per shown index a scan of the form); `request::last`, `plan.rs` unchanged (they are not form-size dependent).

## [2026-11-17] Todo 39
- `Options::max_argon2_iterations` defaults to 16 in kcc-rci too (same as the `[outbound] argon2_max_iterations` default), so a manager built without the registry is capped as well. Range 1..=64 enforced in `Manager::with_auth` (Validation) and at config load (`Config::from_toml_str`, `ConfigError::Invalid { field: "outbound.argon2_max_iterations" }`).
- The range message is an English `ConfigError::Invalid` reason like every other config validation message (none of them is a kcc-i18n key), so no i18n key was added.
- A malformed refresh of the session cookie is ignored (the current cookie stays); the next 401 re-authenticates. kcc-rci has no tracing dependency, so it is not logged; adding one was out of scope.
- Digest: the stored challenge is reused when the nonce matches (nonce only, as the plan says); any other nonce replaces it.
- The fixture's digest verifier now accepts any nonce count not accepted before (RFC 7616 replay check) instead of a strictly increasing one; with two concurrent replays the arrival order of nc 1 and 2 is not fixed.
- The A-02 older-cookie case is a unit test of `Manager::refresh_session` (`session/refresh_tests.rs`): an end-to-end version needs per-login cookie values and a held in-flight request in the fixture. Its red run is a compile failure (the old refresh knows no sent cookie); a mutation check (names-only comparison) shows it fails for the intended reason.

## [2026-11-17] Todo 45 decisions
- G-11 (binding row: naive local time, no router command): `LogRecord::ts` is `NaiveDateTime`; ECS `@timestamp` has no offset (`2026-11-06T12:00:01`); Loki nanoseconds unchanged (Loki has no zone). `parse_records(router, value, now: NaiveDateTime)` uses kcc's UTC clock only for year inference. CHANGELOG "Changed".
- G-10: `parse_records` returns `ParsedLog { entries: Vec<(u64, Option<LogRecord>)>, unnumbered }` so the collector runs malformed ids through the dedupe window too: each malformed record is counted once (`sink="collector",reason="parse"`), not once per poll. `ParseError::Id` removed (unused).
- G-24: `level` word -> error (error, critical) | warning | info | debug | other; the short-label fallback is unchanged.
- G-08/G-09: two tokens per sink worker (`Stop { flush, abort }`); abort fires at the 10 s flush deadline; every send and retry wait is raced against it (biased), counts in-flight + queued as `reason="shutdown"`. Retries stay unbounded while running (at-least-once, documented). Client timeouts: connect 5 s (as kcc-rci), request 30 s; Bulk reply cap 8 MiB -> `BulkError::Response`. `BulkError::is_retriable` is no longer `const` (delegates to `DeliveryError::is_retriable`).
- G-13: per-record one-request length (includes envelope + stream header) + 1 separator, summed: an upper bound of the grouped request; `Pending::take`/`restore_front` (keeps the bound, counts overflow). New private modules `batch.rs`, `destination.rs` (Sink moved out of pipeline_delivery.rs to stay under 250 LOC), `sink_http.rs` (shared client builder + capped reader).
- G-12: `rest()` selects every collector sleep with cancellation; `runtime::Service::shutdown` spawns all collector shutdowns into a `JoinSet`. BACKLOG entry rewritten as traced (not re-measured on a kcc serve process).

## [2026-11-17] Todo 40 (wt/r40; A-03, A-04, A-05, A-12, A-16, A-17, A-19)
- Public API changes (name in the commit body): `RciClient::batch`/`parse_batch` now return `Result<Vec<Result<RciResponse, RciError>>, kcc_rci::engine::batch::BatchError>` (new `#[non_exhaustive]` error: `completed` answers of the chunks before the failure + `error`; `From<BatchError> for RciError`). Consumers updated: kcc-app `ChangeSet::apply_batch` (audits completed chunks), `dispatch_cli` (completed lines + the error as the next line's answer, so `send_cli`'s partial audit covers it), `workflow_replay` (RciError::from); kcc-mcp `generic/rci.rs` read batch, kcc-web `advanced/deliver.rs` `read_batch`, kcc `cli/rci.rs` read batch (all map the inner error as before).
- Removed: `RciClientOptions::stop_on_error`, `Manager::connect`, `Manager::connect_with_options` (tests moved to new `kcc_testkit::outbound::{connect_manager, connect_manager_with_options}`; the kcc-rci unit test builds its manager inline), `kcc_catalog::validate::validate_value` (crate-private; runtime calls `validate_node`), the unreachable let-else in `config_text::write_node` (now writes through a private Display adapter and propagates `fmt::Result`).
- New public items: `kcc_rci::auth_options::{ARGON2_MEMORY_KIB, ARGON2_ITERATIONS}`, `kcc_rci::engine::DEFAULT_RESPONSE_BYTES`, `kcc_rci::budget::DEFAULT_CONCURRENCY`, `kcc_rci::engine::batch` module; testkit `FaultInjection::{show_get_not_allowed, short_batch_reply}`.
- Behaviour changes: show fallback POSTs the query (as a JSON object of strings) and also falls back on 405; only a 405 or a query-less 404 marks the path POST-only; a cached POST answered 404/405 unmarks it. A batch reply of the wrong length is `Decode`. A later-chunk failure of `apply_batch` writes `router.change_batch` with a partial (or failed) outcome and params `{error:"request_failed", succeeded, failed, unanswered}` when any answered item succeeded, then returns the error (an audit failure wins). Status items: level from `status` only, unknown/non-string level = Error, code/ident/message string-or-number, missing = "". Observer: bootstrap and background sessions report logins; batch chunks, config download/upload, detect, auth probe, is_bootstrap and background start/next/stop report requests; is_bootstrap takes a permit. `RciClient::detect` reads with the client's `response_bytes` (was a fixed 8 MiB; same default).
- Request helper: `engine::admit::Admission` (take = permit; report = observer + release) instead of a closure-taking helper: passing the exchange future into a helper doubled the size of the detect future (clippy `large_futures` on kcc-mcp tool futures).
- No i18n key added (no new user-visible string). No test expectation of an existing test changed.
## Todo 42 decision: reused InvalidIndent (width 0 marks non-space leading whitespace) instead of a new variant; no cross-crate matches changed (kcc-web upload_check ignores fields).

## [2026-11-17] Todo 41 (wt/r41; A-08, A-11, A-20, N9, E-22)
- Risk floors live only in `ValidatedRequest::capture`: DELETE and unvalidated lines are Destructive. `interface_node_risk` became `whole_interface_change -> bool` (adds the Management floor + `contains_management` for whole-interface create/remove); it no longer derives Destructive from the method or `no`.
- E-22 resolved by classification (plan alternative), not by an overlay deviation: the overlay's deviation list never named the escape, so it is unchanged. MCP effect: the unvalidated line now also needs the `Destructive` permission (allow_destructive + confirm were already required because raw_change treats Management like Destructive for the switch). Web console effect: `Destructive` permission added to the needed set, and the dialog becomes destructive-management (router name typed) instead of a plain confirm. `kcc` CLI never sends unvalidated lines (no raw authorization), migration/presets use `RawAuthorization::default()`: no change.
- N9 was already done by todo 8 (B-08): no generator/catalog change; reproducibility proven (5.1, 5.0, 4.3: zero generated diff); typed coverage row added to `typing_tests::network_cases`, mutation-checked against a temporarily untyped 5.1 shard.
- A-20: `Boolean` (a generator ValueType never emitted today) is not mapped by the runtime, so a future Boolean argument fails the load; `Ipv6Address`/`Mask` stay accepted aliases.

## [2026-11-17] Todo 43 decisions (r43)
- Truncation keeps only an allowlist of scalars (not every scalar): `error message field unsaved persists_immediately audit_pending request_id applied rebooting factory_reset job_id status`; the largest array is cut by binary search to the longest prefix that fits; the byte cap stays a hard ceiling.
- `next_cursor` on a cut result: only for tools whose input schema has `cursor` (routers_list, catalog_search, migration plan/report pages); = offset + kept items; absent when no item fits or no cursor input.
- `fields` now comes from the parsed INPUT (FailureContext.with_input), applied after masking and pseudonymization to object items of top-level arrays (`statuses` exempt). A `fields` member inside a RESULT is no longer a projection.
- `limit` clamp 1..=100 in `catalog_search` and `paginate` (routers_list).
- Schema changes: every curated domain write tool (`schema_with_ops`) gets one `confirm` description (CONFIRM_DOC); `kcc_firewall_write` loses `index` and `description` (still invalid_arguments when sent: unknown field). Doc comments "Unused confirmation flag..." replaced on routing, policy, nat, firewall, clients, dhcp, segments, dns inputs.
- Changed test expectation: `oversized_result_returns_truncation_marker` (gates.rs) now expects NO `next_cursor` (the tool has no cursor input) instead of a meaningless "1".
- `docs/MCP_TOOLS.md` unchanged by `cargo xtask gen-tool-docs` (it lists no schemas).

## [2026-11-17] Todo 44
- Pseudonym width 64 bits (16 hex): output of std SipHash `hash_one`; a collision merges two labels only; one hash, no second independent hash needed for a home-sized client set. Shared helper lives in kcc-app (both kcc-mcp and kcc-telemetry already depend on it; no new dependency edge, no new crate).
- Pseudonym text changes from `client-N` to `client-<16 hex>` (D-NODEPLOY; CHANGELOG line).

## [2026-11-17] Todo 47
- E-14: generic tool metadata is written once in `registry::definitions::generic()`; `#[tool(name = ..)]` carries the join key only; `ToolDescription::tool_annotations()` is shared by `support::route::route` and the generic patch. Routing the generic tools through `route()` was rejected (it changes argument-parse errors and result shaping for every generic tool). ns3 mask duplicates were already gone (todo 6): `backups.rs`, `config_text`/kcc-web all call `kcc_config::mask::redacted_config`.
- E-10: 123 `missing_errors_doc` hits fixed with `# Errors` sections instead of 123 expects.

## [2026-11-17] Todo 46
- G-16: `kcc_metrics_series_dropped` gauge (per router, Presence PerClient) = series dropped at the latest scrape; the `Shared.dropped` map is deleted. G-18: `keenetic_interface_up{router,interface,type}` + new `keenetic_interface_info{router,interface,description}` (always 1, emitted for every interface with an id). G-19: `JobFollower` (private, `instrumentation/job_follow.rs`) re-reads every counted job from `JobRunner::get` on `Lagged`. Jobs whose only events fell into the lost window and that never reappear are not recoverable (no listing API); the plan asks for the known ids only.
- Dashboard: new target D `keenetic_interface_info` in the "Interface state" table, dropped-series panel renamed expr. No alert rule referenced a changed name.
- Changed test expectation: `per_client_series_are_capped_and_counted` became `per_client_series_are_capped` (the counter assertions moved to the new G-16 test).

## [2026-11-17] Todo 48 (wt/r48; C-08, C-09, W3-04, F-11, C-23)
- F-11 gateway: `kcc dhcp pool --gateway` is REQUIRED (not defaulted to the interface's own address). Why: it matches the Web editor, which already requires it; `--interface` is optional, so an interface-address default would need a second rule for the no-interface case plus a `show interface` read and a guess when the bridge has several addresses. A required flag is one clap rule, refuses before any request, and can never advertise a wrong router.
- F-11 replace: `--lease-seconds`/`--state` lose their clap defaults; a new pool still gets 86400/on, a replace of an existing pool (found with `dhcp::read_pools`, read only when one of them is missing) without them is refused (`cli-dhcp-pool-replace-needs`, exit 2, nothing sent). `--interface`/`--dns` are not required on replace: an omitted one emits no line, so the router keeps its own (critic: the replace resets only lease and state).
- C-09/W3-04: `PoolConfig::dns_servers` is `Option<Vec<Ipv4Addr>>` (None keep, [] clear, [a] set, more refused with `Validation{InvalidValue{field:"dns"}}` in `plan_pool`, the shared seam for CLI/Web/MCP). The clear line is `no ip dhcp pool <name> dns-server` with the batch's ObjectName pool name, as `no ip dhcp pool <name> enable`.
- C-23: client and static-lease read-backs became `VerificationSpec`s appended AFTER `verification::complete` (so the running-config presence checks stay). The lease spec checks `{mac}` in `show rc ip dhcp host`; the address is proven by the presence check of the exact `ip dhcp host <mac> <ip>` line (the old code accepted `address` or `ip` as the key, which one Contains spec cannot express). Host specs compare the MAC in lower case (the router's and `Mac`'s form); the old comparison ignored case. `dhcp::apply`/`clients::apply` keep their `(changes, router, operation)` shape (29 call sites, same shape as the other domains) with the router unused.
- kcc-testkit fake: `ip dhcp pool <name> dns-server` is now one setting (minimum 1 leaf word, identity 1 word): a new server replaces the old one and `no ... dns-server` removes it, as on the router.

## [2026-11-17] Todo 49 (wt/r49; D-03, D-05, D-06, D-07, D-10, W3-08)
- D-05: refusal is the existing catalog issue `ValidationIssue::InvalidValue { field: "source-port" | "destination-port" }` (no new i18n key); MCP answers `validation_failed` as before (was via the B-08 line binding), CLI exit 4.
- D-06: `read::configured_rules` (all lists, strict) replaced by `read::configured_list(router, list)` (targeted, tolerant); public API change named in CHANGELOG. The CLI `firewall rule-property` refuses an unstructured rule at the index as FirewallRuleAbsent (as before for any missing rule).
- D-10/W3-08: `plan_order_rule(router, list, &ListedRule, position)` accepts unstructured rules so the Web can still move them (it could before); `ListEntry::listed()` adapts the text reader's entry.
- D-07: documentation only (verify.rs module rustdoc + docs/BACKLOG.md); the VPN client cites stay with todo 51 (another worker owns vpn_clients/).

## [2026-11-17] Todo 51 decisions
- D-11 risk: the plan says keep max(catalog, classified). A plain max drops the fail-safe bracket of a delete that carries management traffic, because the Web (`page_kit/submit/work.rs`), CLI (`cli/change.rs`) and MCP (`write/common.rs`) arm the recovery timer only when `ChangeOp.risk == Risk::Management` (a Destructive risk cannot say "also management"). Implemented: a management verdict keeps `Management` (bracket kept, unchanged behaviour); an ordinary VPN interface delete becomes `Destructive` (needs the Destructive permission and its confirmation). The management case still lacks the Destructive floor; closing it needs the three front ends to read `contains_management` (follow-up outside this todo).
- D-11 refusal reuses `DomainError::Validation { InvalidValue { field: "name" } }` (no new DomainError variant, so lib.rs/workflow_error.rs stay untouched for the parallel todos). An interface the router does not list proceeds (the router rejects it).
- WireGuard ASC on 5.x: `s3 s4 i1..i5` is ONE optional group in the catalog synopsis (9 or 16 values bind; 10-15 do not).

## [2026-11-17] Todo 50 (wt/r50; D-04, D-08, D-09, D-20)
- D-08: the exact-command absence check was already attached to every route removal by `change::request` (`verification::complete` -> ConfigCommandAbsent, read from a fresh running-config download before the audit entry); the fix deletes the table row-count comparison and the table-based restore. Restore set = top-level `ip route`/`ipv6 route` lines of ONE running-config download taken before the removal (text scan, so secrets elsewhere in the config are never parsed). A route using `auto`/`reject` (or any tail the typed model cannot express) is not restorable: it is reported (InvalidResponse) after every other route was restored. `RouteCountMismatch` is kept as the variant for "the exact command is still configured" (Display unchanged, doc reworded).
- D-08 behaviour change: removing a route that is not configured now succeeds (its command is absent), instead of RouteCountMismatch.
- D-09: failed create step is rolled back when the error is `VerificationFailed`, `UndecodableConfig`, `UnexpectedBody`, `Audit`, or a transport/timeout/HTTP/decode `RciError`; NOT for local validation, permission/conflict/backup/lease refusals or a router-reported refusal (`RciError::Rci`), whose delete line could remove pre-existing configuration.
- D-20: a bad record is skipped with `tracing::warn!(line = N, "skipped an invalid segment ownership record")` (no description text, no interface name).

## [2026-11-17] Todo 52 (wt/r52; C-17, D-19, D-13, D-21, D-22, C-18, C-14, C-10)
- C-10: removed rather than mapped to `media partition` (binding row). Removed: MCP `kcc_storage_write` ops `partition_check`/`partition_format` (now `eject` only, description "Eject storage media"; old ops answer `invalid_arguments`), CLI `kcc storage check|format` (StorageWriteCommand gone, `Storage(StorageCommand)`), the hidden Web routes `POST .../storage/check`, `GET|POST .../storage/format` with their handlers, dialog, unused `FormDialog::danger` and four i18n keys (`web-system-storage-check`, `-format`, `-format-title`, `-format-text`, all six locales), domain `MaintenanceAction`/`MaintenanceRequest`/`plan_maintenance` and the `media partition check` action exemption. docs/MCP_TOOLS.md regenerated, USER_GUIDE/FIRMWARE lines updated, CHANGELOG `### Removed` created under Unreleased.
- D-22: the binding row says remove both; `ipv6_rule` left the firewall write inventory, so the kcc CLI exclusion table became empty and was deleted with its coverage branch (`every_registry_write_has_a_subcommand`).
- D-13: the VPN credential walker is deleted (duplicate of kcc-app's ConfigSecret check that already runs inside apply_cli); parsing secrets into `Token` strings was rejected because kcc-app's own evaluator deliberately avoids allocating credentials. Segments compare commands as parsed tokens (`config_tree`).
- C-14: every module-level `missing_errors_doc`/`missing_inline_in_public_items`/`needless_pass_by_value`/`module_name_repetitions` expect and the crate-root `missing_errors_doc` expect removed; also the 12 module-level `cfg_attr(not(test), expect(missing_docs_in_private_items))` (78 private items documented). Kept: `lib.rs` `cfg_attr(test, expect(dead_code_pub_in_binary))` (guideline form), `segments.rs` `pub_use` facade expect (guideline form), test-module expects. 15 item-level `module_name_repetitions` expects (public names used by every front end). `# Errors` sections were generated per function from the error paths in its body and spot-checked.
- C-18: also removed (finding text, beyond the plan's short evidence list) `wifi::ns3_presence`/`Ns3Presence` and the `SafetyNet::commit`/`configuration::save` forwards; `interfaces::apply` lost its unused `router` parameter (6 callers updated).

## Todo 53 (orchestrator decision before dispatch)
- C-22: the before/after marker comparison treats an unchanged marker as a verification failure. An md5 password hash is deterministic, so a same-value rewrite is indistinguishable from an ignored write and is reported as "the stored value did not change"; salted/encrypted ns3 blobs differ per write so a same-secret rewrite passes there. The worker verifies which case applies to each of the three secrets against fixtures. Real-router behaviour for a same-value rewrite is not proven on hardware (backlog).

## [2026-11-17] Todo 53 design (C-22: secret read-back proves the new value), written before coding
- (a) WHERE: a kcc-app mechanism, not domain-only. The domain plans are built long before dispatch (Web previews, MCP confirm,
  CLI), so a plan-time snapshot would be stale and would put secret-derived data into a printable `ChangeOp`. New
  `PresencePredicate::ConfigSecretReplaced` + constructor `VerificationSpec::replaced(prefix)`; `workflow_verify::Baseline::capture`
  runs inside the change workflow right before dispatch (after authorization, conflict check and backup) on all three
  send paths (`apply`, `apply_batch`, `send_cli`), so Web, MCP and CLI all get it through `ChangeSet::apply_cli`.
  It downloads the running configuration ONLY when the request carries such a spec (no extra request elsewhere) and
  keeps it as the `SecretBytes` the RCI client returns (zeroized on drop; no copy of a payload is ever made).
  Baseline read failure: the error is returned BEFORE the write is sent (fail closed; nothing sent, so no audit entry,
  like a failed conflict check). A spec of this kind verified without a captured baseline fails (fail closed).
  Terminal requests skip verification, so they skip the capture too. Audit entry format and hash rule untouched.
- (b) WHAT is compared: the stored credential payload of the line `<prefix> <payload>` in the running configuration
  (the same context-aware line walk the VPN `ConfigSecret` check uses, now shared as `stored(text, prefix) -> Option<&str>`):
  `user <login> password` -> `md5 <hash>`; `interface <ap> authentication wpa-psk` -> the `ns3` blob;
  `interface <wan> authentication password` -> the `ns3` blob. Before and after payloads are borrowed slices of the two
  `SecretBytes` buffers and compared with `subtle::ConstantTimeEq` (workspace dependency already in Cargo.lock, now
  also a kcc-app dependency); only the boolean leaves the function. The error is `VerificationFailed { field: <prefix> }`
  (key-free: login or interface name and command words only). Running config is the source because its real-router
  format is known (anonymizer and migration fixtures: `authentication wpa-psk ns3 ...`, `user X password md5 ...`); the
  `show interface` reply for secrets is NOT known from real hardware (the fake answers `{"ns3":true}` for the PSK, a
  constant for the WAN password), so it cannot prove a change. The existing presence/length specs stay as they are
  (a first-time secret still passes on presence+length; the new spec only adds "and it differs from before, when there
  was a before").
- (c) SAME SECRET: md5 is deterministic and `ns3` (kcc-config `ns3::encode`, the router's NDM Secure v3) is a
  deterministic, unsalted, reversible scrambling: the same plaintext gives the same blob. So all three secrets
  (router user, Wi-Fi PSK, WAN password) behave the same: re-setting the identical value leaves the stored payload
  unchanged and is reported as a verification failure ("reading <prefix> back still shows the old value"). No secret is
  stored salted, so no case passes a same-value rewrite naturally. Documented in USER_GUIDE and CHANGELOG. NOT proven on
  real hardware: whether a real router rewrites the same payload byte for byte (it should, by the algorithm).
- Rejected alternative: a new `WorkflowError::SecretUnchanged` variant. It would need a new Web key, a CLI exit mapping
  and an MCP mapping, while `VerificationFailed` already says exactly this ("still shows the old value") on all surfaces
  and keeps the MCP `verification_failed` code.

## [2026-11-17] Todo 54 decisions
- G-06: management interface = `show interface` entry whose `address` is a pinned address of the RCI client; unknown -> `None`. Verification fails only when the identified interface's link is not `up`; unknown is reported (`ApplyReport.management_interface = None`), Internet is reported (`ApplyReport.internet`) and never fails. Planner/wizard with unknown management treat every bridge's address/security-level line as management (`TargetInventory::may_carry_management`), the conservative direction.
- G-06 inventory reads `show interface` (one extra request); the existing `interface` config read (`interface_inventory`) is unchanged.
- G-15: report JSON shape and `schema_version` 1 unchanged; `to_markdown`/`to_html` take `Locale`. Preset report items: redacted preset line (`kcc_config::mask::redact_text`), or for Mirror removals the redacted command; an unsupported Mirror removal has no stored line, so its `before` is empty. Preset reason ids now map to the existing migrate reason keys (they all rendered as "unsupported" before).
- G-21 drift: kept the preset classifier's behaviour (password always a plain `Word`). The migration copy wrote the plaintext into an `Ns3` token for an ns3-encoded hash (`user admin password plain ns3 replacement`), which `apply::command` would ns3-decode; regression test `encoded_realm_bound_hash_becomes_a_plain_word` was red on that. The shared helper keeps the migration copy's structural guard (`password` + `md5|nt`). `words()` kept the identical body, single copy in `presets::selection`.
- G-23: removed (not wired up): `StopPolicy`, `ApplyOptions::stop_policy`, `PlannedLine::non_critical`, `execute::retry_lines`.
- [todo 61] backup diff over-budget differences are refused (exit 4) instead of falling back to set semantics (fail closed); F-16 is structural per critic, no behavioural test.

## [2026-11-17] Todo 55 decisions (wt/r55)
- W3-05: POST handlers that read before their `Submission` end through `net_change::unread_change(action, &error)` (network pages) or the existing `routing_page::reply::refused(action, unread(..))` (routing, firewall, NAT): audited `unreachable`, outcome region, nothing planned. Dialog GETs answer `net_change::unusable`/`net_change::unread` (no audit, like `net_internet_settings`). No `Action::unread` in page_kit: the two page families already had their own helpers, and page_kit is another todo's area.
- W3-05 tests: `fail_read_matching("show/interface")` also breaks router detection (`kcc_rci::capabilities` reads `/rci/show/interface` by GET, page facts fail -> every request "unreachable" before the handler runs). Tests add `show_requires_post("show/interface")`: detection's GET gets 404 and goes on without the inventory, the domain read falls back to POST, where the read fault hits.
- `route_remove`'s post-wipe `after` read keeps `unwrap_or_default()` (the guard banner then names nothing restored); not a cited site.
- W3-10: `Report` has route-specific variants (`RoutesWiped`, `RouteCountMismatch`) next to `Note`: one typed enum is simpler than a generic report through `Planned`/`Submission`/`Form`.
- W3-11 scope: port check, netmask contiguity, net-pages `TabLink`, `PRIORITY` and segment object names deduplicated. Not done: the five `TabLink` copies in system_pages/admin/dns_vpn (other todos' areas), `said()`/`CLASS` one-liners and the dashboard's netmask->prefix (`network.rs`, not a network page, slightly different empty-address rule).
- W3-14: `AccessPoint::psk_present` is `serde(skip_serializing)` so MCP/CLI JSON output is unchanged.

## [2026-11-17] Todo 57 decisions
- W2-06: `REASON_ROOM` is now the store's own 48 (no copy number follows), so an uploaded file name keeps 41 characters instead of 38 (CHANGELOG). `web-config-backup-taken` removed in all six locales (unused keys fail i18n-check).
- W2-09: one `with_timer(action, Timer::{Running, Idle})` serves commit/rollback (Running) and Save (Idle); Save refused while armed is audited `armed`, answered like the commit's `not_armed` refusal (200 outcome fragment, error tone), new key `web-config-save-armed`.
- W2-12: the wizard's `ask` calls `Guard::Destructive.check`; the only visible change is that `confirm=yes` without a typed name no longer shows the mismatch error (as the kit). No audit was written on a refused confirmation before or after.
- W2-18: `Action::run` refuses a `Change::Batch` before anything is sent (logged error, failure "internal", audited `internal`) instead of running it; `ending::finished` still matches `Applied::Batch` for exhaustiveness (the router-answer enum is shared with the command pages), now unreachable from a domain page.
- W2-14: the two finish-recovery suites became `tests/finish_recovery.rs` + `tests/finish_recovery/wizard.rs` (`Wizard::{Migration, Preset}`), each scenario looping both wizards; the budget test asserts 200 + HX-Redirect to the run and the keep audited `done` after the lock frees.
- W2-16: `table` and its `pager`/`rows` are `pub(crate)`; `#[inline]`/`#[non_exhaustive]` dropped there and on `Rejected`/`Unplanned` (kept `#[must_use]`).

## [2026-11-17] Todo 62 decisions
- F-26: kept `kcc log read` (removed `kcc diagnostics log`) and `kcc wan password` (removed the `ppp` kind of
  `kcc vpn secret`): `wan::plan_password` classifies a management interface and verifies the replaced secret;
  the coverage table maps `VpnClients ppp_password` to `wan password`.
- F-24: the shared label list lives in `kcc_domain::labels::permissions` (kcc-domain already depends on kcc-app
  and kcc-i18n; Permission is `#[non_exhaustive]` cross-crate, so a `match` would need a wildcard). The key array
  is typed `[MessageKey; Permission::ALL.len()]`: a permission added to `ALL` without a label fails to compile.
  kcc-web's `admin_roles::PERMISSIONS` was NOT switched (todos 57-60 edit kcc-web in parallel); follow-up.
- F-20/F-21: `Family<B, W>` deleted; each domain is one clap enum (old base variants, then writes, then secrets,
  so `--help` order is unchanged). Domains whose writes go through a typed planner (dns, vpn) use a private
  `Request` enum (read | import | secret | Change(typed change)) built by an exhaustive `request(command)`.
  Top-level `Command` = `Local(LocalCommand)` (flatten) + Serve + Mcp + Completions + Domain (flatten).
  `domains::run` is one 24-arm match with `#[expect(clippy::cognitive_complexity)]` (a flat dispatch table).
- F-09: `kcc_app::composition::{Core, CoreSetup, CoreError}`; `server.rs` split into server_services,
  server_web, server_metrics, server_reload, server_error (all <= 210 pure LOC).

## [2026-11-17] Todo 58
- W1-16: render the plaintext dialog when the table refresh fails (binding row), not revoke: the key works, and a
  revoke is another write that can fail the same way. The dialog drops the out-of-band table; reload-warning
  toasts are rendered by the dialog itself (no longer inside the region).
- W1-12: `router_form.rs::Draft::from_profile` keeps `RouterTls::Verify | _` (critic: the stricter mode; a form
  label, not an audit value or a privilege). No test can build an unknown variant of a foreign non_exhaustive enum.
- W1-11: an unknown role-form field is refused with a new localized permission error (422 dialog) instead of
  axum's plain-text 422; missing `name`/`scope` now reach the dialog's own field errors.
- admin_users `administer` takes the caller (`&CurrentUser`) for the error page's locale (4 parameters).

## [2026-11-17] Todo 60 decisions
- W5-07: the apply hooks live on a new Flow subtrait `wizard::applying::Applying` (record-end hook `record_end` with a
  default that ends the run; presets override it to record the WireGuard keys) so each wizard's impl sits in its own
  `apply.rs`. Engine: `wizard/apply.rs` (handler), `wizard/launch.rs` (start/settle/watch). Both `launch.rs` deleted.
  Shared helpers moved into `crate::wizard`: `names` (+`map_of`), `source` (Source, source_text, the step-1 panel,
  Field, refuse), `source_read`, `filters`, `passwords::typed`, `screen::fact`, `report::attachment`,
  `analysis::{mode_text, model_text}`. Left: the target-continue handlers (their panels are different types; not in the
  fix text) and the poison-tolerant `lock` copies (not in the fix text; system_pages is todo 59's area).
- `Finishing::discard` became `fn -> impl Future + Send` (the generic settle/expiry spawn needs a Send future).
- W5-08: typed `Reason`/`NeededInput`/`PresetReason` with `#[expect(clippy::exhaustive_enums)]` (not non_exhaustive:
  the wizards must match every variant). Wire names unchanged (plan/report JSON, MCP `reason`). `ClassifiedItem`
  keeps `needed_input: Option<String>` beside the typed `input` because the CLI (off limits) reads it.
- W5-10: the preview/inputs panels return `Result<_, StoreError>` (internal error); apply over unopenable passwords is
  `Failure::Broken` (internal + audit `failed`); reveal: permission check first, read error -> internal + `failed`,
  NotFound -> 404. `Applier::start` error: `ApplyError::Job` stays "busy" (it also covers a busy router), others are
  internal + `failed`.
- W5-15 (binding row): UpdateCache deleted; `UpdateCheck::cached(router) -> (UpdateStatus, bool due)`.

## [2026-11-17] Todo 63
- Signal ends stdio with `Outcome::Ok` (exit 0), the `kcc serve` code after a signal. SIGHUP left at its default for stdio (serve's SIGHUP is an HTTP-transport reload that stdio has no counterpart for).
- Bound the runtime's exit wait for blocking threads to 1 s in `main.rs` (affects every command, but only a blocking thread that outlives the command is affected; before, such a thread hung the exit forever).

## [2026-11-17] Todo 64
- ServerError keeps its English `#[error]` Display (logs/Debug); the CLI localizes it at the one boundary (`server_code` -> `Failure::from(ServerError)`), exhaustive match without wildcard. Wrapping variants stay `Failure::text` (typed error Display of other crates).
- Unsupported `--lang` is now reported in the env locale (KCC_LANG/LC_ALL/LANG, else en) instead of always English. CHANGELOG Fixed line names it.
- `TlsKeyReadable` now renders `errors-secret-file-permissions` in the output locale on the CLI (Display still English for logs).

## [2026-11-17] Todo 56: HtmlSafe marker instead of a `|safe` name allowlist
- Chosen: `markup::Rendered` (private String, only constructor `Rendered::of(&impl Template) -> Result<_, askama::Error>`,
  `request::rendered` = log-and-None wrapper returning Option<Rendered>) implements `askama::filters::HtmlSafe`; child templates
  embedded by a page are marked with `fragment!` (lib.rs; `impl HtmlSafe for T where T: Template`). Every `|safe` is gone (29 in
  templates + 1 inline source). The type decides escaping: a String anywhere is escaped by askama. A name allowlist would let a new
  `String` field that happens to be called `region` through; the marker cannot be put on String (orphan rule) or on a non-template.
- Lint `assets-check` (xtask/src/assets/escaping.rs) rejects any `|safe`, `filter safe`, `escape("none")`/`e("none")`,
  `escape = "none"` in templates and kcc-web sources, and `HtmlSafe` outside crates/kcc-web/src/{markup.rs,lib.rs}.
- Failure semantics kept: child templates still render lazily inside the page (a failing child = 500 page, as before); the String
  producers keep their existing error paths (`errors::internal` for presets/wizard panels, log + None for regions).

## [2026-11-18] Todo 65 decisions
- B-13: one rule set `registry/rules.rs::check` (ProfileFault enum with field()/reason()); `kcc.toml` validation runs it on
  `rules::from_config(profile)` (moved from registry.rs `convert_config_profile`). Merged toward the stricter copy on each
  rule: URL origin shape from the registry (settings only checked the scheme), TLS pin from settings (the registry only
  refused a bad pin at connect). Reason texts name their key, so the registry message is the reason itself (the existing
  `token_file_with_ndw4_names_the_field` expectation is unchanged).
- B-24: new `RegistryError::ConfigRoute { id, url }` (#[non_exhaustive] variant), checked in `transition` before any
  write; a same-URL transition of a kcc.toml router (password change, restore) still rewrites its password_file as
  documented. No i18n key: the text is the error's Display (CLI detail, server log), like `ConfigDefined`; Web maps it to
  the generic check key, workflow wraps it in `WorkflowError::Registry`.
- B-11: module-level `pub_use` facade expect stays in workflow.rs (guideline exception); everything else is item-level or
  fixed in code.

## [2026-11-18] Todo 66 decisions (cancel-safety)
- Login rule (A-18, plan text binding): a sign-in dropped mid-way can leave an orphaned router session -> NOT cancel-safe; every caller that can reach `Manager::exchange` follows. Reach computed exactly with rust-analyzer call hierarchy (`callHierarchy/incomingCalls`, spawn-only call sites excluded): 760 async fns. Consequence: router READS are NOT cancel-safe too (reason text says "it only reads ..., but it may sign in first ..."); `cancel-safe` remains for fns that never reach a sign-in. This conflicts with the plan's other sentence "read-only handlers are cancel-safe"; the specific A-18 rule ("callers follow") was applied. Alternative (one comment change in kcc-rci): declare a dropped sign-in cancel-safe (kcc already abandons router sessions routinely, A-07) - then all reads go back to cancel-safe; the reversal is mechanical with the evidence table.
- 292 existing `cancel-safe:` comments on fns that reach a sign-in were rewritten to `NOT cancel-safe: <login clause>. Apart from that, <old reason>`.
- Audit rule: a queued audit entry may be written after the future is dropped (AuditLog::append, Record::append are NOT) -> callers NOT (dialogs whose refusal is audited, as the wizard code already did).
- "NOT cancel-safe ... but nothing happens" comments (DNS resolution abandoned) flipped to cancel-safe: outbound resolve/client_builder, engine connect_with, registry client/poll_client/connect_client.
- Gate: any visibility; test code rule unchanged (tests/ paths, #[cfg(test)] items and out-of-line test modules skipped, now also `#[path = ...]` test modules and `#[cfg(test)]` followed by a multi-argument attribute).

## [2026-11-18] Todo 67
- T-01: one approach for all five suites: keep a secret with both `"` and `\` and search every sink with `kcc_testkit::leak::contains_secret` (a testkit public fn, so kcc-app and kcc-domain share one owner), not a second quote-free secret.
- T-03: `RequestRecord::command()` kept (last line) so the ~98 consumers, including live_* files owned by todo 68, need no change; `commands()` added for batches. Parse lines are now recorded in `rci_post_root` from the request body (every `parse` item, including one refused by `refuse_batch_pointer` fault injection, which was previously not logged).
- T-04: conversions only documented as assumed in BEHAVIOUR.md (critic: drop "tests check the fake"); md5-vs-HA1 documented, behaviour unchanged. Note: `password md5 <x>` DOES set the fake's HA1 to `<x>` (critic text said it never updates auth); replaying the stored `md5(password)` therefore breaks sign-in on the fake.

## [2026-11-18] Todo 68 decisions
- One shared live gate `crates/kcc/tests/support/live_gate.rs` (`Refusal`, `admission`, `allowlisted`), included by `#[path]` in live_smoke, live_domains, live_migration, live_presets and (cross-crate) kcc-mcp's live_mcp. The per-suite `Refusal` enums of live_domains/gate.rs and live_migration/guard.rs are gone; `WriteMode` became `config: PathBuf` + `write: bool`.
- Every live suite requires `KCC_LIVE_TARGET_CONFIG` with a `test_device = true` profile, read-only runs included (missing variable -> `live-skip:kcc_live_target_config-unset`). No owner exemption recorded in the overlay: rule (g) holds as written.
- The gate's own connection keeps testkit `connect` (lan_policy + the hermetic loopback flag, the existing pattern); everything kcc builds for the suite (child `kcc.toml`, MCP registry, probe login) takes the admitted `[outbound]`. Twins carry `allow_loopback = true` plus `allowed_networks = ["198.51.100.0/24"]`.
- T-09: the probe arms the fail-safe timer itself (after rollback/commit, because a probe write before the applier's finish would trip the workflow's own conflict check), removes the account on every path, disarms only after the removal succeeded, then requires the target-realm control (`ControlRefused` otherwise). Each probe parser line is preceded by a `show identification` read so a session ended by the password change is renewed (parser lines are never replayed after a 401).
- live_presets `rehearse` returns errors instead of asserting on the child's exit codes, so a refused apply is a test-visible `Err`.

## [2026-11-18] Todo 70 decisions (wt/r70)
- X-02: kept `rustup run stable clippy-driver` in lint_completeness.rs (critic: mirrors the vendored core script; orchestrator prompt: drop the sub-claim). The "Alternatives resolved" row asks for sysroot clippy-driver; not done, flagged for the owner. Gates job gets `components: clippy, rust-docs`; lint-completeness is the last step.
- X-04: container.yml's `gates` job runs only for `v*` tag refs (branch pushes/PRs already run ci.yml directly); `push` needs [gates, image], `image` does not wait for gates (keeps PR e2e fast). release.yml's `build` needs [gates, meta]; checksums/release wait transitively. Both caller jobs set `permissions: contents: read`; no secrets passed; ci.yml declares bare `workflow_call:`.
- X-09: VERSION build-arg only on tag refs (non-tag images are never pushed). kcc.container/run.sh keep `:latest` (now always the last stable tag); no hard-coded 0.1.0 exists in them (only the Containerfile ARG default, which stays as the non-tag default).
- X-13: `--check-missing` compares the fully rendered fresh profile (traces + runtime prologue + aarch64 equivalents) against the committed names, so a missing aarch64 equivalent also fails. Comparison code moved to new xtask/src/seccomp_check.rs (seccomp_gen.rs stays near the size ceiling).
[todo 73] web-smoke.sh: chose --env-file on a 0600 file (umask 077 subshell) over `-e WEB_PASSWORD` valueless: the plan text names --env-file. Both files removed in cleanup.
[todo 73] live-e2e.sh cleanup left as is (SIGINT+wait): it has no traced server, only `podman logs -f` children.

## [2026-11-18] Todo 69 part A (r69a) decisions
- Port race (T-07/F-30): no product change. `crates/kcc/tests/support/serve_port.rs` picks free loopback ports and retries a
  start (max 5) whose stderr carries the OS's own address-in-use text (provoked at run time by a second bind on a held port),
  so no wording is pinned. Fixtures write `listen_port` per attempt; base URLs come from the started process.
- Signals: `kill` subprocesses replaced by `rustix::process::kill_process` (rustix `process` is already a unix dependency of kcc)
  in `support/signal.rs`; non-unix returns `Unsupported` (the old `kill` command failed there too).
- F-30 window: the "still running for 3 s" checks became an ordering check on log lines: disarm held until the drain line,
  then at `jobs drained` (logged only after `wait_for_brackets`) the router must already have the disarm.
- T-11: `disallowed-methods` in the root clippy.toml (Command::new/spawn/output/status, CommandExt::exec with allow-invalid);
  kcc tests start processes only through `support/spawning.rs` (2 `#[expect(clippy::disallowed_methods)]` items).

## [2026-11-18] Todo 69 part B (r69b) decisions
- T-10: shared helpers live in the public `kcc_testkit::bracket` module (`Recovery` with the arm/disarm lines, `Fate` with `ALL` and `faults(recovery, work)`), documented in `crates/kcc-testkit/BEHAVIOUR.md` and a CHANGELOG "Changed" line. Web and MCP map every `Fate` with a wildcard arm that fails the test (the enum is `#[non_exhaustive]`), so a new fate breaks each surface's test until it has its row. The batch table stays per surface (critic: per-surface rows are justified).
- T-12: binding alternative "compare the fields, no PartialEq derive": a `#[cfg(test)] impl TableQuery { fn parts() }` (the type had no inherent impl).
- B-23 audit: the caller cannot see the rotation's I/O error (only `WriterUnavailable`), so the test asserts that structured variant and its doc names the setup instead of claiming a rotation failure.
- E-23 random: `internal` stays allowed for change tools: `kcc_config_save` on an unregistered router answers `internal` (production defect, reported in issues.md, not fixed here).
- A-21: the cookie-name pin in `kcc-i18n/src/locale.rs` is kept (critic); the source-grep test is deleted in favour of the `ConfigurationAnswer` type.

## [2026-11-18] Todo 71
- `cargo vet import isrg|zcash` resolved via the registry to divviup/libprio-rs and zcash/rust-ecosystem audits.toml URLs (written by cargo vet, not by hand).
- `cargo vet import` already pruned the 25 newly covered root exemptions; the following `cargo vet prune` removed 0 more (307 -> 282). Nothing added, nothing certified.
- xtask store: `cargo vet init` wrote 127 exemptions (init's own baseline), the six imports covered 24 -> 103 remain; prune removed 0. Same six imports as root.
- getrandom 0.2.17 skip reason now says ring 0.17.14 is its only dependent (via rustls / rustls-webpki / rcgen), from `cargo tree -i getrandom@0.2.17`.
- .taplo.toml also excludes xtask/supply-chain/** (cargo-vet owned, same as supply-chain/**).

## Todos 69, 73, 71, 72 landed (gate fx45, master 04a8b590)
- 69 is ONE commit (6280c5ea): 69a + 69b + the xtask expects (69x) + the other-crates expects (69y). The disallowed-methods lint is carried by 20 item-level expects: 2 in kcc/tests/support/spawning.rs, 8 in xtask, 10 in test files of kcc-app, kcc-rci, kcc-telemetry, kcc-web.
- 71 added no exemption and pruned 25 that the isrg and zcash imports (with the four existing sets) cover; the xtask store has 103 exemptions left (127 after init, 24 crates covered by imports).
- 72: profile-eq compares the root lint tables to the TOML block of the vendored guidelines; the root equals it today, no allowlist needed.
- The four commits were gated as one tree (fx45); the intermediate trees of 69, 73, 71 were not separately gated (batched gates, disclosed).

## Todo 75 landed (gate fx46, master 4f1d45d6)
- sha3 0.12 drops the block-level API: HMAC-SHA3-512 now runs through hmac::SimpleHmac. I verified the output against Python's hmac/hashlib sha3_512 (64-byte and 10/100-byte keys, empty and multi-block messages) because production code and its two fixtures share the primitive, so the handshake tests alone could not catch a wrong block size.
- rand 0.10.4 leaves the cooldown at 2026-11-18 13:54 UTC; a dry run after that shows `Updating rand` (F4 judges IS-13 against todo 75's evidence, as the plan says).
- gate.sh wipes the main target above 45G; the next worker copies a cold target.

## D-DENY (owner decision 2026-11-18, reply "ignore")
- cargo deny failed on RUSTSEC-2026-0542 (humantime) and -0543 (chrono): unmaintained notices, "No safe upgrade". Both crates stay in the tree through upstream (rmcp-server-kit 3.21.1 depends on humantime and humantime-serde directly; chrono comes through rmcp 3.10.0, rmcp-server-kit, schemars and kcc-telemetry), so replacing our own uses cannot clear the advisory; the earlier recommendation to replace humantime was wrong and is withdrawn.
- Decision: a narrow ignore for exactly these two ids in deny.toml and .cargo/audit.toml (the vendored guideline's own mechanism: name the advisory, why it does not apply, whether an upstream fix exists), with a review date; any other advisory still fails the gate. One extra commit outside the plan's todo list.

## [2026-11-18] Undecided management verdict fails closed (worktree r77)
- Seam: `ManagementVerdict::risk` in kcc-domain `interfaces/management.rs`. `Unknown` maps to `Risk::Management`
  for every interface; the `Bridge0` name special case goes (the name parameter with it). `NotManagement` stays Write.
- `classify_direct` is reordered so that "another interface owns kcc's pinned address" decides NotManagement even
  when the target does not exist yet (a connection being created); otherwise every create in a decided topology
  would turn into Management, which the evidence does not support.
- Callers reviewed: every verdict reaches risk through `risk()` (wan `classified`/`plan_dhcp`/`plan_static_address`,
  interfaces `plan_down`/`plan_security_level`, wifi `plan_up(false)`/`plan_schedule`, firewall `interfaces_risk`,
  `classify_generated` for segments and VPN clients, kcc-web wan_password, kcc-web/kcc-mcp/kcc CLI through the
  planners). Fixed `NotManagement` stays where the interface cannot carry kcc yet (`interfaces::plan_up` is always
  Write; kcc-web `net_internet_create` plans DHCP on the connection it is creating). kcc-migrate has its own rule
  (`management::may_carry`) that is not part of this seam: reported, not changed (another worker owns kcc-migrate).
- Fixture strategy: measure first. Step 1: run the affected suites with no fixture change and list what flips.
  Step 2: choose the smallest fixture that makes the normal deployment decided (an interface of the fake owns the
  address kcc reaches it on) and keep explicit undecided fixtures in the new tests. Rejected up front: changing
  `Bridge0`'s fake address to the loopback one (79 test references to its LAN address, DHCP subnet checks), and a
  flag that restores Write (hides the behaviour).

## [2026-11-18] Same-realm typed password and the stopped-run message (worktree r78)
- Planner: a password typed for a router user (`new_passwords`) now wins over copying that user's `password md5|nt` hash even when source and target realms match. The `realm-differs` rule condition matches when the realms differ OR a password was typed for the line's user; the line then becomes `user <name> password plain <typed>` (Remap), exactly as for a foreign realm. Same fix in the preset classifier (`realm_password_user`). Without a typed password the same-realm hash is still copied; for kcc's own login that copy is still refused before anything is sent (`PasswordRequired`, preflight `validate_credentials`), unchanged.
- Root of the misleading "rejected before anything was sent": after the router restored itself (`RolledBackByRouter`, `report.finished`), the CLI finish still called `Applier::rollback`, which refuses a finished run with `ApplyError::Validation` (exit 4). Fix at the shared seam: `finish::rollback` on a run that already failed and was restored (finished + failure) returns Ok without sending anything (the requested end state already holds and was proven by `wait_restored`). Covers CLI migrate apply, CLI preset run, MCP finish rollback and the Web rollback button in one place. A finished successful run (commit/keep) still refuses rollback.
- CLI message: a run that failed during apply now reports its own failure headline plus a localized detail naming how many lines were applied before it stopped and that they were rolled back, with the next step (plan again). Exit code stays the failure's existing family (RolledBackByRouter/Stopped -> 6 router). New key `migrate-apply-stopped-after` in 6 locales.
- Measured (r77, risk fix alone, default fake unchanged): 28 tests flip Write -> Management (kcc-domain 6, kcc-mcp 3,
  kcc-web 13, kcc CLI 6): creating WAN/VPN/WireGuard connections, firewall bindings on ISP, ISP priority/password,
  and an AP outside Bridge0. Cause: kcc reaches the fake on 127.0.0.1, which no fake interface owns.
- Default fake cannot become "decided" cleanly: (1) Bridge0 owning the loopback address breaks LAN logic that reads
  Bridge0's `show interface` address and mask (DHCP `interface_subnet`, segment rows, 79 test references);
  (2) any other default owner flips kcc-migrate, whose tests assert the default fake is the "management interface
  unknown" fixture (planner.rs, inventory.rs, apply_verification.rs) and whose planning then stops treating Bridge0
  lines as management (giga_bridge_address_is_last_management_phase); it would also make the reviewer's undecided
  scenario impossible with the stock `kcc-fake-router` binary.
- Chosen: the default fake stays the explicit undecided fixture. A FakeRouterBuilder opt-in (`reached_directly`)
  lists `Loopback0` owning 127.0.0.1, the address the fake is reached on, i.e. a router reached directly at an
  address of its own. Shared normal-deployment fixtures opt in (kcc-domain support, kcc-web support, kcc CLI lab)
  and the inline builders of the flipping MCP/CLI tests. An explicit `interface` override still replaces the map.
- `classify_direct` also decides a target that is absent from `show interface` (a connection being created) as
  NotManagement once another interface provably owns the pinned address; names are matched against the key, `id` and
  `interface-name` without regard to case so an alias of the owner is still the owner (fails closed).

## [2026-11-18] Stopped run whose rollback is still restarting (worktree r80)
- One pure rule for both CLIs: `stopped_report(failure, applied, rollback_restarting) -> Failure` in `cli/migrate_apply.rs`
  (replaces `stopped_failure`). Order: an armed fate keeps `apply_failure` unchanged; a rollback that came back
  `RollbackRestarting` keeps the failure's exit family and headline but its detail is `migrate-rollback-saved` (the router
  is restarting with its saved configuration, which may already include the migrated settings); only a proven rollback
  says `migrate-apply-stopped-after` (count, "back on its saved configuration"). No new i18n key (smallest fix).
- migrate: the Verification + rollback special case (`migrate-apply-restored`, "restored the startup configuration") is
  also a proven-restore claim, so it applies only when the rollback was not restarting; otherwise `stopped_report`.
- preset: `run.rs` remembers `RollbackRestarting` from the failure-path rollback and passes it to `stopped_report`.
- Red: add `stopped_report` first as a pass-through to the old rule, write the unit tests, capture (b) failing; then fix.
  Scratch CLI reproduction runs in a file copy of the tree (`/home/andrico/r80-scratch`), never in the worktree.

## Final wave outcome (orchestrator, master 47801a5f)
- 75/75 plan todos committed, one commit each (todo 8 has two, todo 69 is one merged commit). F1-F4 are NOT ticked: they wait for the owner's explicit okay.
- Five extra commits outside the plan's todo list (plan edits stay checkbox-only): b457d99a (D-DENY, owner said "ignore"), 0dd10389 (B1), 299dfc04 (B2), ce2f70f5 (non-blocking findings to BACKLOG, one false cancel-safety comment), 47801a5f (B3, a regression of 299dfc04 found by round 2).
- Convergence: round 1 found B1 and B2, round 2 found B3 (frozen list), the confirmation round (F1c2 + F2c on 47801a5f) approved with G1 fully green.
- Known limits stay in docs/BACKLOG.md; not proven on hardware: everything listed in its "Not proven on hardware" section (all live suites are #[ignore]d and were never run against a real router).
