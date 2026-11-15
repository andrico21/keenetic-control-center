I read this as lane B of the read-only review: follow the BRIEF, read `crates/kcc-app/src/**` and its tests, and report findings in the BRIEF format. I'll stop when the report below is delivered.

# Lane B: kcc-app review

The worst problem is in the audit writer. Every append re-reads, re-parses and re-hashes the whole retained audit log under the cross-process lock (B-01). A single torn last line also stops `kcc serve` from starting (B-03). Two of the change-workflow guarantees are weaker than they look: the conflict check misses other RCI clients (B-02), and the "bounded" audit waits stop being bounded once the queue fills (B-04). `CliCommand` does not tie the line it sends to the request it validated (B-08).

### B-01 Every audit append re-reads, re-parses and re-hashes the whole retained log, under the cross-process lock
- severity: high
- kind: bug
- rule: RUST_GUIDELINES.md §4 "DON'T: Clone gratuitously" (scale); the writer design itself
- evidence: `crates/kcc-app/src/audit.rs:582-597`
  ```rust
  fn append_locked(&mut self, event: AuditEvent, _lock: &StateLock) -> ... {
      let files = audit_files(&self.dir)?;
      let verified = verify_files(&files)?;
      let (next_seq, previous_hash) = verified.last().map_or_else(...);
  ```
  `verify_files` (`audit.rs:750-783`) collects every entry of every rotated file plus the active file into one `Vec<AuditEntry>`, only to take `.last()`. `writer.rs:46-57` holds the append `StateLock` for that whole call. `spawn_with_policy` (`audit.rs:444-449`) does the same at startup, synchronously; `crates/kcc/src/server.rs:365` calls it.
- impact: Rotation is 50 MiB and retention is 365 days (`audit.rs:35,39`), so the retained log only grows. Each audited action (login, MCP call, change) costs CPU and a transient allocation proportional to the whole retained log, and blocks every other kcc process sharing the state directory for that time. As the log grows, receipts pass `AUDIT_WAIT` and changes are reported as `audit_pending`. Once 128 entries are queued, B-04 makes callers block. On a small host the per-append allocation can reach hundreds of MB.
- fix: Under the lock, read only the tail of the newest file (seek back to the last newline) to get `seq` and `hash`. Keep full verification for `verify_chain` and startup. Detect rotation by another process with file identity and size checks.
- confidence: high on the mechanism (INFERRED: the memory and time figures, from typical entry sizes)

### B-02 The conflict check needs both checksum and agent to differ, so a change by any other RCI client goes unnoticed
- severity: medium
- kind: bug
- rule: project change-workflow invariant ("refuses if someone else changed the router in between")
- evidence: `crates/kcc-app/src/workflow.rs:692-700` and `:1341`
  ```rust
  && baseline.checksum != previous.checksum
  && baseline.agent != previous.agent
  ...
  if current.checksum != self.expected.checksum && current.agent != self.expected.agent {
  ```
  The fake router reports kcc's own RCI writes with the generic agent `"http/rci"` (`crates/kcc-testkit/src/config_state.rs:42`). The `user` field is read (`workflow.rs:1429`) but never compared. The only test, `stale_read_from_another_agent_conflicts` (`tests/workflow.rs:91-108`), invents `"another-agent"`.
- impact: Any other HTTP RCI client produces the same agent as kcc: another kcc install, a script, or (INFERRED) the router's own web UI, which also talks RCI. If such a client changes the router between kcc's read and its write, the checksum differs but the agent matches, so no `Conflict` is raised and kcc writes over a configuration it never read. The same gap applies between writes inside a change set.
- fix: Compare `checksum` alone against kcc's own last observed state, which already tracks kcc's own writes. If kcc's own changes from other sets must be allowed, compare `(agent, user)` against kcc's login rather than agent alone.
- confidence: medium (INFERRED: real firmware agent strings; BACKLOG says nothing is proven on hardware)

### B-03 A torn last audit line (crash or full disk mid-append) stops `kcc serve` from starting and kills the writer
- severity: medium
- kind: bug
- rule: RUST_GUIDELINES.md §2 error handling at a persistence boundary
- evidence: `crates/kcc-app/src/audit.rs:621-624`
  ```rust
  self.file.write_all(&bytes).and_then(|()| self.file.sync_data())
      .map_err(|error| io_error(&self.dir.join(AUDIT_FILE_NAME), error))?;
  ```
  `verify_files` (`audit.rs:761-762`) rejects any line that does not parse. `spawn_with_policy` (`audit.rs:444-445`) fails, and `crates/kcc/src/server.rs:365-369` propagates that with `.map_err(error)?`.
- impact: A power loss or a partial `write_all` on ENOSPC leaves half a JSON line. The writer stops (any non-lock error is fatal), and every later `kcc serve` start and every audited CLI command fails until someone edits `audit.jsonl` by hand. A partial write is crash damage, not tampering, yet it is treated the same way.
- fix: On open, if the last line has no trailing `\n`, truncate the file back to the last newline and log it (an incomplete line has no hash to protect). Treat only complete lines that fail verification as tampering.
- confidence: high

### B-04 "Bounded" audit waits block without limit once the 128-slot queue is full, including inside a safety bracket
- severity: medium
- kind: bug
- rule: RUST_GUIDELINES.md §5 cancellation/timeouts; the receipt invariants in `audit/receipt.rs:1-13` and `workflow_receipts.rs:8-10`
- evidence: `crates/kcc-app/src/audit.rs:452` and `:486-490`
  ```rust
  let (sender, receiver) = mpsc::channel(128);
  ...
  let slot = self.sender.reserve().await.map_err(|_error| AuditError::WriterUnavailable)?;
  ```
  `workflow_receipts.rs:48` awaits `audit.submit(event)` even when deferred. The bracket defers audits and then runs `work` before it disarms (`crates/kcc-domain/src/configuration/bracket.rs:113-127`). The Web login calls `submit` before its 5 s `LOGIN_AUDIT_WAIT` starts (`crates/kcc-web/src/auth.rs:486-490`).
- impact: The writer keeps retrying while another process holds the append lock (`writer.rs:85-104`), for example a stalled process or a slow append from B-01. Once 128 entries are queued, every `submit` waits indefinitely:
  - a bracket's `apply` never reaches its disarm, and shutdown waits on the open bracket;
  - Web sign-ins hang despite their 5 s bound.
  
  The module docs promise the opposite.
- fix: Put the reserve under the caller's limit, e.g. `timeout(limit, sender.reserve())`. For deferred receipts, use an unbounded queue or `try_reserve` and return a `Pending` that reports "not queued".
- confidence: high

### B-05 Login runs Argon2 and rewrites `users.json` with fsync under the exclusive cross-process lock, on every attempt
- severity: medium
- kind: security
- rule: overlay http-services DoS bounds; RUST_GUIDELINES.md §5
- evidence: `crates/kcc-app/src/accounts.rs:386-406`
  ```rust
  self.state.update(|document: &mut UsersDocument| {
      let Some(account) = ... else {
          verify_dummy_password(password)?;
          return Ok(Authentication::Invalid);
      };
      ...
      let hash = key.open(&account.username, &account.password_hash)?;
      if verify_password(password, &hash)? {
  ```
  `StateStore::update` (`persist.rs:206-224`) takes the blocking `users.json.lock` and always calls `write_locked`: temp file, fsync, rename and directory fsync, even when nothing changed. That includes unknown usernames and a duplicate in `create`.
- impact: An unauthenticated client sending login attempts with random usernames forces, per attempt, one Argon2id run (19 MiB, t=2) plus one durable rewrite, all serialized behind one cross-process lock. Real logins, password changes, account administration and `has_admin` writers queue behind them, and the Web `spawn_blocking` pool fills with threads parked on `flock`.
- fix: Read the document without the lock, run Argon2 outside it, then take `update` only when the failure counters or lockout actually change. Give `update` a "no change, skip write" result.
- confidence: high (INFERRED: whether a front-end rate limit dampens this)

### B-06 With a read-only login, the poller opens a new router session every round
- severity: medium
- kind: bug
- rule: none (resource use against the router)
- evidence: `crates/kcc-app/src/registry.rs:646-653`
  ```rust
  pub async fn poll_client(&self, id: &str) -> Result<Arc<RciClient>, RegistryError> {
      let profile = self.get(id)?.profile;
      if profile.read_login.is_some() {
          return Ok(Arc::new(self.connect_client(&profile, CredentialUse::ReadOnly).await?));
  ```
  `poller.rs:358` calls this on every round. `poller/extended.rs:78` calls `registry.poll_info` (which calls `poll_client` again) on every heavy round.
- impact: Every 15 s light round, plus a second time on each heavy round, a new `RciClient` and session is created and signs in again. On ndw4 routers that means an Argon2 derivation each time, which BACKLOG says is serialized one at a time. Router sessions also churn (INFERRED: sessions accumulate until they time out). The shared-client design is bypassed exactly for the profiles that set up a dedicated polling login.
- fix: Cache the read-only client per router beside `clients`, and invalidate it on the same profile changes.
- confidence: medium (INFERRED: that sign-in happens on the first request of a new session, since `connect_with` "sends no request", `kcc-rci/src/engine.rs:268`)

### B-07 Blocking file I/O and blocking `flock` waits run directly on Tokio workers
- severity: medium
- kind: guideline
- rule: RUST_GUIDELINES.md §5 "DON'T: Call blocking I/O in async functions" (line 1112)
- evidence:
  - `crates/kcc-app/src/workflow.rs:1370-1374`, inside `async fn ensure_backup`:
    ```rust
    drop(self.workflow.backups.create(&self.router, "pre-change", &SecretString::from(text.to_owned()))?);
    ```
    `BackupStore::create` takes the blocking `state.lock(...)` and does seal, write and fsync (`backups/store.rs:85,101`).
  - `registry.rs:359,525,571,606` call `self.store.update` (blocking lock and fsync) inside `async fn transition/create/update/delete`.
  - `jobs.rs:427,476,524` call `persist` (blocking `state.lock` plus `write_atomic`) inside async `start`, the completion task and `recover`.
  - `registry.rs:627-636` holds the Tokio `clients` mutex across `connect_client(...).await`, which does DNS resolution, for every router.
- impact: When the CLI or another process holds a backup, routers or job lock, a Tokio worker is parked inside `flock()`. With only a few workers, a handful of waiting writes freezes all of the async server's Web, MCP and poller work. Slow DNS for one router stalls `client()` for every router.
- fix: Wrap these synchronous store calls in `spawn_blocking`, as `kcc-web` already does for accounts. Release `clients` before connecting, then insert with a re-check.
- confidence: high

### B-08 `CliCommand` does not tie the line it sends to the request it validated
- severity: medium
- kind: guideline
- rule: RUST_GUIDELINES.md §3 "DO: Force construction through validated constructors" (line 424); project rule (b)
- evidence: `crates/kcc-app/src/workflow_cli/command.rs:42-48` and `:137-138`
  ```rust
  pub fn new(line: String, validated: ValidatedRequest) -> Self {
      Self { line: SecretString::from(line), validated, template: false }
  ...
  if !self.template {
      return Ok(Zeroizing::new(self.line.expose_secret().to_owned()));
  ```
  `workflow_replay.rs:77-82` "validates" the parallel `validated.expose_for_send()` value, never the line. `tests/replay.rs:98-107` sends `interface Bridge9 description …` paired with a validation that never saw `Bridge9`.
- impact: The type called `validated` guarantees nothing about the bytes sent to the router. About 35 production call sites (`kcc-domain/**`, `kcc-migrate/**`, `kcc-web`, `kcc-mcp`) build lines with `format!` next to a separately validated value. Any drift between the two, such as a wrong interface name or a different argument, reaches the router unvalidated, and the audit target still shows the validated path.
- fix: Render the line from the `ValidatedRequest` (or check it against the request's synopsis, as `from_template` already does with `validate_grammar`), and make `new` crate-private or fallible.
- confidence: high on the mechanism (INFERRED: that no current caller drifts; not audited outside the lane)

### B-09 Every job leaves two lock files in the state root forever
- severity: medium
- kind: bug
- rule: project rule (i) retention; unbounded growth
- evidence:
  - `crates/kcc-app/src/jobs.rs:601`: `let _lock = self.state.lock(&format!("job-{}", record.id))?;`
  - `jobs/job_ownership.rs:89-91`: `format!("job-owner-{id}")`
  - `persist.rs:289-291` puts each lock at `<state>/<name>.lock`. `prune_finished` (`jobs.rs:648-655`) removes only `jobs/<id>.json`, and no code removes these `.lock` files.
- impact: Two files per job (diagnostics, migrations, presets and so on) build up in the state root without limit. Every `read_dir` of that root walks them, including `backup_before_migration` (`persist.rs:348`), audit `rotated_files` and job paths.
- fix: Drop the per-record lock (ownership already serializes writers) and remove the `job-owner-*.lock` file when pruning the finished record.
- confidence: high

### B-10 A failed final write of a job record is dropped silently, and the next start reports a false interruption
- severity: low
- kind: anti-pattern
- rule: RUST_GUIDELINES.md §2 (swallowed errors)
- evidence: `crates/kcc-app/src/jobs.rs:476`: `drop(owner.persist(&record));`
- impact: If the final status write fails (disk full, I/O error), nothing is logged and the record stays `Running`. On the next start, `recover` marks it `Interrupted`, probes the router and writes a `job.recovered` audit entry for a job that actually completed or failed.
- fix: Log the error with `job_error_kind` at minimum.
- confidence: high

### B-11 Module-wide `#![expect]` blankets with "the plan mandates" reasons hide wildcard arms
- severity: low
- kind: anti-pattern
- rule: AGENTS.md "No `#[allow]` … `#[expect]` on the narrowest item"; BRIEF item 4 (review-process labels)
- evidence:
  - `crates/kcc-app/src/workflow.rs:2-13` expects 9 lints, including `wildcard_enum_match_arm` and `arithmetic_side_effects`, with `reason = "the plan mandates workflow names and bounded deadline arithmetic; ..."`.
  - Similar blankets: `registry.rs:2-16` (12 lints), `jobs.rs:2-9`, `poller.rs:2-9`, `backups.rs:2-9`.
  - The blanket hides `_ => return Err(WorkflowError::InvalidResponse)` (`workflow.rs:1301`) and `other =>` (`:1477`).
- impact: New wildcard arms, bare arithmetic or string slicing anywhere in these modules pass lint silently. The reason text refers to a planning document, not to the code.
- fix: Move each `expect` onto the item that needs it, with a code-level reason, and drop `wildcard_enum_match_arm` from the module level.
- confidence: high

### B-12 `WorkflowError::InvalidResponse` reports "invalid last-change response" for unrelated failures
- severity: low
- kind: anti-pattern
- rule: RUST_GUIDELINES.md §2; error text must be accurate
- evidence: `workflow.rs:510-511` `#[error("router returned an invalid last-change response")]` is also used for:
  - catalog lookup failure (`:706-707`);
  - non-UTF-8 startup configuration (`:1369`);
  - an unexpected body kind (`:1301`);
  - a running-configuration parse failure (`workflow_verify.rs:158,165-166`).
- impact: An unsupported firmware (no catalog) or an undecodable backup tells the operator that `show last-change` was invalid, which sends troubleshooting in the wrong direction.
- fix: Add distinct variants (`UnsupportedFirmware`, `UndecodableConfig`, `UnexpectedBody`).
- confidence: high

### B-13 Router-profile and router-id validation is duplicated and has drifted
- severity: low
- kind: duplication
- rule: BRIEF item 4 (copy-paste that drifts)
- evidence:
  - `settings.rs:958-1006` (`RouterProfile::validate`) versus `registry.rs:108-134` plus `registry/auth.rs:16-31`. Only the registry checks host, path, query and fragment, and they treat `auth = auto` with `token_file` differently.
  - `settings.rs:645` says the id is `[A-Za-z0-9._-]`, 1..=64, but `:960` enforces `is_valid_router_id` (1-32, `[a-z0-9-]`).
  - The same id rule appears again in `backups.rs:135-147` (`validate_component(router, 32)`) and `credentials.rs:375-384` (`lock_name`).
- impact: `Config::validate` accepts `url = "http://r/x"`, and the failure appears later from `RouterRegistry::new` with a different message. The field doc misstates the accepted ids.
- fix: Have `RouterProfile::validate` call one shared profile validator, use `is_valid_router_id` everywhere, and fix the doc.
- confidence: high

### B-14 Audit module: duplicated helpers, dead state and unused public API
- severity: low
- kind: dead-code
- rule: BRIEF item 4
- evidence:
  - `read_entries` (`audit.rs:692-704`) is a flattened `read_file` (`:790-800`).
  - `json_error` (`audit.rs:890-904`) duplicates `persist::corrupt_json` (`persist.rs:676-691`).
  - The spawn-time `next_seq`, `previous_hash`, `file` and `current_bytes` (`audit.rs:446-462`) are overwritten on every append (`:593-597`), so the `WriterState` fields carry nothing.
  - `with_append_lock_backoff` (`audit.rs:112`) has no caller in the workspace.
  - `spawn_with_limit`, `JobRunner::open_with_retention` and `Poller::light_rounds` are public production APIs used only by tests.
- impact: More surface area, and readers are misled about where the chain state comes from.
- fix: Delete the dead builder and fields, reuse one reader and one JSON-error mapper, and gate test-only constructors behind a test feature.
- confidence: high

### B-15 Audit retention runs only on rotation and only on whole files, unlike its documentation
- severity: low
- kind: docs
- rule: project rule (i)
- evidence: `settings.rs:272`: `/// Audit entries older than this are pruned.` In fact `prune_rotated` runs only from the rotate branch (`audit.rs:615-620`) and deletes whole archives (`:663-669`).
- impact: On a quiet install, archives older than `retention` stay until the next rotation, which may be months away at 50 MiB, and the active file is never pruned.
- fix: Correct the doc, or also prune at spawn time and on a timer.
- confidence: high

### B-16 `glob_matches` claims to be kit-compatible but is not
- severity: low
- kind: anti-pattern
- rule: BRIEF item 4 (comments that misstate behaviour)
- evidence: `registry.rs:962-966`
  ```rust
  /// Matches the kit-compatible `*` glob semantics used by router scopes.
  pub fn scope_matches(patterns: &[String], value: &str) -> bool {
      patterns.is_empty() || patterns.iter().any(|pattern| glob_matches(pattern, value))
  ```
  The kit's `host_matches` (`rmcp-server-kit-3.21.1/src/rbac.rs:1118-1130`) lowercases both sides, and an empty pattern list matches nothing there.
- impact: A custom role scoped `Lab-*` gets MCP tools listed by the kit for `lab-1`, then every kcc `authorize` refuses it. An empty scope means "all routers" here and "none" in the kit.
- fix: Match the kit (case-insensitive, empty means none, with the CLI passing `["*"]`), or fix the comment.
- confidence: high

### B-17 Poller idle-exit race can hand out a receiver that never gets data
- severity: low
- kind: bug
- rule: none
- evidence: `poller.rs:318-323`
  ```rust
  let receivers = sender.receiver_count();
  if receivers == 0 && metrics.is_none() {
      ...
      if since.elapsed() >= self.intervals.idle {
          drop(self.channels.lock().await.remove(&router));
  ```
- impact: A `subscribe` that runs between the count and the removal (the `.await` on the lock yields) gets `sender.subscribe()` from the channel that is about to be dropped. That subscriber's `changed()` fails at once and no data ever arrives, although a fresh subscribe would have started a new task.
- fix: Re-check `receiver_count()` while holding the `channels` lock before removing the entry.
- confidence: medium

### B-18 More private async functions lack cancel-safety annotations than BACKLOG lists (KNOWN-BACKLOG)
- severity: low
- kind: guideline
- rule: RUST_GUIDELINES.md §5 "Annotate every async fn with cancel safety" (line 1188)
- evidence: none of these carry an annotation: `poller.rs:306` `run`, `:351` `fetch`, `:438` `wan_stats`, `:452` `show_json`; `poller/extended.rs:72,125,153`; `registry.rs:767` `connect_client`. BACKLOG lists only `jobs.rs:511,546,571` from kcc-app.
- impact: The backlog count understates the gap. `run` is a spawned task that runtime shutdown can abort.
- fix: Add the annotations and update the BACKLOG list.
- confidence: high

### B-19 A write job with no router fails as "router busy: missing"
- severity: low
- kind: anti-pattern
- rule: RUST_GUIDELINES.md §3 "Use enums instead of boolean parameters" (line 511)
- evidence: `jobs.rs:411-414`
  ```rust
  let target = router.as_ref().ok_or_else(|| JobError::RouterBusy { router: "missing".to_owned() })?;
  ```
- impact: A programming error reaches users as a busy router named "missing". `(Option<String>, bool)` allows a combination that should not exist.
- fix: Take `enum JobTarget { Read(Option<String>), Write(String) }`.
- confidence: high

### B-20 Workflow audit entries use timestamps as request ids, and terminal changes drop their audit receipt
- severity: low
- kind: anti-pattern
- rule: none
- evidence:
  - `workflow.rs:1022`: `.with_result(outcome.to_owned(), format!("change-{timestamp}"))`; the same pattern at `:1097,1330,1397`.
  - `workflow.rs:438-444`: `From<CliChangeResult> for TerminalCliChangeResult` discards `audit`.
- impact: Two changes in the same second share a "correlation" id, and none can be joined to the front-end request that caused it. Reboot and factory-reset callers cannot tell the user that the audit entry is still pending.
- fix: Pass the caller's request id into the `ChangeSet`, and keep `audit` on `TerminalCliChangeResult`.
- confidence: high

### B-21 One malformed backup file turns off retention for that router permanently
- severity: low
- kind: bug
- rule: project rule (i)
- evidence: `backups/store.rs:221` `let record = read_record(entry.path(), &name)?;` fails the whole listing, and `:110-114` only logs a warning when retention fails. The `prune_failure_is_logged_without_failing_create` test (`tests/backups.rs:201-233`) pins this behavior.
- impact: Every later create warns, nothing is pruned, backups pile up past `keep_last` and `max_age`, and `list()` fails for the Web and CLI.
- fix: Skip or quarantine unreadable entries during listing and retention, and report them separately.
- confidence: high

### B-22 The two-group env-override macro adds structure nothing needs
- severity: low
- kind: anti-pattern
- rule: BRIEF item 4 (speculative abstraction)
- evidence: `settings/env_overrides.rs:30-55,137-139`: `before_suffix_check { … } after_suffix_check { … }`. None of the "after" rows touches `outbound.allowed_suffixes`.
- impact: Every new row forces a meaningless choice of group. A single table followed by one `normalize_suffixes` call gives the same configuration.
- fix: Collapse to one row list and normalize once after `apply_rows`.
- confidence: high

### B-23 Several tests cannot fail, describe the wrong failure, or wait in real time
- severity: low
- kind: test-quality
- rule: RUST_GUIDELINES.md §13; the BRIEF's test-quality list
- evidence:
  - `jobs.rs:822-834` (`cancelled_start_releases_router_write_slot`): the future is cancelled while waiting on the first `active.lock().await`, before anything is reserved, so the test cannot fail.
  - `tests/jobs_recovery.rs:242` `assert_ne!(first_id, second_id)`: the two ids differ by random OS entropy within one process, so this does not test collision handling.
  - `tests/audit.rs:317-323` and `tests/workflow.rs:147-149` describe a "forced rotation failure", but the directory named `audit-…0001.jsonl` makes `verify_files` fail before any rotation.
  - `tests/poller.rs:150-157` spins on `yield_now()` against a real-time `Instant` bound (a polling wait).
  - `tests/backups.rs:231` pins log prose (`"backup retention failed after create"`).
- impact: These tests give coverage that is not there; the spin loop and the prose pin are brittle.
- fix: Cancel after the reservation (hold `write_jobs` instead), force a collision with `for_test` allocators, rename the misleading test, wait on the watch signal, and assert on a structured field.
- confidence: high

### B-24 A route transition on a `kcc.toml` router keeps the new URL only in memory but rewrites the operator's password file
- severity: low
- kind: bug
- rule: none
- evidence: `registry.rs:358-365`
  ```rust
  profile.url = endpoint;
  self.store.update::<RoutersDocument, _, _>(|document| {
      if let Some(stored) = document.routers.iter_mut().find(|entry| entry.id == id) {
  ...
  drop(profiles.insert(id.to_owned(), profile));
  ```
  For a config-defined router the `update` is a no-op, while `stored::replace_password` rewrites the operator's `password_file` (`registry/stored.rs:54-65`).
- impact: After a migration moves a `kcc.toml` router, the next SIGHUP reload (which the README asks for after `kcc apikey create`) reverts to the old URL (`registry.rs:708-721`), while the operator's file already holds the new password. Half the transition is persisted.
- fix: Refuse URL transitions for config-defined routers, or persist neither change and report the required `kcc.toml` edit.
- confidence: medium

## Coverage
- **Read in full (src):** `lib.rs`, `audit.rs`, `audit/{writer,append_lock,receipt}.rs`, `persist.rs`, `workflow.rs`, `workflow_{receipts,batch,replay,cli,verify,output}.rs`, `workflow_cli/{command,grammar}.rs`, `brackets.rs`, `jobs.rs`, `jobs/{job_id,job_ownership}.rs`, `registry.rs`, `registry/{auth,stored,budgets,transition_tests}.rs`, `settings.rs`, `settings/env_overrides.rs`, `poller.rs`, `poller/extended.rs`, `accounts.rs`, `accounts/reset.rs`, `api_keys.rs`, `api_key_use.rs`, `permissions.rs`, `role_source.rs`, `backups.rs`, `backups/store.rs`, `credentials.rs`, `credentials/wipe.rs`, `secrets.rs`, `secrets/files.rs`.
- **Read in full (tests):** `audit.rs`, `audit_multiprocess.rs`, `poller.rs`, `jobs_recovery.rs`, `registry/inflight.rs`, `replay.rs`.
- **Read in part (tests):** `workflow.rs` (1-260, 470-699), `state.rs` (90-319), `jobs_recovery/interrupted.rs` (90-173), `backups.rs` (195-234), `config.rs` (140-169).
- **Skimmed by function list and grep only, so not reviewed for test quality:** `permissions.rs`, `accounts_reset.rs`, `credentials_sealed.rs` and `credentials_sealed/kinds.rs`, `secrets_write.rs`, `registry.rs`, `registry/auth_modes.rs`, `registry/secret_files.rs`, `workflow/batch_outcomes.rs`, `workflow/namespaces.rs`, `bootstrap_workflow.rs`, `api_key_use.rs`, `example_config.rs`, `write_redaction.rs`, `cli_templates.rs`, `write_redaction.proptest-regressions`.

## Clean
- **Atomic state writes:** temp file, fsync, rename and directory fsync; owner-only modes on create plus a forced `0600`/`0700`; leftover temp files are cleaned up.
- **State path safety:** lock, lease and backup names are checked as single path components (`check_name`, `validate_component`, job `validate_id`), so traversal is refused.
- **Schema handling:** a newer schema is refused, migrations are looked up step by step, and a pre-migration copy is taken before the write-back.
- **Audit ordering:** one writer per process, FIFO; `seq` and `prev_hash` are re-derived under the cross-process lock, so chains from several processes stay contiguous (only the cost is wrong, B-01).
- **Lock retries:** a busy append lock keeps the entry at the head and never drops it; any other error closes the channel and turns `is_alive` false, so later changes are refused before any router request.
- **Receipts:** `Pending` and `AuditReceipt` state handling, the bracket's deferred-then-settle sequence, and the `BracketGuard` RAII count are balanced on every path.
- **Secrets at rest:** XChaCha20-Poly1305 with a fresh 192-bit nonce and AAD bound to the owner and kind; the master key is size-capped, permission-checked and created race-free through a hard link.
- **Debug redaction:** `Account`, `StoredApiKey`, `CliCommand`, `MasterKey`, `CredentialStore` and `AuditPolicy` redact secrets; the JSON error mappers carry no stored values.
- **Leases:** in-process label removal happens before the lock is released (field drop order in `Reservation`, explicit `Drop` on `ChangeSet`).
- **Job ownership:** cross-process locks, `recover` skips jobs another process still holds, the router probe is bounded at 5 s, and cleanup survives panics and missing records.
- **API keys:** `KeyUseRecorder` throttling, and API keys are stored as hashes only.
- **Env overrides:** the table-driven `NAMES` list and the applied rows cannot drift apart.
- **Backups:** exclusive create with a collision suffix under a per-router lock; sealed records are bound to `backup:<router>:<name>`.