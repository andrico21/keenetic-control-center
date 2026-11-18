# issues - kcc-review-fixes (append only)

## [2026-11-16] Todo 3 (wt/r3) out-of-scope notes
- `crates/kcc-migrate/src/rules.rs` was 620 pure LOC before todo 3 (now 656), far over the ~250 ceiling; a split by responsibility (rule loading / classification / mapping+conflict helpers) is a follow-up refactor, not done here.
- Remapped (`remap-mapped-reference`) lines still skip the scalar-conflict check, like before; only copy-rule lines (secrets, keys) gained it in todo 3.

## [2026-11-16] Orchestrator slip while merging todos 3 and 5 (disclosed, no harm)
- I generated the r3/r5 patches with `git diff master wt/rN` although the worktrees were cut from a040ba2 and master had moved to 757b48b (todos 2 and 7). The patches therefore carried the reverse of todos 2 and 7; the r3 patch applied cleanly, giving an index with those two todos reverted. I noticed from the `git diff --cached --stat` (32 files, 875 deletions) and the r5 apply errors before any gate or commit ran, restored the index and tree to HEAD (`git reset`, `git checkout -- <product paths>`, removed the one untracked file), deleted the two temporary worktrees/targets built on the wrong base, and regenerated the patches against each worktree's own base (`git diff --binary a040ba2 wt/rN`). Rule: always diff against the worker's base commit, not master.

## [2026-11-16] Todo 8: B-08 strict line binding escalated (deep-high)
- A strict `CliCommand::new(line, request) -> Result` that binds the line to the request through the catalog grammar (attempt and refusal inventory: `.omo/evidence/task-8-kcc-review-fixes-b08-attempt.log`) refuses current lines of ~33 command paths in kcc-domain alone (65 failing tests): real drift (segments cleanup pairs `no interface X`, `no ip policy X`, `no ip dhcp pool X` with unrelated requests; `interface X vlan-id N` paired with the `interface` request; firewall `rule N disable` with `{index}`), router spellings the grammar lacks (`interface X down` for `interface up` no; `address port` where the synopsis has `address:port`), and generator shapes (`access-list permit|deny` protocol keyword, `ip dhcp host` single `host` arg, `(vpn-server)`/`(ndns)`/`(system)` leading groups, `show *` with `(show)` group, `access-list rule` without `new-index`). Not shipped; decision needed on scope (site-by-site migration + catalog grammar fixes overlapping todo 41) before `new` can become fallible.

## [2026-11-16] Todo 9 (wt/r9) out-of-scope notes
- `kcc-domain/src/dns/change.rs` was 363 pure LOC before todo 9 (393 after the token checks): a split (catalog input / line rendering) is a follow-up refactor.
- `policies::change::plan::description(name, None)` builds `{"no":true}`, but `render::expected_leaf` requires a `description` field, so clearing a policy description fails with InvalidResponse (pre-existing, untouched).
- The Web schedule dialog still holds descriptions to one word (`is_word`); the domain now quotes them, so allowing spaces there needs only a new help/error key (follow-up).
- The fake router has no `dns-proxy filter profile description` / `object-group fqdn description` grammar.

## [2026-11-16] Todo 10 (wt/r10) follow-ups, not fixed here
- Secret pages (`wan_password`, `wifi_psk`, `vpn_credential`, `vpn_server` psk) pass `Params::default()`: if their plan ever reaches Management (todo 11 classifies WAN planners; a WAN password on the management WAN), the kit's dialog resubmits without the typed secret and the confirmed request answers "unchanged". Such a page needs its own in-dialog confirmation plus `.confirmed_by_page(Risk::Management)`, as `user_password::run` does. Todo 11 should check `wan_password`.
- Form-only handlers whose plans are Write today (dns forms and intercept, nat, routing route/policy, dhcp, schedules, system general edit, internet create, vpn forms/import) get a path-only `Resubmit`; if one of them can plan a management change later, it must read the query too (as segment create and vpn state/service now do) and pass `params.again(path)`.
- No Web test reaches the internet order/edit management path: the fake router cannot make a WAN carry kcc's connection; the kit unit test `asking_tests` covers any planned management change.

## [2026-11-16] Todo 11 (wt/r11) out-of-scope notes
- `no service http` (plan_service "http", false) also cuts kcc off when it uses HTTP; it stays a Management change, not refused (C-12 named only port/ssl).
- A non-bridge interface whose detection is Unknown (no interface owns kcc's pinned address, e.g. kcc behind NAT/cloud) still plans as Write; failing closed there would make every interface Management.
- `crates/kcc-rci/src/engine.rs` (454 -> 479 pure LOC) and `crates/kcc-domain/src/wan.rs` (263 -> 269) were already over the ~250 ceiling; split is a follow-up.
- Other secret pages (wifi_psk, vpn_credential, vpn_server psk) have the same kit-resubmit gap if their plan ever reaches Management (todo 10 note); not changed here.

## [2026-11-16] Todo 8 part B-08 (wt/r8b) follow-ups, not fixed here
- `system log server` and `interface wireguard peer endpoint` are sent as `<address> <port>`; the manuals document `<address>:<port>` (examples `log server 192.168.1.1:8080`, `endpoint 10.0.1.10:11635`). The binding accepts both spellings; whether a real router accepts the two-word form is unverified (no live test covers it).
- `interface vlan-id` is in the catalog only through `catalog/synopsis-errata.json` (no manual documents it; segments send it). Migration still refuses `vlan-id` lines (explicit rule in `kcc-migrate/src/apply/command.rs`), keeping its prior behaviour; replaying VLAN interfaces is an owner decision.
- A refused pairing surfaces as `WorkflowError::SecretCommand(Line)`: the CLI maps it to Exit::Validation, the MCP raw `kcc_cli_parse` to `validation_failed`, but domain tools through `map_workflow` answer `internal` (todo 12 error vocabulary). It is reachable from user input for a DNS route with neither gateway nor interface and a firewall rule with ports on icmp/esp/gre/ipip/ip.
- Keyword choices that are not catalog arguments are not bound (access-list protocol `tcp`/`udp`/`icmp`..., which property `no access-list X rule N <disable|schedule|description>` clears): the request shape cannot express them.
- The general bare-word promotion also typed: `components list [sandbox]`, `crypto ipsec profile dpd-interval [retry-count]`, `interface dsl dmt init [index]`, `interface dsl isp-profile [profile]`, `interface tunnel gre keepalive [count]`, `ip dhcp pool dns-server [address2]`, `ip dhcp relay lan|wan|server` negative arg, `ip policy ipv6 route [metric]`, `mws member [member]`, `nvox call-history filter [text]`, `show crypto ike key [name]`, `show crypto map [map-name]`, `show dot1x [interface]`, `system reboot [schedule]`, and `ip route [metric]` on 4.3 (todo 41 may want to review these facts).

## [2026-11-16] Todo 12 (wt/r12) notes, not fixed here
- D-18 policies/NAT/segments read-backs now fail with `VerificationFailed { field }` (`/ip/policy/<name>`, `/ip/static|/ip/nat`), but the workflow's own config-presence verification (`verification::complete`) catches a silent no-op first, so no test can reach the domain read-back through the fake router; only the firewall port-range part of D-18 has a behavioural regression test.
- C-13 has no behavioural regression test: every catalog has the fail-safe/reboot paths with an unbounded `interval`, so a local planning failure of the arm cannot be produced (critic: "lost only in theory"); covered by the W3-06 mapping test and the structural change (typed `Timer`).
- Over-ceiling files that grew: `kcc-app/src/workflow.rs` (1048 -> 1053), `kcc/src/cli/exit.rs` (273 -> 292), `kcc-web/src/page_kit/action.rs` (252, unchanged), `page_kit/submit/submit_tests.rs` (261 -> 277); `kcc-domain/src/configuration.rs` went down (322 -> ~285) by moving the timer request to `configuration/timer.rs`. Splits are follow-ups.
- The CLI `From<InterfaceChangeError> for Failure` still answers `Exit::Router` for every interface failure (E-07 named MCP only); `DomainError::from(InterfaceChangeError)` now exists if the CLI should class them like other domain errors.
- Web `plan_failure(DomainError)` still words planning refusals itself (ProtectedAccount -> "failed"); only the DomainError -> WorkflowError mapping was unified.
- `firewall_page/run.rs` still maps a snapshot read failure to `WorkflowError::InvalidResponse` (not cited by the findings).

## [2026-11-16] Todo 15 (wt/r15) notes
- Over-ceiling files grew: `kcc-web/src/session.rs` 407 -> 448 pure LOC, `kcc-web/src/auth.rs` 510 -> 550 (anonymous cap logic itself went to the new `session/anonymous.rs`). Splits are follow-ups.
- Several async fns in `session.rs` (get, peek, invalidate, set_fingerprint, ...) have no `// cancel-safe:` comment and `cargo xtask cancel-safety` does not flag them; only the fns this todo touched got one.

## [2026-11-16] Todo 16 (wt/r16) notes, not fixed here
- `kcc-web/src/config_page/backup_rows.rs::stamp` still builds `"{minutes} UTC"` in Rust (same W1-13 class, not cited by the finding).
- `AccountStore::administer`, `set_locale`, `reset_password` still rewrite users.json when the account is missing or the change is refused.
- Size: `kcc-app/src/accounts.rs` dropped to 383 pure LOC (Argon2 and sign-in moved out) but is still over the ceiling; `kcc-web/src/auth.rs` 551, `admin_shared.rs` 352 (pre-existing).

## [2026-11-16] Todo 14 notes
- `kcc-web/src/session.rs` grew 448 -> 454 pure LOC (`SessionStore::lifetime_left`, must sit in the one inherent impl); the split stays a follow-up.
- Job and wizard apply streams are covered structurally (every `guarded` caller must build a `StreamSession`); the integration test exercises the open-ended kinds (fleet, dashboard, router log, interface traffic) because job/apply streams end on their own.

## [2026-11-16] Todo 21 (wt/r21) notes, not fixed here
- `kcc-app/src/accounts.rs` grew 383 -> 387 pure LOC (rustfmt splits the longer `.seal(&Binding::account(..), ..)` calls); it was already over the ceiling.
- `Binding::backup(router, name)` relies on the backup store's `validate_component` (no `:` in the router) instead of a typed id; both callers check it first.

## [2026-11-16] Todo 22 (wt/r22) notes, not fixed here
- `kcc-app/src/persist.rs` grew 425 -> 432 pure LOC (already over the ceiling; the new public helper went to `persist/private_file.rs`). Split is a follow-up.
- `CredentialStore::migrate` still reads a legacy `<id>.password` through a symlink (`fs::read_to_string`) before sealing it; only its removal was changed (inside the kcc-owned 0700 directory).
- `persist::write_exclusive` (backups) keeps its fixed `.<name>.tmp` name under the domain lock, like `write_atomic`.

## [2026-11-16] Todo 23 (wt/r23) notes, not fixed here
- Not zeroized (outside the findings' scope): `kcc_config` `Ast`/`CliLine` tokens (the parsed source and `Preset.lines` hold secrets in plain Strings, critic F-14 says this is model-wide); the CLI console's `line.trim().to_owned()` passed to `client.parse`/`CliCommand::new`; `RciBody::Text` replies; hyper/reqwest/rustls internal `Bytes` copies; serde_urlencoded's decode copies of form values; `presets_page/detail.rs` and `compose_panel.rs` view `lines: Vec<String>`.
- `session.rs:622` and `catalog/runtime.rs:219` were left unchanged: the binding A-10 critic correction refutes both sub-claims.

## [2026-11-16] Todo 25 (out of scope, not fixed)
- CLI `scoped_role` (crates/kcc/src/cli/preset/manage.rs) narrows the role to the registered routers the principal sees; when it sees NONE, `Role.router_scope` is empty, which `scope_matches` reads as "every router". A scoped CLI principal that sees no registered router then gets store-level access to presets of every router (show/delete are still caught by `visible()`, capture-replace is not). Needs a "matches nothing" scope representation.
- `PresetStore::load_for_apply` and `get_for_apply` are identical duplicates.

## [2026-11-16] Todo 26 (out of scope, not fixed)
- CLI `apikey revoke` still lacks the Web's `manages` (dominance) check (F-06 impact text; the binding fix covers create/add only).
- MCP job tools (`kcc-mcp/src/generic/fleet.rs` get/cancel by id) have no owner check; random ids now make enumeration infeasible.
- golden36-net/capture.sh route parser stops at the first `#[cfg(test)]` in a file, so advanced.rs routes show as STALE-SKIP since 187d183.
- `kcc-app/src/accounts.rs` grew 387 -> 396 pure LOC (already over the ceiling).

## [2026-11-16] Todo 27 (wt/r27) notes, not fixed here
- B-14 remainder: `JobRunner::open_with_retention` (body of production `open`; direct public use only in kcc-app integration tests) and `Poller::light_rounds` (used by kcc-app and kcc-telemetry integration tests) stay public. `#[cfg(test)]` cannot serve integration tests or another crate; gating them needs a test Cargo feature (manifest change), outside this todo's audit-module scope. The audit module's own test-only API is gone (`spawn_with_limit`, `with_append_lock_backoff` deleted; callers use `spawn_with_policy(.., AuditPolicy::default().with_rotate_bytes(1))`).
- Sizes: `kcc-app/src/audit.rs` 570 -> 323 pure LOC (still over the ceiling: the public types and AuditLog); `persist.rs` 432 -> 435.
- A torn line on a disk that is still full: the quarantine copy needs space, so that start still fails with an I/O error until space is freed (then it repairs).
- A crash after the quarantine copy and before the truncate leaves a duplicate quarantine file on the next start (by design: never lose the fragment).

## [2026-11-16] Todo 28 (wt/r28) notes, not fixed here
- Web and MCP still draw their request id after the change (page_kit `Record::append`, MCP `finish_with_context`), so their change sets keep the set's own id (`change-<nonce>-<n>`) instead of the front end's; `ChangeSet::with_request_id` exists and only the CLI passes its run id. Joining a Web/MCP request to its workflow entries needs the front end to draw its id before `begin` (todo 30 territory: "logged failure causes carry the request id returned to the client").
- Unix-time copies outside F-25's five remain: `kcc-mcp/src/support/audit.rs`, `kcc-mcp/src/preset_tools/{capture,state}.rs`, `kcc-migrate/src/apply.rs`, `kcc-migrate/src/apply/agreements.rs`, `kcc-app/src/poller.rs`, `persist.rs`.
- Sizes: `kcc-app/src/audit.rs` grew by ~36 lines (queue slots, `submit_within`, `enqueue`, `QueueFull`), `workflow.rs` 1053 -> 1061, `kcc-web/src/auth.rs` 551 -> 558 (pure LOC incl. tests); all three were already over the ceiling. Splits are follow-ups.
- A sign-in whose audit entry finds no slot answers a bare HTTP 500 (the existing `internal()` path, no localized page), like every other audit write failure on the sign-in path.

## [2026-11-16] Todo 30 (wt/r30) notes, not fixed here
- F-13 finding text also names `preset/manage.rs:57-68`, `accounts.rs:32,186`, `api_keys.rs:27,108` (permission refusals through `require()`/`authorize()` without an audit entry); the plan's F-13 line limits the evidence to persist/routers/router_secrets, so only those moved to `Ctx::authorize_audited`. `router list` (`require(Read)`) is not audited either. The others are a one-line change each through the same helper.
- E-09: the `mcp_tool` span is INFO level; with a log filter above `info` for target `kcc_mcp` the span (and so the request id) is not printed on warn lines. A tracing subscriber set with `set_default` for one thread races other tests' first use of a span callsite (interest cached `never`): the logging test lives alone in `kcc-mcp/tests/request_ids.rs`.
- MCP job tasks (diagnostics, component commit, migration apply) run outside the call's task-local, so entries written later by the job keep their own ids; only the call's own change sets carry `mcp-...`.
- The MCP 403 refused by the kit before kcc code (route-table authz) and the Web route-table 403 (`authz.rs`, owned by todo 29) remain unaudited.
- `kcc/src/cli/context.rs` (399 pure LOC), `kcc-mcp/src/domains/write/clients.rs` (~300), `kcc-app/src/workflow.rs` (>1000) were already over the ceiling; this todo kept context.rs net smaller (three refusal blocks folded into the helper) and moved the MCP call lifecycle out of shape.rs into the new `support/call.rs`.

## 2026-11-16 todo 30 review follow-up (orchestrator)
- F-13 helper `Ctx::authorize_audited` covers persist/routers/router_secrets/context. Other `principal().authorize` sites still do not audit a refusal: `crates/kcc/src/cli/rci.rs` (batch read), `migrate.rs` (inventory), `migrate_plan.rs`, `preset/plan.rs`, `preset/source.rs`, `preset/manage.rs`. Outside the F-13 evidence list; candidate for docs/BACKLOG.md at the end (or a later CLI todo if one covers them).
- Todo 30 added a dev-dependency `tracing-subscriber` (workspace dep, already in Cargo.lock) to kcc-mcp; disclose in the commit body.

## [2026-11-16] Todo 31 (wt/r31) notes, not fixed here
- With the checksum-only conflict rule, a write that was SENT but then failed (read-back verification failure, partly refused CLI batch) leaves `expected` stale, so the set's next write/save is refused as a conflict (kcc's own unverified change). The old agent clause hid this. Refreshing `expected` right after a send (before read-back) would fix it; not done (changes what a normal change sends).
- kcc-migrate `Stop::arm` still sends a disarm after an arm refused locally by its preflight (now always sendable through the recovery path; reported Workflow when accepted, ArmUnconfirmed only if that disarm fails). The bracket got the preflight split; the migration arm did not.
- `crates/kcc-app/src/workflow.rs` is 1104 pure LOC (was 1093); already far over the ceiling.

## [2026-11-16] Todo 33 (wt/r33) notes, not fixed here
- The lease timeout uses `Applier::recovery_left()` from the last renewal. After a finish that failed with the router timer already disarmed (e.g. `CommittedSaveFailed`), the applier stays and the Web expiry later records the run as "rolled back by the router" although the router kept the unsaved changes; the engine exposes no "timer still armed" state on the `Applier` to tell them apart. Rare (a failed save after a confirmed disarm); a follow-up could expose the armed state from `kcc-migrate`.
- `kcc-testkit/src/server.rs` (~1300 pure LOC) and `lib.rs` (~460) were already far over the size ceiling; the new request stall (`stall.rs`, `Handle::stall`) added ~15 lines to them.
- The run-retention "last change" is the record file's mtime: restoring a state directory with a tool that resets mtimes changes the ages (a run may be deleted or counted as abandoned earlier/later).
- Wizard store I/O stays synchronous `std::fs` inside async handlers (W5-05 territory); the new index/retention code follows the existing store.

## 2026-11-16 todo 33 review follow-up (orchestrator)
- `wizard/retention.rs::sweep` is called from each landing page view and stats the record file of every indexed run (the list itself reads only the owner's records). Cheap per run, but O(all runs) per landing view; candidate for a rate limit or a BACKLOG line if it matters at scale.
- The owner index is rebuilt by one bounded scan of at most 4096 run directories (`wizard/index.rs::SCANNED`); runs beyond that are not indexed when the index file is lost. Candidate BACKLOG line.
- `index-wizard.json` / `index-preset.json` now live in the runs directory beside the run directories (tests that count directories must count run directories only).

## [2026-11-16] Todo 34 (wt/r34) notes, not fixed here
- A running apply's `Analysis`/plan are cached in the run's session, so a migration whose sealed source was swept after a day of no change still plans from the cache until the process restarts; only a fresh read (Problem::Source) needs the sealed source.
- The presets wizard's password rows are keyed by index only (no hidden user name); its users come from the server-side plan on both GET and POST, so the finding was limited to the migration wizard.
- (todo 34 review) `retention::sweep` now also calls `forget_secrets` (3 discard attempts) for every abandoned-but-not-yet-deleted run on each landing view, up to the 30-day deletion. Harmless, but with the per-landing O(runs) stat noted for todo 33 it is a candidate for an existence check or rate limit (BACKLOG).

## [2026-11-16] Todo 32 (wt/r32) notes, not fixed here
- C-03 covers the native fail-safe timer only: a reboot an operator scheduled (`system reboot <s>` in extender/AP/repeater modes) is not visible in `show last-change`, so a bracket in scheduled-reboot mode can still replace and cancel it. Detecting it needs a router read kcc does not model yet.
- `ApplyError::CommittedSaveFailed` has no producer any more (close no longer saves after the native commit); the variant and its consumers (MCP `management_applied_not_saved`, Web wizard/presets, CLI exit) stay so stored records parse. CLI `closing.rs` `(Close::Save, true, false)` is unreachable for the same reason. A later cleanup may drop them with a CHANGELOG line.
- The todo-33 issue "after CommittedSaveFailed the Web expiry records 'rolled back by the router'" can no longer arise from a router-mode commit.

## [2026-11-16] Todo 35
- A poll round already holding the old read-only client when its profile changes can still re-sign in on that orphaned client (one extra session until the router expires it); `forget` only logs out the session it sees at that moment. Same shape as `client()`; not fixed.
- Primary-credential `clients` are not signed out at shutdown (only read-only sessions and background sessions are).
- `poller.rs` is ~370 pure LOC (pre-existing, over the 250 ceiling); not split here.
- Worker slip: ran `git checkout <file>` once on a file this todo had just edited itself (crates/kcc/src/server_shutdown.rs, reverting only its own wrapper edit); no other work affected.
- (todo 35 review) `read_pool::forget` signs out only an already initialized client; a read-only client still being built when its profile is replaced is dropped without a sign-out (the router expires the session). Rare, bounded; BACKLOG candidate.
- stray empty untracked file '$E' (unset-variable redirect, 01:47) found and removed from the repo root; never part of a commit (untracked, outside the product paths).

## [2026-11-17] Todo 36
- `create_private_dir` re-chmods the jobs dir to 0700 on every access, so a read-only jobs dir cannot be used to fail a record write in tests; the test blocks the temp name with a directory instead.
- `jobs.rs` is still ~960 lines (pre-existing; todo 37 touches it).
- (todo 36 review) With the per-record job lock gone (plan-mandated), two kcc processes starting at the same instant and both recovering the same dead Running job can race on write_atomic's fixed temp name (one startup may fail with an I/O error). Narrow; fix would be to claim the owner lock while recovery rewrites the record. BACKLOG candidate.

## [2026-11-17] Todo 37 (wt/r37) notes, not fixed here
- Still sync on async paths (not cited by B-07/W2-08/W5-05/G-22): kcc-mcp `config_tools/backups.rs` (`BackupStore::create/list/get` in async tool handlers), `JobRunner::get` (record read) from Web/MCP handlers, `StateStore::try_lease` (non-blocking try_lock + open) in `ChangeWorkflow::begin`, kcc CLI preset/backup commands (one command, acceptable). Candidates for a follow-up.
- `kcc-app/src/jobs.rs` (776 pure LOC), `registry.rs` (797) and `workflow.rs` (1111) were already far over the ~250 pure-LOC guideline before this todo; this todo added 15/27/5 lines. Splitting them is a refactor of its own.
- Test seam: `kcc_testkit::blocking_gate::BlockingGate` (FIFO or held resource on a plain thread, released after the runtime answers or a bound). A lock-held gate cannot tell when the call reaches the lock: the Web capture test answers only after 10 000 yields (its first red run passed falsely because the request awaits the blocking pool before the preset lock).
- (todo 37 review) RouterRegistry::transition clones the profile under the read lock, writes password and routers.json on the blocking pool, then inserts the clone back; the client cache stays locked, but an operator edit of the same router in that window could be overwritten (previously the profiles write lock was held throughout, though update() wrote routers.json before locking profiles). Narrow; BACKLOG candidate. The off_runtime tests are unix-only (FIFO), so Windows CI does not run them.

## [2026-11-17] Todo 38 (wt/r38) notes, not fixed here
- `system_pages/job_feed.rs` `JobFeeds` keeps 32 feeds globally and pops the oldest (possibly a running job's) feed: the same shape as W4-07 but not in its cited evidence; candidate for the same per-owner, finished-first rule.
- The wizard/config page-view size now comes from the record, so a backup that fails to decrypt still shows its size (previously blank).
- Consumer tests that run a diagnostic through `start_job` now take about 1.5 s per ping (3 polls at 500 ms) instead of ~30 ms.
- (todo 38 review) log_poller keeps the first viewer's RouterCtx for the poller's life (a profile change is picked up when all viewers leave); advanced::keep_output never evicts a running job's slot, so a user holding only running explorer jobs can exceed the 32-slot cap (bounded by the job runner). Both minor; BACKLOG candidates.

## [2026-11-17] Todo 39
- `crates/kcc-rci/src/session.rs` was 572 pure LOC and is 604 after this todo (refresh rule, cookie name filter); a split (e.g. cookie parsing into `session/cookie.rs`) is a follow-up.
- No `KCC_OUTBOUND_ARGON2_MAX_ITERATIONS` env override was added (CONFIG.md says only the keys in env_overrides.rs have one).

## [2026-11-17] Todo 40 (wt/r40) notes, not fixed here
- A-16 items left (other crates / other todos' files): the 256-byte secret limit (kcc-config `quoting.rs`, kcc-catalog `runtime.rs` and `validate.rs`, todo 41 owns validate.rs) and the JSON-pointer token escaping copies (`kcc-rci/src/lib.rs` append_pointer, kcc-catalog `request.rs`/`secret_value.rs`, kcc-domain several, kcc-app `workflow_cli/grammar.rs`, kcc-testkit `tree.rs`). The A-17 finding also lists `kcc-catalog/src/request.rs:168-171` (defensive block); the plan's evidence list omits it and the file belongs to todo 41.
- `crates/kcc-app/src/workflow.rs` grew to ~1150 pure LOC (+~40 for `interrupted_batch`); `session.rs` (577) and `lib.rs` (583) of kcc-rci are still over the ceiling (both shrank). `engine.rs` went from ~500 to 411 pure LOC (batch, show and admission moved to submodules).
- The interrupted-batch audit counts the items of the failed chunk as `unanswered` (not applied); the router may have applied that chunk before the failure (the error says nothing about it).
- `RouterInfo::detect` counts as one request in the observer although it sends several GETs (it was not counted before).

## [2026-11-17] Todo 41 (wt/r41) notes, not fixed here
- The Web console help text `web-console-unvalidated-help` ("Administrators only... the request is audited") does not say the line is destructive now; the dialog does. Changing it needs six locales (left for a copy pass).
- Project overlay rule (b) still reads "every raw ... CLI line ... is validated"; the audited raw escape is documented in docs/SECURITY.md and MCP_TOOLS.md and is now Destructive, but rule (b) has no sentence naming it.
- `cargo test -p kcc-catalog --lib` takes ~6 min on 2 jobs (risk tests over three catalogs): budget for it.
- [todo 43] `routers_list` never emits `next_cursor` for a full page (only the truncation path does); `catalog_search` fetches `offset+limit+1` results each call. Not changed.
- [todo 43] Reverted my own edit of two test files with `git checkout -- <file>` once (they had no other change); no other git state touched.

## [2026-11-17] Todo 44 worker incident (disclosed)
- While killing my own stale cargo batch I ran `pkill -x cargo`, which matches EVERY cargo process of the user, not only mine. No other cargo process was listed afterwards, but if the orchestrator's gate or another worker had a cargo process running at ~09:55 it was killed and must be re-run. Rule for next time: kill exact PIDs only.

## [2026-11-17] Todo 48 (wt/r48) notes, not fixed here
- MCP `kcc_dhcp_write` `op: pool` has no `gateway`: `PoolConfig::new` advertises `begin` as the default router and a replace resets lease/state (the F-11 harm through MCP). Fixing it changes the tool schema (+ docs/MCP_TOOLS.md regen); recorded in docs/BACKLOG.md.
- Catalog `ip dhcp pool dns-server` synopsis carries the manual prompt `(config-dhcp-pool)> dns-server` as grammar words in 4.3/5.0/5.1; `address2` is typed but untrustworthy. Recorded in docs/BACKLOG.md.
- not proven on hardware (todo 48): 'no ip dhcp pool <name> dns-server' accepted by a real router; fake router rule relaxed to allow the bare 'dns-server' leaf.

## [2026-11-17] Todo 49 (wt/r49) notes, not fixed here
- `crates/kcc-domain/src/dns/change.rs` was already 392 pure LOC before this todo (393 after); it needs a split (not in scope).
- The text reader's `RuleForm::rule()` drops port range ends (`rule_words.rs`), so a Web move of a `port range` rule plans its identity without the range; only the domain apply path (unused by the Web) reads that identity, so nothing breaks, but the two readers still disagree (BACKLOG "two readers").
- Correction to the line above: the text reader keeps a `port range` rule unstructured (words only, `rule_words.rs` module doc), so a Web move of such a rule plans it by its words; no identity is lost. The only real gap is the two readers' different notion of 'structured' (JSON reader models ranges, text reader does not).

## [2026-11-17] Todo 51 issues
- Pre-existing, left alone: `WireGuardParseError::UnknownSection.section` still echoes the (bracketed) line text; a `[`-prefixed line cannot be a bare base64 key, so it was not in the binding scope.
- The fake router assigns `type` "Wireguard" to a created interface only after a wireguard sub-command; a bare `interface X` has no type (a real router types it by name prefix). The D-11 test therefore sets a listen port after Create.
- Web: the VPN delete form now needs an account with the Destructive permission (operator no longer deletes a non-management VPN interface).
- not proven on hardware (todo 49): 'access-list <name> rule <index> order <position>' reorder form and the catalog 'new-index' argument on a real router.

## [2026-11-17] Todo 50 (wt/r50) notes, not fixed here
- not proven on hardware (todo 50): `no ip policy <name> description` without an argument accepted by a real router (the fake rule was relaxed to allow the bare leaf); the IPv4/IPv6 route tails parsed from the real `show running-config` text (`gateway [interface] [metric]`, `interface [gateway]`) follow the CLI manual synopsis only.
- Routes configured with `auto` or `reject` cannot be added by kcc (the catalog has no argument for them) and cannot be restored by the wipe recovery; they are reported after the others are restored. Extending Ipv4Route is a separate change.
- The `apply` of policies (`policies/change/apply.rs`) still reads back after `apply_cli` returns (not a VerificationSpec before the audit entry), unlike todo 48's clients/DHCP; left alone.

## [2026-11-17] Todo 52 (wt/r52) notes, not fixed here
- Line walkers outside D-13's evidence remain: `dhcp/model.rs::parse_pools` (todo 48 design) and `routing/change/restore.rs::route_words` (todo 50 design); `crate::config_tree` could replace them later.
- The 306 + 44 `# Errors` sections in kcc-domain were generated from each function's error paths (catalog validation, CLI tokens, router reads, workflow, specific variants) and spot-checked; wording is uniform rather than hand-tailored.
- Many kcc-domain files were already above 250 pure LOC before this todo (dns/change.rs, wan.rs, vpn_clients.rs, configuration.rs, interfaces/management.rs, ...); this todo added only doc lines and attributes to them.
- `storage::plan_eject` still takes 5 parameters (pre-existing).
- kcc-app `workflow_verify::credential` is now the only VPN credential presence walker (the domain copy was deleted); todo 53 (secret read-back proves the new value) should change it there.

## Todo 52 review notes (orchestrator)
- Backlog: segments now parses the whole running configuration into an Ast (config_tree) without wipe_tokens; the previous code held an unzeroed String copy of the same text, so exposure is not worse, but kcc-app wipes its parsed tokens and the domain does not.
- Worker disclosed: 350 generated `# Errors` sections; 35 were vacuous and are being rewritten by a follow-up worker.
- Two other config line walkers (dhcp/model.rs, routing/change/restore.rs) were left as they are (outside D-13's evidence).

## [2026-11-17] Todo 53 follow-ups (out of scope, not fixed)
- VPN client/server credentials (`vpn_clients::secrets::plan`, `ConfigSecret` presence check: L2TP/PPTP/SSTP passwords, IPsec
  keys, IKE key, WireGuard obfuscation/preshared keys) have the same C-22 weakness: an ignored write over a stored credential
  passes. The new `VerificationSpec::replaced(prefix)` would close it with one line per plan (prefix = their `binding()` prefix);
  not done because C-22 names only the three writes. Their Web success text `web-secret-done` ("checks only that it is there")
  stays true for them and is kept.

## [2026-11-17] Todo 54 issues
- The testkit fake cannot express "the interface holding the address kcc connects to" by default (it binds 127.0.0.1, Bridge0 is 192.0.2.1), so every default inventory now has `management_interface = None` and the conservative all-bridges rule. The migration matrix sets `migration::Fixture.interfaces` (renamed from `management_link`) to a Bridge0 holding 127.0.0.1 so its snapshots keep the real-router meaning.
- Pre-existing oversize files touched: `kcc-migrate/src/inventory.rs` (~378 pure LOC, +8 for `may_carry_management`, one inherent impl rule keeps it there) and `rules.rs` (~653, shrank). Split is out of scope.
- Not done (outside the plan's G-21 evidence list): MD5-hex triplicate (verify.rs, diff.rs, source.rs), the four reconnect loops, repeated `Catalog::for_router`, telemetry `load`/`lock` duplicates. Residual lines in plans/reports are still `<redacted>` placeholders (finding text mentions verify.rs:83-86; plan fix text does not).
- [todo 61] docs/BACKLOG.md still lists `cli-confirm-missing` (router printed as "-"); fixed by todo 61 for `ask` and the commit job, backlog entry not edited. `denied("-")` in principal.rs/preset store has no router and was left. Interactive (terminal) choice of rollback in `preset apply` is not additionally confirmed.

## [2026-11-17] Todo 55 gotchas (wt/r55)
- `fail_read_matching("show/interface", n)` is consumed first by router detection (`kcc_rci::capabilities` GETs `/rci/show/interface` when page facts are not cached), so the page answers "unreachable" from `Operation::open` before any handler read runs: a test can pass red for the wrong reason. Add `show_requires_post("show/interface")` so detection skips the inventory and the domain read (GET 404 -> POST fallback) takes the fault.
- The KN-1811 fixture has no PPP connection (`PPPoE0` only exists after a create); an existing-name test must create it first.
- Moving an askama `Template` struct to another module needs `use kcc_i18n::keys;` there when the template uses `keys::...` (`kit_outcome.html`).
- Never `pgrep -f <pattern>` + kill a process group from the tool shell: the pattern matched the tool's own command and the call was killed (the cargo run stopped too).
- Left as is (not cited by W3-05): `route_remove` reads the routes after a wipe with `unwrap_or_default()` (the guard banner then names nothing restored); `net_internet.rs` page status reads (`read_status`, `read_ping_check`) default to "unknown" by design.
- `page_kit/action.rs` (252 -> 256 pure LOC) and `page_kit/outcome.rs` (249 -> 254) were at the 250 ceiling before; `OutcomeView` moved to `page_kit/outcome/view.rs` to offset part of it. A split of `action.rs` belongs to the page_kit todo.
- Correction: the `OutcomeView` move was reverted (`clippy::field_scoped_visibility_modifiers` forbids its `pub(super)` fields); `page_kit/outcome.rs` is 249 -> 257 pure LOC, `page_kit/action.rs` 252 -> 256. Both were at the ceiling before; a split belongs to the page_kit todo.

## Backlog from todos 55 and 61 (orchestrator)
- An ordered line diff now exists twice: kcc-web `diff.rs` (Myers on digests) and kcc `cli/line_diff.rs` (LCS on digests, 16M-cell budget, refuses larger differences). Candidate for one shared implementation in a lower crate.
- 55: `route_remove` reads the routes after a wipe with `unwrap_or_default()`; `net_internet.rs` status reads default to "unknown" by design; the other TabLink copies (system pages, admin, DNS/VPN) belong to todos 57-59; `page_kit/action.rs` (256) and `outcome.rs` (257) exceed the pure-LOC ceiling and need a split in todo 57.
- 61: `denied("-")` in principal.rs and the preset store has no router and was left; a terminal-chosen rollback in `preset apply` is not additionally confirmed (typing the word is the choice); docs/BACKLOG.md still lists `cli-confirm-missing`.
- Tooling: `background_output` can fail with "Error fetching messages" for a finished worker; recover from the evidence log, notes and the diff.

## [2026-11-17] Todo 57 notes
- `crates/kcc-web/tests/config_pages/files.rs` was already 278 pure LOC before todo 57 (unchanged now; the new store tests went to `config_pages/store.rs`). `page_kit/change.rs` is 511 lines (pre-existing, not split here).
- `config_page/restore.rs::ask` still lists the store with `.unwrap_or_default()` only to show the backup's time in the dialog (falls back to the file name); not named by W2-11's critic, left as is.

## [2026-11-17] Todo 62 gotchas
- `nohup` sets SIGHUP to SIG_IGN for its children: the F-23 red run under `setsid nohup` lost the startup SIGHUP
  (timeout) instead of dying; a rerun without nohup showed the real failure (`Disconnected`: the process died).
  tokio's `signal()` replaces SIG_IGN, so the green run passes under nohup too.
- clippy denies `Variant { .. }` ("struct destructuring with rest"): spell every field as `name: _`.
- `cli/context.rs` (343 pure LOC) and `cli/persist.rs` (271) stay over 250 (were 395 and 274); `Ctx` methods
  cannot move to another module under "one inherent impl per type". Follow-up.

## Backlog from todos 57 and 62 (orchestrator)
- 57: Action::run refuses Change::Batch at run time (log + internal error + audit); the Batch variant itself remains because 42 callers build Change values (type-level removal later); Applied::Batch arm remains in action/ending.rs finished(). config_pages/files.rs (278 pure LOC) and page_kit/change.rs (511) still exceed the ceiling.
- 62: cli/context.rs (343 pure LOC) and cli/persist.rs (271) still over 250 (Ctx methods cannot move under the one-inherent-impl rule); kcc-web's own PERMISSIONS table should use kcc_domain::labels::permissions (assigned to todo 58 W1-11); the logs-before-serve_result and update-task-abort orderings in run_serve have no behavioural test (shown by code only).
- Process: the audit of todo 62's command-to-permission mapping is read-only evidence in .omo/evidence/perm-audit-r62.md.

## [2026-11-17] Todo 58
- auth.rs (558 -> 573 pure LOC: one error-shell closure per handler), admin_users.rs (609), admin_roles.rs (546),
  admin_shared.rs (297), session.rs (446) stay over the ~250 LOC ceiling (pre-existing); they need a split todo.
- `kcc_domain::labels::permissions` and the Web `PERMISSIONS` table both rely on `Permission::ALL` order; the
  Web side is guarded by `the_checkboxes_cover_every_permission_in_order`.

## [2026-11-17] Todo 60 issues
- W5-14 has no red test: with today's derived `Deserialize` the JSON round-trip cannot fail (critic), so the fix is
  structural (infallible `FromIterator<MapEntry>`), proven by the removed-pattern grep.
- presets reveal: a store read failing after the list succeeded is not reproducible black-box (list opens the same
  record); the fix is covered by the type-level match (Forbidden/NotFound/other), no red run possible.
- `ApplyError::Job` conflates a busy router with a job-state I/O failure in kcc-migrate; the Web still says "busy" for
  it. Splitting it is a kcc-migrate/kcc-app change outside this todo.

## [2026-11-17] Todo 63
- After a signal, rmcp logs ERROR "failed to send pending response during drain ... Tokio context ... being shutdown" when the in-flight tool call's reply is produced while the runtime shuts down: the reply is dropped by design (the client asked us to stop); the log level is rmcp's, not changeable from kcc.
- `kcc mcp stdio` still dies immediately on SIGHUP (default disposition); out of scope.

## Backlog from todos 59 and 63 (orchestrator)
- 63: main.rs bounds the runtime exit to 1 s for EVERY command (a blocking tokio stdin read cannot be cancelled and kept `kcc mcp stdio` alive after its shutdown); blocking work orphaned by a cancelled future now gets 1 s instead of an unbounded wait. After a signal rmcp logs an ERROR for the dropped in-flight reply (library log level); stdio still dies at once on SIGHUP.
- 59: `admin_shared::lock` (async tokio lock) and `admin_audit`'s inline jsonl attachment were left (different shapes).

## [2026-11-17] Todo 64
- crates/kcc/src/cli/persist.rs was already 271 pure LOC (over the ~250 budget) before this todo; now 275 (rustfmt split one call). Needs a split in a later todo.
- Left English: main.rs `cannot start async runtime` and the privilege-floor refusal (printed before a locale is resolved), clap parse errors, typed-error `Failure::text` detail lines (Detail::Text by design).

## [2026-11-17] Todo 56 gotchas
- The step wrapper `cmd | grep -v ... | tee` under pipefail reports exit=1 for a silent success (fmt --check): rerun unfiltered.
- No defects found outside scope.

## Notes from todos 56 and 64 (orchestrator)
- 56: `cargo fmt --manifest-path xtask/Cargo.toml` would reformat the untouched xtask `seccomp.rs`; CI formats only the main workspace. The fix for SEC1-10 is type-based (HtmlSafe) rather than name-based, so a new String field can no longer carry unescaped HTML.
- 64: translations to be checked by a native speaker are listed in the ledger entry for todo 64 (kk, be, de, ru/uk/be unit abbreviations). `cli/persist.rs` is 275 pure LOC (was 271; already over the ceiling). main.rs messages printed before locale resolution and clap's own parse errors remain English.

## [2026-11-18] Todo 65 follow-ups (not fixed, out of scope)
- kcc-migrate maps every `ChangeSet::reconnect` error to `ApplyError::Workflow` / keeps retrying for 120 s, so a refused
  URL move of a kcc.toml router (B-24) reaches the user only as a failed reconnect plus the server log line naming the
  url; a preflight refusal (plan has reconnect_url, target is config-defined) with its own ApplyError + i18n key would
  tell the user up front.
- kcc-web `router_check::failure` maps every `RegistryError::InvalidProfile` to WEB_ROUTER_ERROR_URL, also for
  credential-source or TLS-pin faults (pre-existing).

## Backlog from todo 65 (orchestrator)
- B-24: a refused kcc.toml router move reaches the user only as a failed reconnect (kcc-migrate maps every reconnect error to ApplyError::Workflow and retries for 120 s) plus a warn log; the router's own safety timer then restores the old state. A preflight refusal in kcc-migrate (own ApplyError variant, i18n key, all callers) would show the "edit kcc.toml" instruction at once.
- The Web maps every InvalidProfile to the URL message (predates 65).
- workflow.rs +9 pure LOC (explicit map_permission variant list, checked deadline); no file was split.

## [2026-11-18] Todo 66 (cancel-safety) - noticed, not fixed
- crates/kcc-app/src/poller.rs `run` (spawned per router by `subscribe`): if its task is aborted, the router's channel entry stays registered with no poller, so later subscribers wait for snapshots that never come. Only shutdown aborts it today.
- crates/kcc-web/src/wizard/live.rs `settle`: dropped while waiting for the applier lock, the `Applier` passed in is dropped instead of stored.
- crates/kcc-mcp/src/migration_tools/apply.rs `follow`: dropped, it drops the `done` receiver, so the applier the job hands back is discarded (the MCP call itself is not cancelled by rmcp today, BACKLOG).
- crates/kcc-web/src/session.rs `login`: removes the old session and inserts the new one under two lock acquisitions; dropped between them the caller has neither.
- Twelve readers over generic blocking runners keep `cancel-safe` while the runner says NOT (BACKLOG item rewritten).
- The gate missed `#[cfg(test)] #[path = "x_tests.rs"] mod tests;` and `#[cfg(test)]` + `#[expect(a, b)]` test modules (fixed in the gate).

## [2026-11-18] Todo 67
- Out of scope, noticed: `TraceCapture` (kcc-domain tests/support) uses thread-local `set_default`; events from `spawn_blocking` (audit writer) are not captured (T-01 INFERRED sub-point, not fixed here).
- Consumers that assert ABSENCE through `RequestRecord::command()` still see only the last line of a batch; moving them to `commands()` is left to the test-hygiene todo (69).

## [2026-11-18] Todo 68 open owner questions / gotchas
- OWNER QUESTION: the live migration SOURCE router (`KCC_LIVE_SOURCE_URL`) is now gated by the serial allowlist and the admitted `[outbound]` policy, but NOT by a `test_device = true` profile (it is typically the production router being migrated from, and marking it a test device would admit it to the write suites). Decide whether a separate read-only marker is wanted.
- Gotcha: `FakeRouterBuilder::user(..)` replaces the default admin account; add `DEFAULT_LOGIN` explicitly when seeding other users.
- Gotcha: the fake ends every session on a successful `user X password ...` (BEHAVIOUR.md "assumed"); a parser line is NonRetryable, so the next parse fails with `RciError::Auth` unless an idempotent read renews the session first.

## [2026-11-18] Todo 70 (wt/r70)
- deploy/podman/e2e.sh was broken since 5e1689d3 (kcc refuses secret files others can read): the e2e user's password file was chmod 0644, so `user add` failed silently inside the masked `accounts` step and web-login/dashboard-sse/backup-download failed (native and container). Fixed minimally for the X-13 proof: 0600 for native, and a podman secret (uid 65532, 0400) at /run/secrets/kcc-user-password for container mode (a 0600 bind mount is owned by container root). Todo 73's stricter step() will no longer mask this class.
- e2e native under --trace-dir hangs in cleanup when a step fails (see learnings); not fixed (todo 73 owns e2e error handling).
- The dns-lookup step's expected error text suggests `192.168.1.0/24` (kcc's own message, not a repo literal); no_secrets passes.
- Owner: required status checks for ci.yml jobs cannot be set from the repository (branch protection is a GitHub setting).
- Owner: "Alternatives resolved" row X-02 asks for sysroot clippy-driver in lint-completeness; the critic and the orchestrator prompt say keep `rustup run stable` (mirrors the vendored core). Kept; flagged.
[todo 73] Pre-existing: web-smoke.sh cleanup also does kill -INT + wait without a bound (same hang class as e2e.sh, no strace wrapper there). Not changed.

## [2026-11-18] Todo 69 part A (r69a): the workspace `disallowed-methods` entry reaches files outside part A
- Clippy reads the root clippy.toml for every workspace crate AND for xtask (no xtask/clippy.toml; clippy walks up the tree).
  Spawn sites outside kcc's tests that the new entry flags under `--all-targets -D warnings` (not edited: owned by part B / xtask):
  kcc-app tests (registry/client_pool.rs, jobs_recovery.rs, workflow.rs, off_runtime.rs, workflow/request_ids.rs,
  workflow/cli_partial.rs, workflow/batch_outcomes.rs, cli_line_binding.rs, audit_multiprocess.rs), kcc-telemetry tests/sink_proxy.rs,
  kcc-rci tests/outbound_proxy.rs, kcc-web tests (presets_pages/off_runtime.rs, migration_wizard/off_runtime.rs,
  migration_wizard/retention.rs), xtask/src (seccomp.rs, tool_output.rs, metric_docs.rs, tool_docs.rs, catalog_extract.rs).
  Each needs `#[expect(clippy::disallowed_methods, reason)]` on the narrowest item (or a crate-local spawning helper) before
  `cargo clippy --workspace --all-targets` and the xtask clippy job go green.

## [2026-11-18] Todo 69 part B (r69b): production defects found, not fixed (out of scope)
- `kcc_config_save` on a router id that is not registered (an admin with scope `*`, host `"cb"`) answers `internal`, not `invalid_arguments`: `crates/kcc-mcp/src/config_tools/state.rs:52-53` (`authorize_host` passes, `begin_change` -> `WorkflowError::Registry` -> `map_workflow` maps it to `McpFailure::Internal` at `crates/kcc-mcp/src/support/errors.rs:66-76`). Found by the E-23 random-input test (2 of 4096 cases); the test allows `internal` for change tools for this reason.

## Backlog from todos 69 and 73 (orchestrator)
- 69a: the F-30 log-line ordering check that replaced the 3 s windows is proven for the Web test (fails under a scratch kcc serve that ignores open brackets) but the MCP test still passes under that same scratch: its ordering check is weaker.
- 69a: the process-spawn lint lives in the root clippy.toml, which the separate xtask workspace also reads; xtask's spawn sites carry item-level expects (a nearer xtask/clippy.toml would replace the root file wholesale and drift).
- 73: step() now runs each step in a subshell, so a step cannot set variables for later steps; servers are launched by top-level launch_* functions. `kcc-fake-sinks` output is made colourless with NO_COLOR=1 because ANSI codes had defeated a wait that a masked failure used to hide.
- 69b: tests that assert absence through RequestRecord::command() still see only the last batch line (carried over from 67).

## [2026-11-18] Todo 71
- scripts/ci-local.sh runs `cargo vet --locked` for root only; it does not yet run the xtask store (`cargo vet --locked --manifest-path xtask/Cargo.toml`). scripts/ is owned by todo 73: follow-up there.
- `cargo vet` prints exemption-based paths still: getrandom 0.2.17..0.4.3 chain starts at a local exemption for 0.2.15; thiserror 2.0.21 and rand 0.9.5 remain exempted (no import covers them).

## fx44 gate failure (orchestrator)
- The root clippy.toml `disallowed-methods` added by todo 69a is read by every crate and by the xtask workspace, but 69a's worker verified it on `kcc` and `xtask` only. `cargo clippy --workspace --all-targets` fails in test code of kcc-rci, kcc-app, kcc-telemetry and kcc-web (they re-run their own test binary as a child or call `mkfifo`). Lesson: a workspace-wide lint change is verified with a `--workspace --all-targets --keep-going` clippy run, not per crate. Fix: item-level expects (todo 69y), same standard as the xtask expects.

## [2026-11-18] Todo 69y
Sites: rci outbound_proxy (1 fn), telemetry sink_proxy (1), app registry/client_pool (1), off_runtime (1), audit_multiprocess (2), jobs_recovery (1), web presets_pages/off_runtime, migration_wizard/off_runtime, migration_wizard/retention (1 each).

## [2026-11-18] Todo 72
- Stub-first red needed: tests referencing the new behaviour compile only with a read stub, and warnings=deny rejects an unused module, so red was shown with the guidelines read but not compared. No other issues; CONTRIBUTING/AGENTS only name the command, so no doc edit.

## [2026-11-18] Todo 74 ledger (docs/review-ledger-2026-11-15.md) - doubtful rows for the orchestrator
- D-07 (65f93954): no code change; the presence-check limit is documented in verify.rs rustdoc and docs/BACKLOG.md. The binding critic correction allows "document it as a known limit" for secrets; the rule-count part of the fix text is not implemented. Ledger note says so.
- X-02 (66e93982): kept `rustup run stable` (following the critic) instead of the plan's alternatives row (clippy-driver from the active sysroot); commit body flags it as "owner to decide".
- W2-18 (b9b80411): Change::Batch kept, Action::run refuses it at run time; the alternatives row said remove the Batch arm.
- SEC1-05 and W1-01 (59a18c4f): not named in the commit body; closed with F-01 (H7) per the plan's GAP-4 row; tests name them.
- 72 ids have no test doc comment naming them at HEAD (structural, docs, CI, dead-code); the notes say "no behavioural test" or how they were proved.

## [2026-11-18] F1a (todos 1-25) audit
- APPROVE 25/25, no blocker. Report: .omo/evidence/F1a-kcc-review-fixes.md
- BACKLOG: management detection maps a non-bridge Unknown verdict (pinned address on no interface) to Write (interfaces/management.rs:29-38); todo 11 text asked fail-closed for "cannot decide".
- NOTE: todo 23 adds bytes = "1.12.1" directly to kcc-rci (in Cargo.lock at 349b7fb, not a workspace dep): allowed by Must NOT have, stricter F1 wording disagrees.

## [2026-11-18] F1b (todos 26-50)
- APPROVE all 25; backlog: audit prune_rotated at rotation kills writer on unreadable/tampered old archive (pre-existing; state.rs:158-174), N9 ledger attribution (fix in 034ec919). Report .omo/evidence/F1b-kcc-review-fixes.md

## [2026-11-18] F1c (todos 51-75 + Must-NOT checks)
- APPROVE, no blocker. Report: .omo/evidence/F1c-kcc-review-fixes.md. Notes: bytes in kcc-rci is a non-workspace direct dep (allowed by Must NOT have line 211, stricter F1 wording); assets-check escaping rule covers kcc-web only; CLI and Web keep two diff implementations.

## [2026-11-18] F3 real manual QA
- F3 verdict APPROVE (items 1-9 PASS). Report: .omo/evidence/F3-kcc-review-fixes.md.
- BACKLOG: same-realm `--user-password` ignored for the hash line but used as reconnect credential -> 900 s wait, router rollback, CLI says "rejected before anything was sent" (exit 4).
- BACKLOG: [logs] collector ignores routers added at run time until restart.
- Gotcha: kcc-fake-router binary has no `show running-config` fixture or secrets; Playwright MCP needs npx (absent).

## [2026-11-18] F2 code quality review
- G1 cold run on 1defea38: every step green except `cargo deny check` (only RUSTSEC-2026-0542/0543, known owner decision). Evidence: .omo/evidence/F2-kcc-review-fixes.log, report F2-review-kcc-review-fixes.md.
- BACKLOG: crates/kcc-web/src/advanced/deliver.rs:126-128 `read_with` says cancel-safe (two comments) but its callers pass client.parse/show/get, which are NOT cancel-safe by the sign-in rule (A-18 caller/callee contradiction left over).
- BACKLOG: mutants missed audit writer.rs:134 `stop` -> () (writer-failure cleanup unasserted) and state.rs:127 `>`->`>=` (rotation boundary). mask.rs 22/22 caught.
- Gotcha: cargo-mutants needs `--cap-lints true` + CARGO_BUILD_WARNINGS=allow here, else the deny profile makes most mutants unviable.

## [2026-11-18] F4 ideal-state fidelity
- F4 APPROVE: IS-1..IS-14 re-run on 1defea38 (f34); perturbations P1-P5 red then green, worktree clean. IS-14 G1 conditional on the deny owner decision.
- BACKLOG: module-level #![expect] left in kcc-app/src/backups.rs, kcc/src/server*.rs (split in df2fb8ff), kcc-telemetry/src/metrics/system.rs; not in docs/BACKLOG.md.
- NOTE: kcc audit verify on a torn tail before any writer start reports intact (exit 0) without mentioning the torn bytes.

## [2026-11-18] r77 follow-ups (not changed)
- kcc-migrate `management::may_carry` (crates/kcc-migrate/src/management.rs): with the management interface unknown
  only bridges may carry it, so a migration line re-addressing a non-bridge WAN on a router reached through NAT or a
  relay is not a management line. Same gap as the domain fix, separate classifier; kcc-migrate is another worker's.
- Wi-Fi SSID, key, encryption, channel and power planners (crates/kcc-domain/src/wifi.rs) are fixed Risk::Write even
  on the access point kcc's host may be associated with; pre-existing, outside the management-verdict seam.
- crates/kcc-testkit/src/lib.rs (517 pure LOC) and crates/kcc-domain/src/interfaces/management.rs (283, with its unit
  tests) were already over the 250 LOC ceiling before this change (497 and 274).

## [2026-11-18] F1r2 round-2 review
- REJECT: 299dfc04 stopped_failure prints "router is back on its saved configuration" after a RollbackRestarting (scheduled-reboot rollback silent >120 s); reproduced, see .omo/evidence/F1r2-repro-stopped-restarting.log. Preset CLI run.rs:130-137 same path. 0dd10389, b457d99a, ce2f70f5 approved.

## [2026-11-18] F3r2 round-2 manual QA
- S1 (B1 fail-closed) PASS, S2 (B2 typed password) PASS, S3 regression PASS; no blocker. Report: .omo/evidence/F3r2-kcc-review-fixes.md
- BACKLOG: migration refused for a same-realm login hash without a typed password prints the generic "Migration stopped. Review the result before choosing rollback." instead of the documented "router password required" (ApplyError::PasswordRequired -> migrate-apply-failed).
- BACKLOG: a CLI change whose read-back fails is audited only as cli.change failed {error:router}, without the sent line.
- [2026-11-18] F2r2: G1 on ce2f70f5 clean worktree fully green (cargo deny check now passes); evidence .omo/evidence/F2r2-kcc-review-fixes.log

## Round 2 (orchestrator)
- B3 (frozen blocker, regression of 299dfc04): a scheduled-reboot rollback that returns RollbackRestarting must not be reported as "back on its saved configuration". Lesson: a new user-facing claim about router state needs a test for every outcome of the call that feeds it, not only the proven one.
- F3r2 and F1r2 backlog items are being folded into docs/BACKLOG.md by the B3 worker.

## [2026-11-18] F1c2 confirmation of 47801a5f
APPROVE: F1r2 BLOCKER 1 closed for migrate and preset (silent extender rollback now prints the restarting sentence, exit 6; proven rollback unchanged). Notes: restarting sentence printed twice on migrate (stdout+stderr); commit body says three preset rollback sites, there are two. Report: .omo/evidence/F1c2-kcc-review-fixes.md

## [2026-11-18] F2c G1 confirmation on 47801a5f: 48/48 steps EXIT=0, workspace tests passed=1805 failed=0 ignored=7; evidence .omo/evidence/F2c-kcc-review-fixes.log
