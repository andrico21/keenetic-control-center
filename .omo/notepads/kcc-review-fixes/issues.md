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
