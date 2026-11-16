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
