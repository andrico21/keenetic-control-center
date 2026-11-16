# learnings - kcc-review-fixes (append only)

## [2026-11-15] Carry-over from the previous plan (kcc-review-remediation)
- Workers' targeted checks miss repo-wide fixtures; the orchestrator's G0 gate is the arbiter. Verify the evidence log and the diff, never the summary.
- Plain cargo on stable 1.100.0; fmt only with `cargo +nightly-2026-10-03 fmt --all`; `.map_or_default(..)`; `[build] warnings = "deny"`.
- Dummy secrets built at run time; RFC 5737 addresses; the anonymizer flags 44-char base64, `ns3 ` blobs, RFC1918 literals.
- Generated files (keys.rs, MCP_TOOLS.md, METRICS.md, catalog, seccomp) are regenerated, never hand-edited.

## [2026-11-15] Todo 1 progress (SEC1-02, worktree r1)
- `validate_username` is now `pub` in kcc-app accounts; `INVALID_USERNAME_ACTOR = "<invalid-username>"` lives next to it.
- Web login replaces an invalid name with the marker at the boundary; the marker is itself invalid, so `authenticate` takes the unknown-user path (dummy Argon2 -> Invalid). `authenticate` also checks the name first (`valid_name && candidate.username == username`) so an invalid name never matches and runs the same state-update + dummy Argon2 path.
- The failed-login page re-renders an empty username field for an invalid name (no echo of the 1 MiB text, no marker shown).
- `Actor::new` is no longer `const`; it truncates with `floor_char_boundary(Actor::MAX_ID_BYTES = 64)`. No const-context callers existed.
- Gotcha: clippy `too_long_first_doc_paragraph` fires on test doc comments too; keep the SEC id sentence short and split the paragraph.
- kcc-web tests/auth.rs Fixture field `_core` renamed `core` (now read for the audit dir); `login_as(cookie, csrf, (user, pass))` helper added.

## [2026-11-15] Todo 6 progress (worktree wt/r6)
- Shared masker lives in `kcc_config::mask` (`is_secret_name`, `mask_json(value, marker)`, `redact_text`, `redacted_config`, `redacted_copy`, `REDACTED_MARK`); kcc-config gained the workspace dep `serde_json` (Cargo.lock: one dependency edge).
- `secrets::redact` now masks every `ns3` payload itself (token kind kept: `ns3 <redacted>`); `mask::redacted_config` shows each ns3 token as the bare `<redacted>` word (the download/backup/CLI display form). The consumer re-mask copies (CLI redact, MCP backups, Web config text, Web preview, wizard `shown_line`, migrate `redact_ns3` and preset `redacted`, testkit anonymize arm) are deleted.
- `redact_text` is line-wise with a block stack, so it works on whole configs, fragments and single lines (the seam for todo 7's text bodies and `message` arrays); unreadable lines become `<indent><redacted>`.
- Gotcha: a pub fn in kcc-config used only by integration tests trips `dead_code` in the lib-test build; unit tests go inline via `#[cfg(test)] #[path = "mask_tests.rs"] mod tests;`.
- Gotcha: whole-member masking also masks container members named like secrets in Web request previews (`crypto ike key` preview now shows `"key": "********"`).
- Gotcha: `Interface.extra.authentication` is read by the Web AP rows for password presence; C-04 keeps `authentication` as presence-only (`{"wpa-psk": true}`) instead of dropping it.
- [2026-11-16] Todo 6 done in wt/r6: green on kcc-config/mcp/web/kcc/domain + migrate/testkit; the superset test stores kcc-style secrets on every fake profile first (the bare fixtures hold none, so a comparison over them alone is vacuous) and asserts each former classifier masked >0. Target dir and r6 logs removed.

## [2026-11-16] Todo 7 progress (worktree wt/r7, H1 / D-H1)
- New kcc-config API: `mask::redact_text_with(text, marker)` (`redact_text` = it with `<redacted>`; changed tokens become the bare marker word) and `mask::mask_reply(value, marker)` = `mask_json` + every JSON string redacted as configuration text (an unreadable string becomes the marker).
- One decision per layer: MCP `support::access::reply_for(identity, host, value)` (rci_read, rci_batch read and change results, cli_parse); Web `Rendered::{body,json}` with the existing `Dispatch::reveal()` (job stream now computes `reveal` per listener instead of `false`); CLI `fleet::mask_unless_revealed(ctx, target, value)` (print_body for `show`/`rci get`, `rci::shown` for batch reports). Each uses the router-scoped check; any failure masks.
- MCP `shape` still masks secret-named members for every role (pre-existing contract, test `raw_interface_read_redacts_planted_secret`); RevealSecrets only lifts the string redaction.
- W4-14 is not observable end to end: no Show command (the only Read risk) has a path or argument the SecretValue registry protects (`show crypto ike key` takes no arguments). Read batches (Web RCI console, CLI `rci post|batch`, MCP `kcc_rci_batch`) now send `expose_for_send()`; evidence is a grep.
- The fake router serves `show running-config` only through `show_fixture("running-config", {"message": [...]})`; it has no CLI `parse "show ..."`, so the CLI console has no end-to-end test (it shares `Rendered::body` with the explorer).
- Explorer "stored lines" view left as is: it already redacts for every role (`<redacted>`).

## [2026-11-16] Todo 2 progress (D-01 / NEW-1, worktree wt/r2)
- `firewall/change/render.rs::render_property` now takes the `OwnedRuleProperty` from `Verification::property()` (new accessor in verify.rs) and has one arm per variant; it returns `DomainError::InvalidResponse` when the variant's negation disagrees with the validated body's `no` member or the plan is not a property plan. `Description(None)`/`Schedule(None)` render `no access-list L rule N description|schedule`.
- Web no-op: new kit variant `page_kit::submit::rejected::Rejected::Unchanged` -> `Submission::unchanged` (abandon "unchanged", info outcome `WEB_SYSTEM_UNCHANGED`, no new i18n key). `firewall_page/rule_props.rs` returns it when the fresh `ConfiguredRule` already has the submitted description/schedule (covers "nothing to clear" and re-saving the same value).
- MCP (`kcc_firewall_write` refuses `index`/`description`) and the CLI (`rule-property` only sets values) cannot express a clear, so D-01 is unreachable there; their property paths share the fixed renderer.
- The fake router already applies `no access-list ... rule N description|schedule` (testkit cli_engine/acl_rules.rs); no fake change needed.
- Gotcha: editing domain sources while a detached RED build is still compiling lets the build pick up the fix; restore HEAD content (new mtime forces a rebuild) and rerun the RED.
- [2026-11-16] Todo 7 done in wt/r7: kcc-mcp/kcc-web/kcc tests green (exit 0), fmt+clippy clean; target dir and r7 logs removed.
- [2026-11-16] Todo 2 done: kcc-domain+kcc-web tests green (65 binaries), kcc cli_domain_writes green, clippy 4 crates clean, cancel-safety ok. Target dir and r2 logs removed.

## [2026-11-16] Orchestrator notes (merge flow)
- A worker worktree cut from a temporary wip base must have its patch generated with a product pathspec: `git diff --binary master wt/rN -- crates docs CHANGELOG.md Cargo.lock Cargo.toml`, otherwise it carries reverse hunks of the .omo state files that master gained since.
- Todo 7 notes: MCP raw tools (kcc_rci_read, kcc_rci_batch, kcc_cli_parse) redact every string as config text for roles without RevealSecrets; a string that cannot be read as configuration lines (for example an unterminated quote) shows only the marker. Accepted fail-closed; candidate for BACKLOG if viewers report over-masking.

## [2026-11-16] Todo 3 progress (G-01 / H4a, worktree wt/r3)
- One shared lookup `kcc_migrate::maps::WordMapping::find(mappings, word)` (generic over the decision type: `&str` in the migration planner, `Option<&str>` in the preset classifier): an exact entry wins, else a `WifiMaster<n>/<child>` word follows its radio's entry (`interface_names::is_radio`), keeping `/<child>`. rules.rs wraps it in `mapped()` and uses it for `apply_mappings`, `references-mapped-name`, bridge-member lookup and planned interfaces.
- `explicit_item` maps `Copy` lines too (output SecretString and redacted twin); a copy whose output changed is reported `Remap` (rule id stays `copy-ns3-secret`/`copy-wireguard-private-key`).
- `conflict_rule` sends a `Copy` rule's line to the `scalar-conflict` rule when the MAPPED line conflicts with the target; `scalar_conflict(source, sent, ..)` compares the sent line but checks `overwrite_scalars` with the SOURCE key, because Web/MCP `overwrite_keys` derive keys from source lines.
- Gotcha: a preset ns3 line is only buildable with a real `kcc_config::ns3::encode` payload (catalog `validate_secret`); a random blob gives `Unsupported` with no result.
- Gotcha: clippy `field_scoped_visibility_modifiers` forbids `pub(crate)` fields: private fields + `const fn` accessors.

## [2026-11-16] Todo 5 progress (H7: F-01, SEC1-05, W1-01; worktree wt/r5)
- `crates/kcc/src/state_watch.rs`: `StateWatch` polls `api_keys.json`/`users.json` every 2 s (stat by inode+mtime ns+size in `spawn_blocking`, then content). Keys: set of (name, hash, role); a change calls `TransportReload::reload_keys` (the Web keys page path, now serialized by a `Mutex` so an earlier read cannot install over a later one). Users: `WebState::end_stale_sessions()` re-reads `AccountStore::standings()` and ends sessions whose account is gone/disabled/other role/other password fingerprint.
- One task owns the watcher: `select!` over the 2 s `Interval` and the SIGHUP `Signal`; SIGHUP runs the same pass (forced), then the existing `kcc.toml`/roles reload, whose "configuration reloaded from SIGHUP" line stays last (serve_refresh waits on it). The watcher starts in the kit's reload callback (keys need the reload handle).
- Fingerprint = SHA-256 of the opened PHC string (`kcc_app::accounts::standing::PasswordFingerprint`, Debug redacted), kept only in `Session`. Login reads it BEFORE `authenticate` (a reset in between makes the old password fail, or the session mismatches and ends). Own password change uses `AccountStore::change_password_for_session` (returns the new fingerprint) and `SessionStore::set_fingerprint`.
- Race design: `SessionStore` has an `account_reads: RwLock<()>`; sign-in and own password change hold a read guard from the account read until the session records it; `end_stale` holds the write guard across its read and the session sweep. Without it a pass could judge a session against an older read and log the user out of their own new session (or miss a reset).
- Logs: `kcc::state_reload` debug per real reload (`file` field); `kcc::state_watch` debug "rewritten without a change" and a start event with `interval_ms`, warn (once per file version) when a file cannot be read/parsed. Process tests use `[observability] log_format = "json"` and match `target` + `fields.file`; the fixture waits for the start event (else a touch right after "listening" lands before the watcher's baseline).
- Gotcha: the bash tool does not keep `cd` between calls; a detached cargo started without `cd` ran in the main repo (it failed at target lookup, no build). Always `cd` inside the detached `bash -c`.
- Gotcha: `cargo xtask ...` without CARGO_TARGET_DIR builds into `<worktree>/xtask/target`; set the target dir or delete it after.
- [2026-11-16] Todo 5 done in wt/r5: 7 process tests RED then GREEN; cargo test -p kcc -p kcc-app -p kcc-web --all-features EXIT=0 (774 passed); clippy, fmt --check, cancel-safety clean. Target dir and r5 logs removed.

## [2026-11-16] Todo 4 progress (H5/G-03, M13/G-04; worktree wt/r4)
- `TargetInventory::login` (new pub field, from the inventory client's credentials) lets both planners know kcc's own login. `planner::LoginPassword::of(line, login)` -> Untouched/Set (`user <login> password plain|md5|nt ..`)/Removed (`no user <login> password ..`); `is_management_line(line, mgmt_iface, login)` is now pub(crate) and also takes the login (other users' `password plain` lines stay management as before).
- One credential tracker: `apply/credential.rs::LoginCredential` (login + replacement + `replaced` flag). `reconnect::complete_line` calls `applied(line)` before the reconnect and reconnects with `current()` (None = keep the client's credential) until the login's Set line ran; raw restore uses `restored()` (the replacement, as before).
- `preflight::validate_credentials` scans ALL phases: login Set line outside management -> Validation; Removed -> Validation; Set needs `management_password` (PasswordRequired), plain must equal it (`planner::plain_password` parses the secret as config text).
- Presets: `convert::migration_plan` runs the same classifier (so other users' plain lines also go to the preset management phase now); `presets::apply::request` sets `management_password` from the reviewed plain login line (what the migration front ends do with `passwords.get(login)`); a same-realm md5 copy has none -> PasswordRequired before any write.
- Web presets surfaces (launch texts, preview phases/count, reveal) ignored `phases.management` (preset plans never had one): fixed, else the run stream showed an empty line.
- Fake router: a `user X password md5 <ha1>` line now updates the account's HA1 (and clears sessions) like `plain` did.
- Gotcha: the fake catalog cannot build `no user <login> password md5 <hash>`, so a Mirror removal of the login's hash is planned Unsupported and never sent; a Mirror-specific guard had no observable effect and was dropped.
- Gotcha: a preset apply test without an injected clock hangs ~15 min on a rollback (recover waits safety_seconds on the system clock): give every run an advancing MockClock shared with the fake.
- [2026-11-16] Todo 4 done in wt/r4: RED 3/3 then GREEN; cargo test -p kcc-migrate -p kcc --all-features ACCEPTANCE_EXIT=0 (311 passed); kcc-web+kcc-mcp+kcc-testkit 644 passed; fmt --check, clippy (migrate/web/kcc/testkit), cancel-safety clean. Target dir and r4 logs removed.

## [2026-11-16] Todo 8 progress (worktree wt/r8; B-08 escalated, C-07 + D-15 done)
- `ValidatedRequest.value` is private; read it with `value()`; in-crate `with_secret(protected)` replaces the old `validate_secret` field writes. Mechanical getter edits across domain/web/mcp/kcc and catalog unit tests.
- `ChangeOp` gained `commands: Vec<CliCommand>` and `push(command)` (pushes the command and its request). Planners whose lines carry words their bodies lack (VPN clients/servers context names, VPN secret templates, DNS FQDN members, KeenDNS proxy upstream) build the `CliCommand` at plan time; their `change_request` returns `operation.commands`. Web `vpn_checks::merge` appends both vectors.
- KeenDNS proxy upstream: the line itself is validated with `validate_cli` (protocol keyword, IP/MAC host, port). The catalog has no `protocol` argument and types `fqdn` as the literal `FQDN`, so a host name is refused (CHANGELOG). The read-back expectation `{protocol,host,port}` is built at plan time (`keendns::verification::upstream`).
- Security levels (cloud, ip http/ssh/telnet) validate `{"level": name}` directly: the catalog accepts it.
- fake router `request_log()` keeps only the LAST line of a parse batch in `RequestRecord::command`.
- profile_coverage requires every kcc-domain test suite to iterate `support::PROFILES`.
- [2026-11-16] Todo 8 (wt/r8): C-07 + D-15 done and green (catalog/app/domain, web/mcp/kcc, clippy 7 crates, fmt); B-08 strict binding escalated (see issues.md). Target dir and r8 logs removed.

## [2026-11-16] Todo 8 follow-up (wt/r8): KeenDNS proxy upstream host names restored at the catalog source
- The manual's `ip http proxy upstream` table row `fqdn | FQDN` was parsed as the keyword literal `FQDN`; `xtask/src/catalog_build.rs` `parse_value_type` now maps `("fqdn", "FQDN")` to `String` (name-scoped on purpose: 4.3 `object-group fqdn include/exclude` has `address | FQDN` and stays a keyword, as before todo 8). Pinned in `expected.rs` TYPED_ARGUMENTS and the `ambiguous_value_cells_map_to_semantic_types` table. Regenerated 4.3/5.0/5.1: only the three `ip.json` `fqdn` entries changed.
- `cargo xtask catalog build` needs no network once `catalog/.cache` is copied into the worktree; it is deterministic (rebuild = same shards).
- `plan_proxy_upstream` refuses port 0 in the domain (the Web already did; MCP/CLI accepted it). The catalog's `port` Integer has no bounds.
- `cargo +nightly-2026-10-03 fmt --manifest-path xtask/Cargo.toml --all -- --check` reports pre-existing diffs in xtask seccomp*.rs (not touched here).
- New suite `crates/kcc-domain/tests/keendns_upstream.rs` (iterates PROFILES for profile_coverage).

## [2026-11-16] Todo 9 progress (wt/r9)
- Shared rule in `kcc-domain/src/cli_token.rs`: `validate`/`token` (one bare word), `object_name` (ObjectName, refused as `InvalidCliToken`), `quoted`/`quoted_text` (free text). Local copies of `validate_token` in schedules/logging/storage were removed in favour of `cli_token::validate`.
- Clients plan now renders its lines at plan time (`ChangeOp::push`), so a bad registration name is refused by `plan_*`, not at apply. `clients::registration_name` (moved from the Web) is shared by Web and CLI.
- `plan_register`/`plan_static_lease` take `kcc_rci::Mac` (the existing type; no new type needed).
- Fake router bug fixed: `apply_known_host` re-joined unquoted words with spaces, so a quoted name with a space failed verification; it now rebuilds the node from tokens (quoting preserved).
- The fake router has no `dns-proxy filter profile description` grammar: DNS description tests check the planned line (`expose_for_send`), not `request_log()`.
- `catalog.validate_cli` refuses any quote, so `validated_lines`-style re-validation cannot run on lines with quoted free text.

## [2026-11-16] Todo 10 progress (worktree wt/r10; W2-01 W3-01 N11 N12 W4-11 W2-05 W3-02 W4-06 W3-07)
- Kit: `Submission::new(action, params, form, resubmit)` now takes the `Resubmit` (required). `carry` always asks for the planned stakes (`Planned` holds `Stakes`: highest op risk + "some op is Management"), raised to the descriptor risk (`Action::effective`), unless the page's own confirmation covers it (`.confirmed_by_page(risk)`; used by the typed-name deletes: WAN, segment, VPN tunnel; router-user/VPN-server password dialogs cover Management). `.confirming(risk)` is the extra early check (no resubmit arg); `confirming_planned` is gone.
- A role that may not take the planned risk gets no dialog: `carry` checks `Action::may_take` first and the run answers `forbidden` (keeps answer_tests' operator/destructive expectations).
- `Plan::at(Stakes)`: management bracket follows `stakes.management()`, so a Destructive plan that contains a Management op keeps the fail-safe timer.
- `Params::again(path)` = path + the request's pairs (minus confirm/confirm_name) as query: the resubmit of query-reading handlers. Form-only handlers that can plan management must read the query too (segment create now merges RawQuery + form).
- Firewall `assess` no longer hand-checks `Destructive`; `Action::plan` (SafetyNet::required) decides.
- Kit unit tests that need a change to RUN wrap the handler in an axum Router with `middleware::from_fn(crate::brackets::own)` (else `brackets::hold()` refuses before sending).
- Test helper `tests/support/asked.rs`: `asks_first` (dialog key marker + zero commands) and `runs_in_timer` (arm first, disarm last).
- KeenDNS release: `keendns::plan_drop_name` is Management when the profile URL host is the booked name or under it (`reached_by`, inline unit test in `keendns/tests.rs`); no DNS lookup.
- [2026-11-16] Todo 9 (wt/r9): done and green (kcc-domain/mcp/kcc tests EXIT=0, kcc-testkit+kcc-web tests EXIT2=0, fmt check 0, clippy 6 crates 0). Target dir and r9 logs removed.
- [2026-11-16] Todo 10 done in wt/r10: RED captured (kit, wifi, segments, firewall, keendns), kcc-web 443 passed EXIT=0 (final run after hoisting resubmits), kcc-mcp+kcc 341 passed EXIT=0, clippy kcc-web+kcc-domain and fmt --check clean; golden diff = segment create dialog + its cascade. Target dir, r10 logs and scratch removed.
