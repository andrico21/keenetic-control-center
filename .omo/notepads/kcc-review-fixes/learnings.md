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
