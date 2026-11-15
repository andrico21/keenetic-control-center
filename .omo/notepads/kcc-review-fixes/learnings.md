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
