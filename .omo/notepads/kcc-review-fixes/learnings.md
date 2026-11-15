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
