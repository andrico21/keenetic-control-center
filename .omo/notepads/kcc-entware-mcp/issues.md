
## [2026-11-20] Todo 6 (e6) findings for later todos
- russh-cryptovec 0.62.0 calls `mlock`/`munlock` on every CryptoVec buffer (via nix on unix, VirtualLock on Windows) and ignores failures. Once kcc-ssh runs inside `kcc serve` (container), the traced seccomp profile (todo 18) must include `mlock`/`munlock` or the calls fail with EPERM (silently ignored by russh, but a kill-on-violation profile would kill the process). Check the profile's default action when tracing the SSH leg.
- russh logs through the `log` crate (debug/trace), not `tracing`: todo 7's no-secret-in-logs byte test must capture `log` records too (LogTracer via tracing-subscriber's `tracing-log`).
- `cargo deny --manifest-path xtask/Cargo.toml check` warns `unmatched-skip` for thiserror@1.0.69/thiserror-impl@1.0.69 (root deny.toml read for the xtask workspace); pre-existing, exit 0.

## [2026-11-21] Todo 24 (e24): out-of-scope findings
- `crates/kcc-web/src/admin_shared.rs` `Timestamp::at` calls `humantime::format_rfc3339_seconds(time).to_string()`. humantime's Display returns `fmt::Error` for year >= 10000, so `to_string()` panics. A hand-edited `api_keys.json` with `created_at`/`last_used_at`/`expires_at` >= 253402300800 would panic the keys page handler. This predates todo 24, which only adds `expires_at` to the same path. `kcc_app::api_keys` formats with `write!` instead and fails closed.
- `crates/kcc-web/src/admin_keys.rs` was already 325 pure LOC (over 250) before todo 24 and is now 346. A split (handlers vs. region/dialog builders) is a follow-up.
- [2026-11-21] (todo 23 verifier, pre-existing, not fixed) The persist layer parses state files into serde_json::Value before the typed StateDoc, so a state file with a duplicate key (e.g. "read_only": true, "read_only": false) is accepted with the last value winning, for ALL StateDocs (mcp_settings.json, roles.json, api_keys.json, ...).

## [2026-11-21] Todo 23 residuals from the re-verifier (not changed in todo 23)
- R2 (for todo 29): duplicate OIDC `claim_value` / `scope` entries in `auth.oidc.role_mappings` / `auth.oidc.scopes` are accepted. With state mappings `[x -> viewer, x -> admin]` an actor may set `[x -> admin]` and it is not an "added" mapping. Whether that raises a token holder's role depends on how todo 29 resolves several mappings for one value. Todo 29 must either refuse duplicate `claim_value`/`scope` in `settings/mcp_schema/checks.rs` or define resolution as union ("any mapping grants") so the ceiling stays sound.
- R1 (policy question for the owner): turning on a listener auth mode (e.g. `auth.main.mtls = optional`) makes an owner-configured kcc.toml role target (e.g. mTLS `default_role = admin`) live without a dominance check against the acting role; it is flagged safety-reducing (password re-ask). Owner to decide whether activating an existing target must also require the actor to dominate it.

## [2026-11-21] Todo 4 (e4) residuals (not changed)
- `storage::wait_initialized` returns as soon as `show media` reports ext4 for the medium. Initializing a drive that already is ext4 can return on the first read if the real router still reports the old ext4 filesystem right after accepting `media initialize` (the fake removes it at once). Todo 10 should confirm the real router's `show media` shape during initialization (live) or wait for a non-ext4 read first.
- The `show rc opkg` read-back of removals (`no opkg chroot|dns-override|disk`) uses `PresencePredicate::Absent`, which needs `show rc` to return an `opkg` object. The fake always returns `"opkg": {}`; if a real router omits `opkg` once every setting is gone, the last removal would fail verification although applied. Check on a live test router (todo with live coverage).
- `entware::configured_media` resolves an ambiguous label (two media with the same label) or a duplicated uuid to `None`, so the guard is off for those drives; kcc's own planners never write such an `opkg disk`, but a hand-made one would not be guarded.

## [2026-11-21] Todo 7 fix (e7f): hardening idea, not changed
- kcc-ssh AppendKey/RemoveKey scripts follow a pre-planted `/opt/etc/dropbear/authorized_keys.kcc` symlink (the `>` redirection writes its target, then `mv` makes the file the link). Planting it needs root write in `/opt/etc/dropbear`, so it is not a trust-boundary crossing. A leading `rm -f A.kcc` would close it, but the plan fixes the rendered strings character for character, so the scripts were left unchanged; a plan change is needed to add it.

## [2026-11-21] Todo 25 (e25): residuals, not changed
- `crates/kcc-web/src/admin.rs` was 262 pure LOC at HEAD (over 250) and is 283 after todo 25 (TransportReload fan-out). `TransportReload` cannot move to a child module without a path change (`pub use` is banned); a split that moves `ServerFacts`/`Fact` out (todo 27 touches the server page) would bring it back under the ceiling.
- `KccMcp` keeps the rmcp `#[tool_handler]`-generated `get_tool` (schema lookup for SEP-2243 headers) ungated: a tool a tightening removed still resolves its input schema there; the call itself is refused by `call_tool`. Harmless today; gate it if a later rmcp uses `get_tool` for dispatch.

- [2026-11-21 todo 4 fix] Owner decision pending (verifier R1/R2, not changed): the Entware drive guard is case-sensitive in `storage.rs` `admit` (`system eject media0` passes when `opkg disk` names `Media0`) and in the label filter of `entware/drives.rs` `resolve` (`opkg disk FIXTURE-MEDIA:/` resolves to none), while the uuid match ignores case; and when one medium's label equals another medium's uuid the uuid wins. If the router matches ids/labels case-insensitively or resolves `X:/` by label first, the CLI/MCP guard can protect the wrong drive or none. Hardening option: `eq_ignore_ascii_case` in `admit` and the label filter, and treat every matching medium (label or uuid) as the Entware drive instead of `None` on ambiguity.

## [2026-11-21] Todo 25 verifier notes for todo 26 (not defects)
- `McpApply` has no production caller: in `crates/kcc/src/server.rs` the live handler is moved into the kit factory closure. Todo 26 must construct `McpApply` from the same `Arc<ArcSwap<KccMcp>>`, gates cell and `TransportReload` and call it from `restart`/`apply_live`.
- `server_listeners` must add a test with TWO registrations of the same kind (a restart) proving StateWatch/SIGHUP are not started again (the todo 25 test cannot tell once-per-registration from once).
- `TransportReload::register`: when reading the keys fails the server is registered and keeps its start-up role policy until the next role reload; the error is returned. Todo 26's restart path must treat that error as a failed health step.
- [2026-11-21] Todo 29 BLOCKED (owner): enabling the kit `oauth` feature also brings RUSTSEC-2026-0387 (crypto-bigint 0.5.5 via jsonwebtoken 11 `rust_crypto` p256/p384), not covered by D-RSA. No compatible fix (0.5.x unpatched; kit 3.21.1 is the latest and pins jsonwebtoken 11; `[patch]` forbidden). Needs an owner decision: a second ignore with a verify-only reason, or wait for a kit release on jsonwebtoken 12. Measurement in decisions.md "Todo 29 (e29)".

## [2026-11-21] Todo 10 (e10) residuals (not changed)
- The setup's component commit applies EVERY staged component change, including ones a user queued before the setup (`show components pending` is not required to be empty). The commit's check then demands them too. A preflight refusal "components pending" would be a plan change.
- `crates/kcc-domain/tests/support/mod.rs` was over 250 pure LOC before todo 10 (about 330) and is 387 after it (local-socket builder, registry helper, separate workflow).
- The setup treats a non-JSON `show log` reply (the fake's text for an empty log) as an empty log; a real router that always answers text would make the job time out with `MarkerMissing` (fail closed). Confirm the live shape (todo 19).

## [2026-11-21] Todo 8 verifier hardening notes (for the todo 20 docs sweep / BACKLOG; not defects)
- N1 sealed SSH files are read with an unbounded `fs::read` (`entware_ssh.rs:~194`); a 64 KiB cap would bound a damaged or planted file (credential reads have the same property).
- N3 `forget` does not remove `.<id>.{sealed,key.sealed,ticket.sealed}.tmp` crash temps (sealed, 0600). N2 a directory at `<id>.ticket.sealed` makes `forget` fail once a redeem renamed it (needs the state-dir owner).
- N4 ticket expiry is absolute wall-clock time; a clock stepped back extends a ticket. N5 Web delete with a failing `forget` shows success and logs at error (like the credential wipe); the CLI exits Generic after the profile is gone.
- N6 an inner-record malformed JSON path (M18b) has no test; reachable only with the master key.
