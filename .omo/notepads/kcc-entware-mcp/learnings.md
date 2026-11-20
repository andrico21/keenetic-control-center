# kcc-entware-mcp: learnings (orchestrator)

READ FIRST: `.omo/notepads/kcc-notify-schedule/learnings.md` and `decisions.md` (macOS/Windows portability, paused-clock + Unix-socket seam, Windows launcher and de-elevated tests,
rustdoc private links, drain request bodies in fakes, job verdict vs `JobRunner::ended`, union-merge of shared docs, keys.rs regenerated not merged). They all still apply.
New for this plan:
- Never push for this plan until the owner says so (the earlier grant named the CI fix and kcc-notify-schedule). Commit locally per todo.
- A scheduled/unattended path that can leave the router's fail-safe timer armed must hold the router lease until the timer ran out (see decisions.md of kcc-notify-schedule, todo 21);
  the same invariant applies to every new write path of this plan (Entware drive initialize/setup job, SSH mutations, listener restarts are process-local but must never leave the main server down).
- `kcc-cargo xtask <sub>` that itself spawns cargo can hang (xtask inherits the wrapper's slot fds): run the built `debug/xtask` binary directly in that case; local-only problem.
- cargo-mutants needs `RUSTFLAGS=--cap-lints=warn CARGO_BUILD_WARNINGS=allow` (workspace has `unused = deny`).
- UPDATE (owner, this session): "yes, you can push to master" - pushes to origin master are authorized for kcc-entware-mcp (fast-forward only, never forced, after `git fetch -q origin` and
  `git merge-base --is-ancestor origin/master HEAD`; command `git -c credential.helper='!gh auth git-credential' push origin master`; batch pushes, a push cancels the in-progress CI of the same ref).

## [2026-11-21] Todo 3 progress (e3)
- kcc-domain `tests/profile_coverage.rs` fails any new suite that never iterates `support::PROFILES` (`for firmware in PROFILES`): give every new kcc-domain suite at least one PROFILES loop (or a SINGLE_PROFILE row with a reason).
- `cli_engine/rules.rs` sits at exactly 250 pure LOC: new fake grammar goes into its own module chained from `classify_top_level` (as `opkg_rules::shape`). `projection.rs` is at 246.
- clippy here: `shadow_reuse` fires on `x.filter(|x| ..)` after `let x = ..`; `assert_is_empty` wants `assert_eq!(v, Vec::<T>::new())`.
- Red runs: (1) compile failure, module absent; (2) runtime red with the module registered but the fake unchanged (opkg parse refused -> RciError::Rci, opkg component Missing). Green first time after the fake changes.

## [2026-11-20] Todo 6 (e6) learnings
- russh 0.65 server API: `channel_open_session(channel, reply: ChannelOpenHandle, session)` must call `reply.accept().await`; `exec_request` must call `session.channel_success(channel)` itself; deliver output from a spawned task with `session.handle()` (`data`, `extended_data(ch, 1, ..)`, `exit_status_request`, `eof`, `close`). Returning `Err(russh::Error::Disconnect)` from a handler drops the TCP connection. Client `check_server_key(&PublicKeyOrCertificate)`; trait param must be named `server_public_key` (clippy renamed_function_params).
- Clippy in this repo for russh handler impls: `#[expect(clippy::unused_async_trait_impl, reason = ...)]` per fn; `significant_drop_tightening` wants the state lock in an inner block; `Option<String>` results of map insert/remove need `drop(..)` (`let _: Option<_>` trips let_underscore_drop); `impl Into<String>` params are refused (impl_trait_in_params): use a generic with a where clause; integer `/` is refused.
- Ed25519 host keys without the rand_core API: `PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&seed))` with `rand::rng().random::<[u8; 32]>()` in `Zeroizing`.
- ring 0.17.14's C build works with the zig wrappers for x86_64-pc-windows-gnu and aarch64-apple-darwin (russh + pageant + windows 0.62 included).

## [2026-11-21] Todo 24 progress (e24)
- A web form struct with `deny_unknown_fields` answers 422 to ANY new field on the base. A "refused" test that only checks 422 is green before the change, so assert the field-error id (`id="key-expires-error"`) instead.
- Child-serve expiry test: `serve_api_key_expiry.rs` reuses `serve_state_watch/support.rs` (portable) under `#[expect(dead_code)]` and polls `/mcp` with a `tokio::time::interval` bounded by `timeout_at` (real time; the time itself is under test). It ran 3/3 green in ~3 s.
- (from todo 6 worker, for todos 7 and 18) russh-cryptovec 0.62 calls `mlock`/`munlock` on key buffers and ignores failures: the seccomp profile regenerated in todo 18 must show them in the trace (do not hand-edit); russh logs through the `log` crate, so todo 7's no-secret-in-logs byte test must capture `log` records too (tracing-subscriber `tracing-log` / LogTracer).
- (todo 24 worker finding, outside its scope) `kcc-web/src/admin_shared.rs` `Timestamp::at` panics on a hand-edited timestamp >= year 10000 (humantime Display `fmt::Error`): add to docs/BACKLOG.md at the todo 20 sweep or fix when todo 27 touches the same file; also `admin_keys.rs` is over the 250-LOC guideline (split is a follow-up).
