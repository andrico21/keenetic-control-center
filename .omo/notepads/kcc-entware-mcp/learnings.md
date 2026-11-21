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
- HARNESS (verifier of todo 23): a cargo target dir shared by several worktrees can serve another worktree's workspace crate as fresh (mtime), giving bogus errors like E0425 for keys that exist in the tree under test. NEVER share a target dir across worktrees: every worker/verifier uses its own private target; the orchestrator's warm `kcc-target-main` is only for the main checkout.
- Verifier pattern that worked: report file + JSON verdict + `VERDICT:` last line; the verifier found real defects in 3 of 4 HEAVY wave-1 todos (a privilege escalation through `McpBase::reset`, a fake-SSH matcher that would have masked todo-7 rendering bugs, four unpinned rules), so keep it for every HEAVY todo.
- Resume of a finished worker session fails ("Task not found"): fix workers are fresh tasks pointing at the existing uncommitted worktree plus the verifier report.
- Landing gate lesson (todo 24 broke CI on 633a7d96): the per-landing set must include EVERY suite that renders or drives a surface the todo touched, not only the todo's own tests: for a Web page change run the full `kcc-web` tests AND `kcc --test serve_refresh --test serve` (they scrape the page HTML); for a CLI change run `kcc --test cli`; for an audit/permission change run `kcc-app` whole. Workers' briefs must list those suites too.
- The amd64 seccomp trace is slightly nondeterministic (sched_yield appeared in a run with no relevant change): on a `--check-missing` failure for an already-mapped syscall, regenerate from the CI artifacts (two arches, two traces each), never hand-edit.

## [2026-11-21] Todo 7 (e7) learnings
- clippy `significant_drop_tightening` false-positives on a binding that a `self`-consuming method moves (`let slot = pool.acquire(..).await?; slot.connect(..)`): chain the calls instead of binding.
- clippy `tests_outside_test_module` does not recognise `#[cfg(all(test, unix))]`: an `#[expect]` on the mod declaration is needed.
- `[lints] unused = deny` makes `CARGO_BUILD_WARNINGS=allow` useless for a neutered red run: neuter with runtime-only conditions (`if text.len() < usize::MAX { return true; }`, `bound.max(..)`) so no unused/unreachable lint fires.
- russh's `ssh id = ...` debug record is a reliable proof that the `log` bridge (tracing-subscriber `tracing-log`, `set_default`) reaches the capture in a current-thread tokio test.
- Git hygiene while a patch is staged in the main tree during a landing gate: commit orchestrator state with `git commit -o <paths>` (only those paths), never a plain `git commit` (it swept the staged todo-3 patch into a state commit once; fixed with `reset --soft` before anything was pushed).

## [2026-11-21] Todo 4 (e4) learnings
- Every catalog (4.3, 5.0, 5.1) has all five `opkg` paths (`opkg initrc`/`opkg timezone` included, despite "since 5.1" in the 5.1 catalog); only `media initialize` is 5.1-only.
- To capture a runtime red for surface wiring without lint trouble, neuter with `x.as_deref().filter(|_| false)` (no unused binding); `RUSTFLAGS=--cap-lints=warn` would rebuild every dependency in the private target (avoid).
- Fake-router setup without a request: `Handle::configure(line)`; actions (not config lines) belong in `server/parse_command.rs::intercept`, since `Shared::parse_command` is at the 100-line clippy limit.
- clippy in tests: `assert!(x.is_ok())` is refused (`assertions_on_result_states`): use `drop(x?)`; the first doc paragraph of a test is limited (`too_long_first_doc_paragraph`).

## [2026-11-21] Todo 7 fix (e7f) learnings
- A tracing capture test that shares its test binary with other tests misses tracing-native DEBUG/TRACE events (thread-local `set_default` plus callsite-interest caching): put the capture test in its own integration target and install the subscriber process-wide (`SubscriberInitExt::try_init`, which also installs the `log` bridge) before any work, then assert a positive control of the crate's own DEBUG line (`DEBUG kcc_ssh::transport`). With that, an output leak at TRACE went red 5/5 in the plain parallel run.
- A second test target that reuses `tests/ssh/support.rs` via `#[path]` needs `#[expect(dead_code, reason)]` on the `mod support;`; removing a module that used `alloc` from a target makes its `extern crate alloc;` an error (`unused extern crate` is denied).
- clippy `missing_panics_doc` fires on an inline `#[cfg(test)] mod tests` fn with `assert_eq!` here: use the crate's `#[expect(clippy::missing_panics_doc, reason)]` on the mod.

## [2026-11-21] Todo 25 (e25) learnings
- `#[path]` on a module declared INSIDE an inline `mod tests { }` of a test crate root resolves under `tests/tests/...` (the inline module is a directory component); `../` does not help because `tests/tests` does not exist. Keep such tests inline or declare them at the crate root.
- The kit's `serve_with_listener(.., ready_tx, ..)` sends the address after the "listening" log and BEFORE it calls the reload callback: gate one-time background work (the state watcher) on it to keep "runs once serving" semantics (serve.rs F-23 test).
- Moving a helper's only caller under `cfg(unix)` makes the helper dead on Windows: the Windows cross-check catches it, Linux clippy does not.
- Never `pgrep -f`/`pkill -s` a pattern that also appears in your own bash command line: it killed the tool shell (no harm beyond an interrupted run).

## [2026-11-21] es (Windows CI stack overflow after todo 23)
- Windows gives the main thread 1 MiB; Linux/macOS 8 MiB. Emulate on Linux with `ulimit -s 1024` in the shell that launches `kcc` (`sh -c 'ulimit -s 1024 && exec "$0" "$@"' kcc ...`); overflow shows as SIGABRT (exit 134, "killed by a signal" in the CLI support).
- Root futures are small (entry::run 16.5 KB; tokio already boxes large block_on futures). What overflows is the depth of DEBUG poll frames: an async fn with a big `match` of `.await` arms gets one stack slot per arm's future (no stack-slot reuse at opt-level 0). entry::local was 311 KB, entry::run 100 KB, domains::run 344 KB. Measure with `objdump -d -C kcc | awk` on the prologue `sub $N,%rsp|%r11`.
- Fix pattern: a dispatcher is a SYNC fn returning `entry::Boxed<'_>` (`Pin<Box<dyn Future<Output = Outcome> + Send>>`), each arm `Box::pin(async move { .. })` / `Box::pin(f(ctx, sub))`; the sync frame is popped before polling. Preset apply needed >1024 KiB before, 640-768 KiB after.
- Regression: `permission_gates::apply::preset_apply_runs_within_a_one_mebibyte_main_stack` (Linux only). Domain writes still need 896-1024 KiB is NOT true any more after domains::run was boxed; clap's `augment_subcommands` frames (VpnCommand 430 KB) are the next-largest main-thread cost (argument parsing, before block_on).
- (correction to the last line above) measured after the fix: the whole CLI suite passes with every kcc child at 896 KiB; at 768 KiB only completions and pipes fail (clap argument parsing on the main thread, before block_on).
- [2026-11-21 todo 4 fix] Testkit gotcha: `fail_read_matching` matches the GET path for `show/media` but the POST body for `show rc`, so the `opkg disk` read is faulted with `"rc":{"opkg"`. The Web eject reads `show media` in `known` before `configured_media`, so only the `opkg` fault distinguishes a fail-open Web guard.

## [2026-11-21] Todo 8 (e8) learnings
- clippy here refuses `drop(barrier.wait())` (drop_non_drop) and `let _: bool = ..is_leader()` (let_underscore_must_use): bind `let _wait = barrier.wait();` as backups.rs does.
- A red run whose new pub(crate) helpers are not yet used fails at the LIB (dead_code), not at the test: for a clean compile-red keep the helper edits out until the module is registered.
- `module_name_repetitions` fires on plan-mandated names (`ticket::TicketStore`, `ticket::TicketScope`, `state::EnrolmentState`): `#[expect]` with a reason on the item.
- Mutation probes as a python apply/run/restore loop over one integration target run in ~1 min per mutant when slots are free (11 mutants, all red).
