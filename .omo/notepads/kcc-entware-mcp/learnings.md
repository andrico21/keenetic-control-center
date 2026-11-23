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

## [2026-11-21] Todo 10 (e10) learnings
- A fake-router clock that follows tokio time (`impl kcc_testkit::time::Clock` over `tokio::time::Instant::elapsed`) plus `start_paused` makes the component-commit reboot window, the 5 s polls and the 15 min timeout cost no real time, with no manual `MockClock::advance`: the whole entware_setup suite (23 tests) runs in < 1 s.
- `RouterRegistry::with_local_socket` is `cfg(unix)`; a domain fixture whose job uses the registry (poll_info, workflow.begin) must wire it too, not only the RciClient's OutboundPolicy (`Fixture::spawn_local` did not; `spawn_local_builder` does).
- To hold a router lease in a test while the router is down, use `workflow.reserve(..)` (no request); `begin` reads the router and fails.
- clippy: `field_scoped_visibility_modifiers` refuses `pub(super)` fields; put the struct in the parent module with private fields (children see them). A cfg(unix)/cfg(not(unix)) rebinding trips `shadow_*`: bind under a new name first.
- Mutant probes as a python apply/run/restore loop: ~10 s per mutant once warm; a mutant that trips a deny lint (dropping_copy_types, unreachable_patterns) reads as RED by compile error, so check the output for "test ... FAILED".

## [2026-11-21] Todo 26 (e26) learnings
- In-process kit-server tests cannot use `Services::open` (it loads the PROCESS master key from `KCC_MASTER_KEY_FILE` or the user's config dir, and `set_var` is unsafe/forbidden): build the handler, Web state, exporter and reload fan-out by hand (`server_listeners/tests/{fixture,services}.rs`).
- A deterministic test of "queued changes run one after the other" needs no sleep: make the API queue the command when CALLED (`fn restart(&self, c) -> impl Future`), plan the second candidate on a COPY of the state dir where the first is committed, and hold the first at a hook stage; an interleaving implementation refuses the second with `SettingsChanged`.
- Holding a port the old generation used: run the hook AFTER the stop (and after waiting for the old metrics listener to release `[metrics] bind`, which the kit stops on its own task): binding it in the `Stopped` hook is then race-free.
- The kit's `serve_with_listener` sends `ready_tx` BEFORE `run_server` loads the TLS files, so a generation with a missing cert still reports its address and then returns `Err`: useful to test "a listener that returns on its own stops the supervisor".
- `rmcp_server_kit_http_requests_total` only appears in `/metrics` after a request was recorded (an unlabeled CounterVec exports nothing).
- Mutation probes must keep the crate compiling under `unused = deny`: a mutant that leaves a fn/import unused is a compile error, not a red (`filter(|e| x && !x)` instead of replacing a call with `pending()`).
- Plain-text kit logs carry ANSI colour codes in a child's stderr; assert on `log_format = "json"` fields (`/fields/reason`) instead.

## [2026-11-21] Todo 9 (e9) learnings
- `AuditLog::append` refuses (AuditError::SecretParameter) any params key containing `password`, `passwd`, `api_key`, `token` or `secret`, at any depth: a boolean like `default_password_in_use` must be renamed in the audit params (todo 9 uses `default_credentials_in_use`). A flow that only logs an append failure (WARN) then passes silently; assert the audit entry's presence in a test.
- `entware_ssh::state::forget` deletes the whole record, port included: after revoke/disable the next probe dials 222 again. Tests that re-enrol after a revoke must `set_port` the fake's port first.
- A mutant that leaves a binding unused (`let _lease = ();` when the only other use of `services` was the lease) or drops a Copy value (`drop(HostKeyPin)`) is a COMPILE red under `unused = deny`/`dropping_copy_types`: re-run it with a replacement that keeps every binding used (`let _lease = services.workflow.state();`, `let _ticket_pin = ..`).
- The mutation loop for one integration target ran ~20 s per mutant with a warm private target (44 mutants in ~15 min).
- clippy here: `rest_pattern_accessible_field` refuses `Variant { .. }` on a struct variant with public fields (spell `{ actor: _ }`); `shadow_reuse` refuses `opt.is_some_and(|x| ..)` when `x` names the outer binding; `option_if_let_else` refuses a `match` on an `Option` building two events (use `map_or_else`).

## [2026-11-22] Todo 14 (e14) learnings
- The fake router has no `system eject` rule: an acknowledged eject over MCP answers `router_rejected`, but the request log still shows `system eject <media>` (assert the line, not `applied`). `media <id> initialize ext4` applies.
- The rmcp client in the Lab attaches a progress token on its own: a job-starting tool returns `{"job_id", "status": "completed"}` under a paused clock (the call follows the job). Do not pin `"running"`; wait with `JobRunner::ended` instead.
- A management-meta Entware op is pre-authorized by `open_as` already (SafetyNet::required(Write, Management) = [Write]), so the extra `preauthorize_management` call is an equivalent mutant: nothing can pin it.
- The `$schema` URL of every rmcp input schema contains `https://`: assert "no installer URL" with the host `bin.entware.net`.
- Mutation probes: ~40 s per mutant with a warm private target (27 probes in ~20 min); a mutant that builds a `CallToolResult` by hand needs `rmcp::model::ContentBlock` (not `Content`).

## [2026-11-22] Todo 13 (e13) learnings
- The fake router does not implement `system eject`: an accepted `kcc storage eject` reaches the router (the line is in the request log) and exits 6. Assert the sent line, not exit 0.
- `show media` of the fake lists `"initialize-supported": ["default","ext4","ntfs"]`: a substring check for `"ext4"` passes before any initialization (mutant "no wait" survived it); assert the medium's own `filesystem`.
- `kcc-cargo +nightly fmt` also waits for a build slot: run it detached, a foreground call can hit the tool timeout.
- Never `pkill -f` a pattern from your own command line (it killed the tool shell again: the rules file says so).
- A CLI child test of the Entware setup costs ~26 s of real time (5 installer polls of 5 s in the job); keep such runs to a few tests that run in parallel.

## [2026-11-22] Todo 12 (e12) learnings
- kcc-web kit: a confirmation cannot be skipped by dropping `.confirming(risk)` alone (the kit asks again at the planned risk in `carry`), and a management change keeps its fail-safe bracket while the `Operation`'s declared risk is Management even if the plan carries no operation. Mutants that only remove one of those layers are equivalent; mutate `.confirmed_by_page(risk)` (the real skip) or remove both layers.
- A web test that counts router requests before a confirmation must count COMMANDS (`RequestRecord::commands`), not requests: `Operation::open` loads the router's catalog facts (reads) on first use. Forbidden roles are refused before the facts load, so "zero requests" holds there.
- Visual QA without a kcc binary: a scratch integration test that builds `support::build::Setup` and proxies `axum::serve` on 127.0.0.1:8080 (the harness's ORIGIN) to `Fixture::send`; Playwright 1.49.1 via `bunx --bun playwright@1.49.1 install chromium` + `bun add playwright@1.49.1` works headless on this machine. The dialog's close button is a `type=submit` in `form[method=dialog]`: click `#dialog .dialog__actions button`, not `#dialog button[type=submit]`.
- `.choice__option` (flex-wrap) drops a long radio label under the radio on a phone; the `.check` + `.check__label` + `.field__help` pattern (router form) keeps the name next to the control and wraps the details on a full-width help line.
- clippy here: `struct_excessive_bools` also fires on askama view structs (expect with a reason); `field_scoped_visibility_modifiers` again forced the shared `Described` struct to stay in the parent module (children read private fields).
- A mutant written as `crate_name::path::Item` inside a module where that crate is imported trips `absolute_paths` (compile error, not a red): import the item instead.

## [2026-11-22] Todo 11 (e11) learnings
- Reusing `tests/entware_enrol/harness.rs` via `#[path]` (+ `#[expect(dead_code)]`) gave an enrolled rig in a few lines; table tests over every op (`READS`/`MUTATIONS` arrays) made the per-op guard rules cheap to pin (counters() equality proves zero connections/commands).
- Fake switches that made read-back rules testable: `Service::exits(code)` (an rc.func exit status that lies about the effect) and `Config::frozen(name)` (opkg exits 0 and changes nothing). Without them a skipped read-back is invisible.
- Mutation loop (python apply/run/restore + touch): ~10 s per mutant once warm, 52 mutants. Mutants that leave a binding of type `()` (`let _lease = run.read()?;`) or an unused import are compile errors under `unused`/`let_unit_value`: rewrite them as statements/guards (`run.read()?;`, `(_, 255) if name.is_empty() =>`).
- Logging pipelines: `cmd 2>&1 | tee -a EV | grep .. | head -40` kills cargo with SIGPIPE once head exits (EXIT=101 with no failing test). Never cap a tee'd cargo pipe with head.
- `pgrep -f`/`pkill -f` with a pattern in your own command line killed the tool shell (again).
- Slot wrapper is not FIFO: a queued command waited ~25 min behind other workers; batch runs into one detached script.

## [2026-11-22] Todo 27 (e27) learnings
- askama macros: bool macro arguments are awkward (references vs values); pass structs and read their fields (`section.save`, `upload.stored`), and in `{% match %}` arms bound values are references (`{% if *on %}`). Indexing an array field in a template (`sections[0]`) was replaced by a struct with named fields to keep generated code free of indexing.
- `clippy::field_scoped_visibility_modifiers` again: view-model structs read by templates live in the module root (`admin_mcp.rs`) with private fields; the child modules (rows, view, sections, page) see them.
- A section form that posts only the keys whose value differs from the effective one keeps "Save" from pinning every kcc.toml value as a Web override; every editable control posts a hidden `field=<key>` so an unticked checkbox still means "off".
- htmx: an outcome region at the top of a long page is out of view after a save at the bottom; `hx-swap="innerHTML show:top"` on the forms scrolls it in.
- The status fragment's restart outcome is recorded by the Web task AFTER its audit entry is queued, so a test that sees the outcome can read the audit at once (no polling of the audit).
- Mutation probes for a Web page are about 4 min each with two shared build slots; batch them in one detached python apply/run/restore loop (30 probes took about 2 h of wall time).
- Playwright 1.49.1 here needs `executablePath` = `~/.cache/ms-playwright/chromium-1148/chrome-linux/chrome` (the headless-shell download is absent); `bypassCSP: true` for a text-spacing probe (the page's CSP refuses injected styles). Never `pkill -f` a pattern from the command line (it killed the tool shell once more).

## [2026-11-22] eci (D-CI-LATEST) learnings
- taiki-e/install-action resolves `tool: x@ver` from manifests/<tool>.json of the PINNED action SHA. A version not in that manifest falls back to cargo-binstall (default `fallback: cargo-binstall`), losing the manifest's sha256 check. A gate-tool bump therefore needs an install-action pin whose manifest lists it; under the 3-day action cooldown that can hold back a brand-new tool (cargo-deny 0.22.0, cargo-vet 0.10.4 on 2026-11-22).
- GitHub Actions retired the macos-14 runner on 2026-11-02 (runner-images #15226); release.yml now uses macos-26.
- Container digest refresh without podman: registry HTTP API (Docker Hub token from auth.docker.io; gcr.io anonymous), compare per-platform manifest digests to see whether the image content changed or only the index.

## [2026-11-22] Todo 30 (e30) learnings
- A table-driven negative case that reuses a value derived from ANOTHER fixture object can pass for the wrong reason: the `plain` verifier case first used the challenge of an earlier code, so a mutant accepting `verifier == challenge` survived. Derive the bad input from the very object under test (here: the fresh code's own challenge).
- The base Cargo.lock (be146782) listed `sha2` without a version in kcc-domain's dependencies although two sha2 versions are locked (0.10 via jsonwebtoken, 0.11); the first cargo command rewrites it to `"sha2 0.11.1"`. Expect that one-line Cargo.lock diff in any worktree cut from that base.
- Mutation loop over one integration target with a warm private target: about 8 s per mutant (73 mutants in ~12 min). Neutering with `&& now == u64::MAX` keeps every binding used under `unused = deny`; a mutant that drops the only use of an import is a compile red, rewrite it.
- rustfmt reflows test tables of tuples into one field per line: a 25-row table pushed a test fn over clippy's 100-line limit. Keep fixed rows in a `const` array and add the runtime-built rows in a helper.

## [2026-11-22] Todo 17 (e17) learnings
- kcc-mcp may not depend on kcc-ssh (F1): build kcc-ssh values through kcc-domain functions and let inference carry the type (`Mutation::Install(names::package(text)?)`); a value that must be stored before use is kept as its checked text and parsed again at the call.
- `common::open_as` authorizes the router twice (authorize_host, then `SafetyNet::required(Destructive, Destructive)` = [Destructive] again): removing only one scope check is an equivalent mutant; mutate both.
- A test that holds a mutation (`Fault::HoldMutations`) and reads behind it must release the hold whatever the read answered, or a regression turns into a hang instead of a red (join! waits for the held install).
- The MCP Lab clients attach a progress token, so a job-starting call waits for the job: run it inside `tokio::join!` with the code that releases a held fake command.

## [2026-11-22] Todo 16 (e16) learnings
- A CLI gate that must refuse BEFORE any router contact cannot use `domains::Session::open` (it connects to the router during `Ctx::target`); authorize with `Ctx::authorize_audited`, confirm with `secret::confirm` + `Ctx::confirmed`, then call `Ctx::target_named` only when the command needs a `RouterCtx`.
- A test process can make the CLI child see `RouterBusy` by holding `StateStore::open(state_dir)?.try_lease(router)` (a file lock): no setup job is needed.
- Per-command audit pins: `kcc_app::audit::read_entries(state_dir)` counting `cli.refused` entries before/after each refused run kills "refusal not audited" mutants.
- clippy here flags `entries + 1` (usize) in a test assert as arithmetic_side_effects; `checked_add(1)` compared with `Some(..)` passes.
- The mutation loop for the CLI suite ran ~1 min per mutant with free slots but waited up to 20 min for a slot (the wrapper is not FIFO). Mutants that add two helpers at once fail to compile (dead_code on the unused one): add only the helper each mutant uses.

## [2026-11-22] Todo 15 (e15) learnings
- Golden "before" without git stash/checkout: copy the touched sources aside, write `git show HEAD:<path>` over them, build and run a scratch dump test (same private target: only kcc-web rebuilds), restore the copies and `touch` them. Normalize the CSRF meta token before `diff`.
- `SshStore::set_port`/`set_enabled` create a default record (Pending, no pin): a page that shows "Pending" for any record calls a never-enrolled router Pending; treat a record without a fingerprint as not enrolled.
- A test that reuses a nonce after a successful enrolment must also tick the Active-replacement box, or the page's own Active guard answers first and the domain's ticket refusal is never reached.
- The kit's destructive dialog text ("can erase data or restart") is wrong for SSH reads and local changes: build the kit `Dialog` with `Guard::Destructive.check` and an own text per action kind; pin the kind via `data-message-key`.
- `.check` uses `flex-wrap: wrap`: a long checkbox label drops under its box at 390 px; keep labels short and put the explanation in a notice or `.field__help`.
- `axum::serve` in a scratch Playwright server holds the cargo build slot while the test runs: stop it as soon as the screenshots are taken.
- Slot contention: a 2-minute compile often waited 5-10 minutes for a slot; xtask subcommands that need no cargo (i18n-gen, allow-gate, i18n-check) run from `$CARGO_TARGET_DIR/debug/xtask` without a slot.

## [2026-11-22] Todo 28 (e28) learnings
- rustls client: a `ResolvesClientCert` whose `has_certs()` is true and whose `resolve()` returns `None` records the server's CertificateRequest without presenting a certificate; a required rustls server then fails the exchange with `rustls::Error::AlertReceived(CertificateRequired)` (TLS 1.3, on the first read), reachable through `io::Error::get_ref()` + `downcast_ref::<rustls::Error>()`.
- rmcp 3.10 puts the HTTP `http::request::Parts` into `RequestContext.extensions`; the kit's `AuthIdentity` (with `method`) is in `parts.extensions`. The kit only exposes the identity NAME as a task-local, so the sign-in method needs its own task-local scoped in the `ServerHandler` methods.
- The kit's `RbacPolicy` denies a host outside a role's router scope at the HTTP middleware, before kcc's handler: a kcc-audited `forbidden` cannot be produced that way. A destructive tool with `allow_destructive = false` (`kcc_storage_write` eject) gives a kcc-audited refusal without a router.
- A mutant that leaves a parameter unused (`assignable` -> `roles`) is a compile error under `unused = deny`; use `[assignable, roles].concat()`. A "refused" table row must isolate one rule: a path-field case carrying random certificate bytes was refused for the bytes, so the ignore-unknown-fields mutant survived until the row sent a valid CA.
