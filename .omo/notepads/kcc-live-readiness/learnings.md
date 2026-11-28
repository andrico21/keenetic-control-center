# kcc-live-readiness: learnings (append-only; CI lessons, gotchas, conventions discovered while executing)

Public repository: never write the owner's router id, address, host, network, serial, MAC, name, SSID or any captured value here (the leak scan `python3 /home/andrico/kcc-live-scan.py staged` runs before every chore(omo) commit).

## [2026-11-26] Executor notes carried over from the review
- Leak scan hit blocks the commit; no override. If a learned identifier is an ordinary word that new code legitimately contains, stop and ask the owner; never weaken the scan.
- Todo 28: one test for Stop in session-continuation mode (dedicated session signed out, no DELETE sent). The new Web continuation-ping test must not use `#[tokio::test(start_paused = true)]` with the loopback fake.
- Todo 9: its evidence log should also show the schedule-eligibility (`kcc`) and telemetry (`kcc-app`) tests.

## [2026-11-26] Todo 7 lint gotchas
- Clippy here denies `non_ascii_literal` in tests too: Cyrillic test strings go in a `const` written with `\u{...}` escapes. A doc comment's first paragraph longer than ~2 lines trips `too_long_first_doc_paragraph`; split it with a blank `///` line. `return_and_then` fires on `.first().and_then(..)` as a closure's tail.
- A manual 1 MiB stack check of a CLI path: run the built `kcc-target-l<N>/debug/kcc` through `sh -c 'ulimit -s 1024 && exec "$0" "$@"'` with `env -i`, `KCC_MASTER_KEY_FILE` (32-byte 0600 file), and `[outbound] allow_loopback = true` in kcc.toml.

## [2026-11-26] Todo 1 gotchas
- hyper 1.12 server panics in debug builds (`payload claims content-length of N, custom content-length header claims M`) when a handler sets a Content-Length that differs from a body with an exact size; and a stream body that ends early makes hyper drop the connection WITHOUT flushing the buffered head, so the client sees "closed before answering", not a cut body. The fake's `cut_body` therefore cuts at the socket (`connection_fault::Stream` writes the head plus 8 body bytes of a correct answer, then fails the write).
- Per-connection fake faults: `axum::serve(listener, app.into_make_service_with_connect_info::<connection_fault::Wire>())`, where `Wire: Connected<IncomingStream<'_, Listener<L>>>` returns the stream's own switches (`stream.io()`); handlers read `ConnectInfo<Wire>`. The in-process `FakeRouter::router()` has no `ConnectInfo`, so wire faults only act over a socket.
- rustls failures reach reqwest callers inside `io::Error` (`io::Error::get_ref()` holds the `rustls::Error`; its `source()` skips it). TLS to a plain-HTTP port gives `rustls::Error::InvalidMessage` -> `Tls(Handshake)`.
- A connection the server closes after reading the request surfaces as `hyper::Error::is_incomplete_message()` -> `ClosedBeforeAnswer`; a cut body surfaces as an `UnexpectedEof` io error inside a body error, which `classify` would call `ConnectReset`, so body reads map chunk errors to `BodyInterrupted` themselves (engine/body.rs, testkit capture.rs).
- The path rule `^[A-Za-z][A-Za-z0-9_-]{0,63}$` shows name-like map keys (a key like `SECRET-VALUE-7` stays visible); router name-keyed objects must go through the planned `keyed_rows` helper, never be decoded as maps.
- clippy here denies `module_name_repetitions` (hence `diag::answer`/`diag::collapse`), `unnecessary_box_returns` (expect with reason on `DecodeDetail::new` and `not_json`), `wildcard_enum_match_arm` on foreign non_exhaustive enums (use `matches!` chains), and struct patterns with `..` (name the fields `: _`).
- Todo 6 landed in worktree live-6: gates green (fmt, clippy -p kcc-web -p kcc, QA, dashboard, docs, doc, allow-gate, no_secrets, windows+macos checks).

## [2026-11-26] Todo 4 learnings
- `RciClient::show` falls back to `POST /rci/show/<path>` after a GET 404/405; the capture now uses `RciClient::get` for every Show item so it never sends a show POST (the fake answers 404 for several show paths without fixtures, which used to trigger the POST).
- Clippy in this repo rejects `|| async move {..}` closures (`closure_returning_async_block`): take `F: AsyncFnMut() -> T` and pass `async || ..`.
- Integration tests that run a workspace binary need `#[expect(clippy::disallowed_methods, reason = ..)]` on the spawning fn (clippy.toml forbids `Command::new`/`output`); `env!("CARGO_BIN_EXE_<bin>")` works even with `test = false` on the bin.

## [2026-11-26] Orchestration lessons (wave 1)
- Finished worker sessions are deleted about 10 minutes after they end (background_task cleanup); the completion notifications arrive batched when ALL tasks finish. A worker's final message can be lost, so workers also write their DoneClaim to `.omo/evidence/claim-task-<N>-kcc-live-readiness.md` (rules file).
- Landing order per todo: independent verifier confirms, orchestrator reviews the diff, commit, rebase onto master, gate G0, fast-forward, push, CI watch.
- The `programming` skill stopped resolving mid-run (plugin cache path changed); fix workers were dispatched without it, with the rules file carrying the same rules.
- Round 1 verifiers found real holes in every W1 todo (privacy self-check leaks in todo 4; weak tests elsewhere); keep verifying each todo independently and re-verify narrowly after fixes.

## [2026-11-26] Todo 1 fix round
- Now pinned by tests in crates/kcc-rci/tests/diagnostics.rs: `expected` is the text after the LAST `expected ` (router text containing it stays out; `router_text_with_the_word_expected_stays_out`) and is cut at 80 chars (`a_long_expected_list_is_cut`). Both proven RED by scratch mutations (split_once, EXPECTED_CHARS=100000), answer.rs restored byte-identical.
- Doc lines fixed: deploy/podman/README.md:275 (new Display text), docs/BACKLOG.md:284 ("RCI request failed" -> "an RCI error"), crates/kcc/tests/cli/failures.rs:1 comment.
- Todo 7 fix: `stored_label_must_already_be_canonical` (router_labels.rs) hand-writes routers.json with an untrimmed, blank and empty label and expects InvalidProfile starting with "label"; it kills the mutant `rules::check` using `label::parse(name).is_err()`.

## [2026-11-26] External cross-check: the public `keenetic-rci` crate (hexqnt/keenetic-rci 0.1.1, MIT OR Apache-2.0)
Reference only: no code is copied and no dependency is added. Local copy of its source for grep: `/home/andrico/ref-keenetic-rci/keenetic-rci-0.1.1/` (fixtures in `tests/fixtures/`, continuation in `src/client.rs` `NetworkTestSession`). It targets KeeneticOS 5.0+ and was tested on KN-2311, KN-3810 and KN-3811, so it is evidence from other models than ours.
- Confirms our captured shapes on other models: `show ip hotspot` `{"host":[...]}` (`interface` object `{id,name,description}`, `rxbytes`/`txbytes`, `first-seen`/`last-seen`, `dhcp.expires`, `ap`, `txrate`), `show ip dhcp bindings` `{"lease":[...]}`, `show associations` `{"station":[...]}`, `show ipv6 route` `{"route6":[...]}`, `show ip arp` and `show ip route` bare arrays, `show usb` `{"device":{<id>:{...}}}` (`no-led` is an empty-string presence marker), `show media` keyed by media name with a `partition` map and string sizes, `show mws member` an array.
- `show mws member` answers `{}` (an empty object) when there are no extenders: todo 15 must accept `{}` for the member list too, not only for `show mws associations`.
- Continuation protocol confirmed: POST starts, `GET` of the same endpoint polls, `continued: true` while more follows, empty continued chunks are skipped, the first POST answer is the first chunk. Endpoints `tools/ping`, `tools/ping6`, `tools/traceroute`, `tools/iperf3`; request keys `host`, `count`, `packetsize`, `sequence-id`, `source`, `tos`, `ttl`.
- Difference to the plan (plan wins, scope unchanged): the crate cancels a running command with `DELETE /rci/<endpoint>` (returns the unread output) while todo 28's `stop()` signs the dedicated session out and sends no DELETE. A DELETE of a command kcc started on kcc-diag would need the owner's consent (the hardware protocol does not allow it on the owner's router); record as a follow-up idea, do not implement now.

## [2026-11-26] Todo 1 round 3: doc fix verification
- The D3 defect from verifier round 2 was real: `deploy/podman/README.md:275` claimed seccomp-refused getsockopt returns "connection refused", but the code path is:
  - Seccomp EPERM (defaultErrnoRet 1) → tokio's take_error() fails with `io::ErrorKind::PermissionDenied`
  - `diag.rs::io_cause()` has no PermissionDenied arm, returns None
  - Falls through to `flagged()`, which returns `ConnectOther` by default
  - Display of `ConnectOther` is "could not connect" (line 119)
- Fix: change line 275 from the master version ("RCI transport failed") to the correct text: `"connection to the router failed: could not connect"`
- Verification: `kcc --test docs` passed 9/9 (exit 0); only README.md changed in this round; no other doc claims the wrong text for the seccomp case

## [2026-11-26] Todo 2 learnings
- A red run started while edits continue picks up the edited sources once the build slot frees (the slot wait can be minutes): for a clean red, put the base versions back (`git show HEAD:<file> > <file>`, no git state change), run, then restore.
- Clippy here flags `tracing::field::debug` / `tracing::subscriber::set_default` written as paths (`absolute_paths`): import them. `matches!(x, Err(E::V { .. }))` trips `rest_pattern_accessible_field` in tests too.
- tracing fields that must appear only sometimes: pass an `Option` (`query = flag.then_some(true)`, `content_length = response.content_length()`); `None` records nothing in the fmt output.

## [2026-11-26] Todo 11 learnings
- askama 0.16 passes a `String` field to a template method taking `&str` fine: `{{ router_name(router) }}` compiles against `fn router_name<'n>(&'n self, id: &'n str) -> &'n str` on the `Localize` trait.
- clippy here denies `shadow_unrelated` (a `let named` beside an extractor `Query(named)`) and `cognitive_complexity` > 25 (the router create handler needed `new_id` and `undo_create` helpers once the id derivation was added).
- `kcc` server_notify tests live in the kcc LIB (`cargo test -p kcc --lib server_notify`), not `--bin kcc` (that runs 0 tests).

## [2026-11-26] Todo 3 gotchas
- `crates/kcc-domain/tests/profile_coverage.rs` fails any kcc-domain test suite that never iterates `support::PROFILES`: every new kcc-domain suite loops `for firmware in PROFILES` (or is listed in `SINGLE_PROFILE` with a reason).
- The decode deduper is process-wide: a test that hits the same (router id, resource, problem kind) twice sees one WARN; give each test its own log id (`with_log_id`).
- `kcc serve_scheduled::a_started_run_is_reported_interrupted_once` timed out once (90 s) in a full `--workspace` run under host load and passed alone in 0.41 s: load flake.
- Removing a now-unused `DomainError` import breaks rustdoc intra-doc links in that file; write them `[`crate::DomainError::X`]` (precedent: routing/read.rs).

## [2026-11-27] Todo 9 learnings
- Thread-local tracing capture (`set_default`) is flaky in a multi-test binary: with at most one live dispatcher tracing decides a callsite's interest from the first thread that reaches it (JustOne rebuilder), so another test thread without a subscriber can disable the callsite for everyone. `kcc_testkit::log_capture::start()` keeps two permanent dispatchers alive; use it instead of a private `Captured`.
- `tracing` string fields log quoted when recorded as plain `&str` (`router="home"`); use `%` for unquoted values.
- `kcc-cargo` can wait many minutes for a slot, even for fmt; run it detached, and never `rm` a log that a detached job redirects into.

## [2026-11-27] Todo 8 learnings
- `cargo xtask i18n-check` fails on a message no code or template names: removing the last use of a key means deleting it from all six locales and re-running `i18n-gen`.
- `ReadProblem: From<MessageKey>` lets a `Result<_, ReadProblem>` function keep `?` on old `MessageKey` errors (store failures, parse errors) unchanged.
- Askama macros in `partials/kit_macros.html` can call the page's `Localize` methods (`t_read`) and other macros of the same file (`details(..)`); an inline `source =` template can `{%- import "partials/kit_macros.html" as kit -%}` too.
- A show resource the fake must answer 404 for by GET and POST: `FaultInjection::show_absent(path)` (the POST fallback otherwise hides a GET 404).

## [2026-11-27] Process lessons (waves 1-3)
- Verifier mutation chase: round counts reached 5-6 for the capture tool and 4 for the router-name todo, each round finding a new untested-but-correct call site. The standard was relaxed (see decisions.md / the verifier rules file). Keep verifier briefs to the plan's own bar: one mutation per NEW rule, plus anything that leaks or is wrong.
- Rebase conflicts so far were append-only locale files and generated keys.rs (keep both blocks, run i18n-gen) and one test-infrastructure overlap (two different overrides for the fake's `show rc` answer: both kept).
- Model quota errors ("monthly quota exceeded") and gateway errors appear in bursts; a retry a bit later worked.

## [2026-11-27] First real capture: facts for the next todos (structure only, no values)
- Capture: KN-1811 on firmware 5.1.10, 94 manifest items (85 written, 9 skipped), 38 interface-stat items, 12 of 30 harness reads already decode, 18 fail as expected.
- Real shapes confirmed object-envelope again: hotspot, DHCP bindings, associations, IPv6 routes, policies, UPnP, media, usb, schedules, `show rc user`/`service`, `show mws associations`; `show ndns` booked is a string; `show components list` is an object; the log and ping use the continuation protocol (no /process/id).
- Surprise: `show ip nat` ALREADY decodes (a bare array whose rows fit NatSession) in the capture: todo 17 should still implement local paging and the real field names, but its red test needs a synthetic fixture with more than 200 rows, not the capture.
- The router refuses 8 reads with `Core::Configurator` router errors when asked as single `show rc` roots or as `show interface bands/rrd`: show-interface-bands, show-interface-rrd, show-rc-opkg, show-rc-dns, show-rc-vpn-server, show-rc-oc-server, show-rc-wireguard-server, show-rc-crypto; `show components pending` is not-found. The harness replay DROPS refused roots, so `live_vpn_servers` passes vacuously: todo 22 must replay a refused root as a router error (structured skip record) before it can claim the VPN read is proven.
- The anonymizer lessons: free-text comments in a running config span several words; firmware interface references (`interface: {id, name, ...}`) must not be learned as host names.
- A privacy tool that rewrites text must also prove it preserved the schema: a learned generic word that equals a firmware key corrupted keys inside the first real capture (found only by looking at key paths with a value-free shape view, `kcc-shape.py`). Todo 12 round 4 adds the vocabulary rule and a fidelity self-check. Lesson for the F-wave: verify fixtures against the capture's KEY PATHS, not only against decode results.

## [2026-11-28] Todo 16 gotchas
- kcc-web `/ui/admin/scheduled/new?...&kind=policy_switch` answers 503 when the page has no scheduler attached: build `Scheduled::over(Some(Stub::new()), builder)` (or `build(Some(..))`), never `None`, for dialog tests.
- `cargo test` stops at the first failing test binary of a crate: a gate run that fails in the middle leaves later binaries unrun; rerun the whole gate after the fix.
- A `show_fixture("ipv6/route", ...)` override can be the envelope or a bare list; the projection unwraps `route6` before appending the running static routes.

## 2026-11-28 Verifier lesson (todo 14 round 1)
- The fake-router projection of a real shape (plan procedure step 4 / IS-11) was changed by the worker but pinned by no test (mutant: projection back to the old shape survived every suite). Every decoder todo of wave W4 (13, 15, 16, 17) must have a test that reads the fake's DEFAULT answer raw for every model/firmware profile and asserts the captured envelope/keys. Verifiers of 13, 15, 16, 17: mutate the fake projection and require a named test red.
