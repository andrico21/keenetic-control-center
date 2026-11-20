# kcc-notify-schedule: learnings (orchestrator, inherited from the CI-fix run of 2026-11-19)

## CI now runs on Linux, macOS AND Windows, on every push
CI run 44609262975 on ca856767 is the first fully green run: macOS 1810 tests, Windows 1767 tests under a NON-ELEVATED
token, doctests on all three. Every new test and fixture must hold on all three. Cheap proof from Linux for the crates a
todo touches (run once at the end, after clippy/tests; one cargo command at a time):
  export CC_x86_64_pc_windows_gnu=/home/andrico/kcc-zigcc/windows.sh AR_x86_64_pc_windows_gnu='zig ar'
  CARGO_BUILD_WARNINGS=deny cargo check -p <crates> --all-targets --target x86_64-pc-windows-gnu
  export CC_aarch64_apple_darwin=/home/andrico/kcc-zigcc/macos.sh AR_aarch64_apple_darwin='zig ar'
  CARGO_BUILD_WARNINGS=deny cargo check -p <crates> --all-targets --target aarch64-apple-darwin
(both targets are installed; the wrappers strip cc-rs's --target=... and call zig cc). It proves compilation and warnings only.

## Tests that talk to the fake router or to a fake over a socket
- Paused tokio clock (`start_paused = true`) + loopback TCP is BROKEN on macOS: TCP over lo0 delivers asynchronously (measured
  on the runner: 189 of 200 bytes not readable right after write), tokio's idle auto-advance then jumps the clock over replies
  that are written but not yet readable and every timer fires early (30 s read timeouts, the tests' own timeout(..)).
  A Unix socket delivers within the write (0 of 200 late). Rule: a paused-clock test that reaches the fake router serves it with
  `FakeRouter::serve_local()` (cfg(unix); returns (address, socket path, Handle)) and registers the socket with
  `RouterRegistry::with_local_socket(address, path)` or `OutboundPolicy::with_local_socket(address, path)` BEFORE the profile is
  created; `#[cfg(not(unix))]` keeps plain `serve` (TCP). Shapes: crates/kcc-web/tests/support/build.rs, kcc-app tests/poller.rs
  `registry_for`, kcc-telemetry tests/logs.rs `serve`/`Endpoint`. The TCP leg of serve_local delays every chunk 2 ms ON PURPOSE (a
  paused-clock client that bypasses the socket then fails on Linux too): never remove it to make a test pass.
- Tests over sockets WITHOUT a paused clock use real time with injected short ticks and await the exact event with a bounded
  timeout (no fixed sleeps). New fakes that a paused-clock test needs (the plan's FakeTelegram) should offer the same
  `serve_local` shape if a paused-clock test will use them (the plan says real time for the outbox tests: then plain TCP is fine).
- A job's `done`/verdict arrives BEFORE the job ended and freed its router write slot (cleanup runs on the job's detached task):
  a test (or tool) that starts another write job on the same router right after the verdict must `timeout(..., runner.ended(&id))`
  first (`JobRunner::ended`, kcc-app jobs.rs). Otherwise it is refused as busy on a slow host (Windows runner, macOS).

## Windows
- kcc refuses to run elevated (exit 77). GitHub's runner is elevated; the CI Windows leg runs cargo test through
  .github/scripts/deelevate.ps1 (method `filtered`: restricted token, elevated groups deny-only). Never weaken the check.
- Paths into TOML: use `kcc_testkit::toml_text::path(&Path)` (a backslash path in a TOML basic string starts a \U escape).
  Paths looked up in JSON text: compare `serde_json::to_string(&path)`.
- Spawned kcc children with `env_clear()` must pass `SystemRoot` (sockets fail to load otherwise) and set `LOCALAPPDATA` and
  `APPDATA` next to the XDG variables (kcc resolves its config/state dirs from them on Windows).
- A state scan must skip `*.lock` (a held lock is a mandatory byte-range lock on Windows: read fails with os error 33).
- No SIGHUP on Windows: a test that reloads with SIGHUP is `#[cfg(unix)]` with a one-line reason; unix-only helpers are gated too
  (CARGO_BUILD_WARNINGS=deny turns an unused item into an error).
## macOS
- kcc reads its config from $HOME/Library/Application Support/kcc, not XDG (docs example harness mirrors it per platform).
- Unix socket paths are limited to 104 bytes: keep temp dir names short.
## Process rules that still stand
- Workers never git add/commit/push; the orchestrator lands `git diff --binary` patches, runs no_secrets with the warm main target,
  and pushes fast-forward. A push cancels the in-progress CI of the same ref: batch landings, do not push while a run is needed.
- C: free space (`df -BG --output=avail /mnt/c`) must stay above 80G for workers; no cold target when a warm copy exists; no debug
  builds without a reason; `CARGO_BUILD_JOBS=2` (1 when two other cargo builds run).

## [2026-11-19] Todo 1 progress
Overlay deviation 6 and rule (i') added, BACKLOG section appended at the end (no CI section in base 5eca1fab). Heading date 'status 2026-11-14' left alone: git history shows it was not bumped when items 5 (2026-11-16) or the 2026-11-18 updates landed. Checksums pass before and after. Docs test not run (prose only).

## [2026-11-20] Todo 4 progress
FakeTelegram: handler split into src/fake_telegram/handler.rs (child module sees parent's private fields; no mod.rs, no pub use). Every request is recorded (wrong token and invalid body included) before the token check; chat_id is compared as the JSON value as sent (5 != "5"). Wrong token = 401 without consuming a fault. Slow(d) sleeps then answers normally. Request Debug redacts the token. wait_for_requests uses watch::wait_for. kcc-fake-sinks prints telegram <url> as 3rd line; report line is "sink requests loki=.. elasticsearch=.. telegram=.." (e2e regex loki=..elasticsearch=.. still matches). Clippy lints bite tests: default_numeric_fallback (json!(1) -> suffix or typed helper), indexing_slicing (use .get), shadow_*. No serve_local added: plan's outbox tests use real time.

## [2026-11-20] Todo 7 progress (audit broadcast, PollError::Auth)
- `AuditLog::subscribe()` is a tokio broadcast (capacity 256) in `Progress.written`; the writer sends the repair entry
  (now returned by `WriterState::append_locked` as `(Option<AuditEntry>, AuditEntry)`) and then the event entry, after
  `Reply::Written`. Send errors (no receiver) are dropped; a slow receiver gets `RecvError::Lagged(n)`; 300 appends with an
  unread receiver -> `Lagged(44)`, then seq 45.
- Subscribe BEFORE the first append in tests: `append()` returns on `Reply::Written`, which precedes the broadcast send, so a
  receiver created right after an append may still see that entry.
- The spawn-time repair is held in `Progress.startup_repair: std::sync::Mutex<Option<AuditEntry>>` and `take()`n once by
  `AuditLog::startup_repair()` (any clone); it is never broadcast.
- `wildcard_enum_match_arm = "deny"`: mapping one variant of a foreign non_exhaustive enum (RciError::Auth) uses `matches!`.
- A login the fake router rejects: `FakeRouter::builder(..).user(DEFAULT_LOGIN, format!("{DEFAULT_PASSWORD}-rotated"), [..])`
  replaces the default admin, so `registry_for`'s DEFAULT_PASSWORD file is refused. Before the fix it surfaced as
  `PollError::Registry { reason: "RCI authentication failed" }` (from `poll_client`/`poll_info`).

## [2026-11-19] Todo 2 progress (n2)
jiff 1.0 API: `ZonedDateTime` (not `Zoned`), `Timestamp::to_zoned_datetime`, `TimeZone::to_ambiguous_timestamp(dt).compatible() -> Result<Timestamp>`, `TimeZoneDatabase::bundled()`, `db.get(name)` is case-insensitive and cached. Use `kcc_app::schedules::time::{zones, ZoneName, DaySet, WeeklyTime, format_local}`; never `jiff::tz::db()` (clippy refuses it). The all-zones proptest takes ~1 s (32 fixed-seed cases per zone).

## [2026-11-20] Todo 3 progress
Permission::ALL is 12; new FTL keys appended at the end of each web.ftl. RolesDocument and Role are non_exhaustive: integration tests build a RolesDocument with default() + push. README/SECURITY prose only: kcc docs test not run.
Files moved: unit tests now in crates/kcc-app/src/schedules/time/tests.rs (time.rs 197 pure LOC, tests 121).

## [2026-11-20] Todo 6 progress (n6): schedule model, store, run ledger
- Paths: `kcc_app::schedules::{model::{Schedule, Action, Owner, ScheduleState, PauseReason, NewSchedule, Edit (= NewSchedule), PRESET_SOURCE_PERMISSIONS, names::{ScheduleName, ClientMac, PolicyName, PresetId, FieldError}}, store::{ScheduleStore, SchedulesDocument, ScheduleError, MAX_PER_ROUTER, MAX_TOTAL}, ledger::{RunLedger, RunsDocument, ScheduleRuns, RunRecord, RunState, RunOutcome, Trigger, UnsavedRun, RunError}}`; `kcc_app::settings::schedules::SchedulesConfig` (`Config.schedules`).
- Text fields are newtypes parsed on construction AND on deserialize (`serde(try_from = "String")`), so a hand-edited schedules.json with a bad MAC/policy/name fails to load.
- `RunLedger::begin(id, Trigger::Slot(unix) | Trigger::Now { requested_by }, now) -> Result<i64 started_at, RunError>`; `finish(id, started_at, RunOutcome, Option<job_id>, now)`; `skip(id, slot, &str reason, now)` also refuses a fired slot; `runs(id)` reads the history; `fire_until` (pub(super)) is what create/update/resume call (max(last_fired, now)).
- Store sync (StateStore file locks); no async fn added. Out-of-scope schedule -> NotFound; in scope but missing action permission -> Forbidden. pause/resume/delete/update also need the CURRENT action's permissions on the current router.
- Concurrency test: two std threads + Barrier racing `begin` for one slot; the per-file flock serializes them in-process too (separate open file descriptions).
- Clippy in tests: `let _: T = ...` on a Drop type is refused (use drop(..) or a named `_binding`); `{ .. }` patterns refused (`rest_pat_in_fully_bound_structs`/`unnecessary_rest_pattern`): spell `{ field: _ }`; Display::fmt param must be named `f`.

## [2026-11-20] Todo 5 progress (n5): notify settings and the sealed bot token
- API: `kcc_app::settings::notifications::{NotifyConfig, TelegramConfig, DEFAULT_TELEGRAM_API_URL}` (Config field `notify`);
  `kcc_app::notify_store::{NotifyError, NotifyEvent, NotifySettings (notify.json), NotifyRuntime (notify_state.json), DisabledChat, DisabledReason}`,
  `notify_store::recipients::{Chat, ChatId, ChatLabel, Chats, MAX_CHATS}`, `notify_store::token::NotifySecrets::{set_token, token, clear}`,
  `secrets::binding::Binding::notify_telegram()`.
- Module names avoid clippy::module_name_repetitions: `settings::notify` would flag `NotifyConfig`, `notify_store::chat` flags `ChatId`.
- `TelegramConfig.api_url` is `Option<Url>`: Default parses the constant with `.ok()` (no unwrap/expect allowed), an absent key
  takes the default through struct-level `#[serde(default)]`; `validate` refuses `None`. Consumers use `api_url.as_ref()`.
- ChatId is stored as TEXT (`"-100123"` or `"@name"`, integers canonicalized, `+42` -> `42`) so it can key a JSON map in
  notify_state.json; `ChatId::numeric()` gives the i64 for the Bot API body (FakeTelegram compares chat_id as sent: 5 != "5").
- `locale` is `Option<kcc_i18n::locale::Locale>` serialized as its tag (`with = "locale_tag"`); `kk-KZ` reads as `kk`.
- Token timestamps are Unix seconds from SystemTime inside set_token (signature kept as the plan's: state, key, token).
- A runtime RED for a validation fn: `-D unused` forbids a not-yet-called fn and `CARGO_BUILD_WARNINGS=warn` does not lift
  workspace lint levels; a temporary `if cfg!(test) { return Ok(()); }` at the top of the check gave a clean runtime RED.
- Evidence logs are scanned by people too: a panic message printing a private test URL was redacted in the red log.

## [2026-11-20] CI fix d4f96b37 (macOS fake_telegram reset)
A test fake that answers (404/405) without reading the request body can reset the client on macOS (RST on close with unread bytes discards the response; Linux usually delivers it). Fix: fallback and method_not_allowed_fallback handlers take `Bytes` to drain before answering. Not reproducible on Linux even with 1 MiB bodies. Axum's default body limit is 2 MiB (a 2 MiB test body gets 413). Sibling fakes fake_loki/fake_elasticsearch have only one route and no fallback: same latent defect. Rustdoc: a public item's doc must not intra-doc-link a private item.

## [2026-11-20] Todo 8 progress (n8)
- reqwest resolver errors: `Err(Box::new(MyErr).into())` DOUBLE-boxes (From<E: Error> picks Box<MyErr>), so `source().is::<MyErr>()` fails. Annotate: `let e: Box<dyn Error + Send + Sync> = Box::new(MyErr); Err(e)`. Chain: reqwest::Error -> hyper_util Error -> ConnectError("dns error") -> reqwest DnsError -> your error.
- A literal IP in the URL never reaches a custom `dns::Resolve`: check literals yourself (TelegramClient::with_resolver does with never_admitted).
- `tracing_subscriber::util::SubscriberInitExt::set_default()` (feature tracing-log) installs LogTracer too, so a thread-local TRACE capture sees reqwest's `log` records ("starting new connection") in a current-thread tokio test.
- field_scoped_visibility_modifiers forbids pub(super) fields: share structs by defining them in the PARENT module (children see private fields of ancestors), e.g. delivery.rs `Parts`, task.rs `Settings/Test/Cargo`.
- FakeTelegram `Fault::Slow` holds a request a fixed time; the queue-overflow test works whether or not the 300 pushes land before the release (cap applies either way).

## [2026-11-20] Todo 11 progress (n11): Web Administration > Notifications
- `clippy::field_scoped_visibility_modifiers` refuses `pub(super)` fields: keep fields private and give the type
  methods (`Region::refuse(Field, msg)`, `Seen::settings()`); a template can read private fields only of types
  defined in the module that derives the Template.
- askama: inside `{% for x in list %}` a `MessageKey` field is `&MessageKey`: write `t(*x.label)`.
- A template needs `use kcc_i18n::keys` and `use crate::page::Localize as _` in the deriving module.
- `clippy::fn_params_excessive_bools`/`struct_excessive_bools`: more than 3 bools in a struct is refused; group them.
- Unknown routes under /ui answer 403 (not 404) to a POST without CSRF (the CSRF layer runs first), so a
  "POST without CSRF is refused" test passes before the route exists: give it a positive control (same post with
  the token accepted) to make it RED first.
- `Setup { wiring: Wiring::Fleet, ..Setup::default() }` then `.roles.extend`/`.accounts.extend` builds a fleet
  without routers whose `WebState` can be cloned and given `with_admin`/`with_notify` before `web_router`.

## [2026-11-20] Todo 12 progress (n12)
- A separate kcc test binary that reuses `tests/cli/support.rs` needs `#[expect(dead_code)]` on that `mod` when it uses no
  fake router (`support::router` stays unused). Test modules split into `tests/cli_notify/*.rs` see the root's private
  helpers through `use crate::{..}`.
- Clippy in kcc tests: `absolute_paths` (import `core::error::Error`, `std::process`), `integer_division_remainder_used`
  refuses `%` (build run-time tokens with `iter().cycle().skip(..).step_by(..)`), `similar_names` (`set`/`sent`),
  `redundant_test_prefix` (a test fn named `test_*`).
- Manual QA of `kcc notify test` MUST point `[notify.telegram] api_url` at a fake: the default is the real Bot API.

## [2026-11-20] Todo 10 progress (n10)
- Deterministic barrier for "the notifier handled audit entry X": append a later entry that produces a message (one audit task, in order) and await that message at the FakeTelegram.
- tokio watch::Sender::send_replace(()) on a `watch::Sender<()>` is a clean "reload requested" signal whose loop ends when the sender drops (no infinite_loop lint, unlike Notify in a bare loop).
- clippy too_long_first_doc_paragraph: the first doc paragraph must be one short sentence; split with a blank `//!`/`///` line.
- Adding a ServerError variant breaks crates/kcc/src/cli/exit_from.rs (exhaustive match) - use ServerError::Config(ConfigError::Invalid{..}) for config-shaped startup failures.

## Todo 18 (live Telegram suite)
- live_telegram.rs: the live flow takes its variable lookup as a closure, so the hermetic skip test runs the same body with an empty lookup and captures the tracing output through a local MakeWriter (set_default guard, current-thread test). Clippy here denies integer division, std-instead-of-alloc, absolute paths, unused async and missing assert messages in tests too. Sent is Copy: bind it as `let _sent: Sent` (unused-results is denied).

## [2026-11-20] Todo 13 progress (n13)
- Paused-clock loop tests: a wall clock = base + tokio `Instant::elapsed` + steps moves with auto-advance; spawn_blocking reads of state files inside the loop are fine under `start_paused`. A "never fires" RED stub must not make the loop sleep 0 s (it spins forever and virtual time never advances): shift `after`, not `now`.
- The kit logs "listening" BEFORE run_server installs its SIGTERM handler: a test that SIGTERMs right after "listening" can kill the process with the default action (exit by signal 15). Answer one `/healthz` first.
- Fake router: a policy on a fixture-registered client (`ip/hotspot` fixture) does not read back (projection applies `ip hotspot host` lines only to `known host` entries of the config): register the client through the workflow first.
- clippy in tests: `field_scoped_visibility_modifiers` also bites `pub(crate)` fields of test rigs (use accessors); `AtomicUsize::fetch_update` is deprecated (use `try_update`); a `watch::Ref` from `wait_for` must be dropped explicitly (unused_results).

## [2026-11-20] Todo 14 progress (n14)
- Deterministic "the run holds the lease mid-apply": subscribe to `JobRunner::subscribe()` before the run, await the first job event (the reservation is taken before `Applier::start`), then `Handle::stall()` + `stall.held()` (a request of the run is held), then `workflow.reserve` -> RouterBusy. If the run had already ended, held() never resolves and the test fails loudly (no false pass).
- A hand-moved `kcc_migrate::apply::Clock` (watch::Sender<Duration> + recorded waits) lets a test see the run waiting for the fail-safe timer (`waiting_longer(60 s)` returns recovery_left = 901 s) and release it with `advance(left)`; nothing else in a rollback refused at `close` waits on the clock.
- Fake router: `fail_parse_matching("system configuration fail-safe timer", 2)` refuses both the arm and its cleanup disarm -> ApplyError::ArmUnconfirmed (recovery_armed) from preparation; `silent_noop_path(<exact parser line>)` ignores just that line.
- Clippy: `too_long_first_doc_paragraph` fires on ~3-line first paragraphs (tests included): one short sentence, blank `///`, details. `shadow_reuse` fires on closure params named like the receiver (`waits.wait_for(|waits| ..)`) and on `let (x, role, id) = (.., role.clone(), id.to_owned())`. `module_name_repetitions` on `unattended::UnattendedRefusal` (kept the plan's name with an expect).
- `#[cfg_attr(not(test), expect(dead_code, reason))]` keeps a crate-visible fn for a later todo that tests already call.

## [2026-11-20] Todo 16 progress (n16)
- clippy `missing_assert_message` does not fire inside #[test]/#[tokio::test] fns but DOES in test helper fns.
- clippy `struct_excessive_bools` (>3 bools) bites clap Args structs: split into flattened sub-structs with `#[group(skip)]`;
  an `ArgGroup` on the outer struct can still name the inner fields' ids.
- A RED stub of a new crate-visible fn trips `dead_code` under warnings=deny in the non-test build: for the process-level RED
  run the module line was commented out temporarily, then restored.
- A wrapper `cmd | grep -v ...; echo $?` under pipefail reports grep's 1 when the command prints nothing (fmt --check):
  capture the command's own status first.

## [2026-11-20] Todo 15 phase 1 (n15)
- askama: a `for (value, label) in array_field` binds `label` as `&&MessageKey` -> `t(**label)`; a plain `MessageKey` field passed to `t(..)` fails (reference): expose a `const fn` getter.
- askama strips `{% if false %}` blocks entirely, so a field only read there becomes dead code (useful to know when neutralizing a template for a RED run: use a runtime-false condition such as `x.is_some() && router.is_empty()`).
- Foreign `#[non_exhaustive]` enums (Action, ScheduleState, PauseReason, RunState, TimeError, ScheduleError): match with `Known | _ =>` (the codebase precedent, view.rs) or `matches!` chains; a bare `_` arm trips wildcard_enum_match_arm.
- A type gets ONE inherent impl (clippy multiple_inherent_impl): a child module that parses a parent's struct uses free functions taking `&Parent`.
- Golden HTML: dump with a scratch integration test writing to a dir from an env var; normalize the CSRF meta and the `/tmp/.tmpXXXX` state path (server page), nothing else varies.

## [2026-11-20] Todo 15 phase 1 progress (n15)
- Phase 1 (kcc-web only) done and uncommitted in /home/andrico/kcc-wt/n15; phase 2 (crates/kcc ScheduleControl impl, server wiring, serve_scheduled_web.rs) pending todo 16. Evidence: task-15-kcc-notify-schedule{,-red}.log. No existing test expectation changed; the admin tab bar gains only the Scheduled actions tab (golden diff on /ui/admin/users and /ui/admin/server), dashboard and configuration page goldens unchanged.

## [2026-11-20] Todo 15 phase 2 (n15)
- `NotifyEvent::ScheduledSuccess` is OFF by default (noise): a serve test that waits for a scheduled success line must add it to `NotifySettings.events`.
- The Web page answers a refused dialog (store refusal, scheduler refusal, field error) with 422, not 200.
- A fixture-registered client (`02:00:00:00:10:01`, policy Policy0 in the fake's fixture) switched to `Policy0` reads back fine: the serve run succeeds
  and the running config gets `ip hotspot host <mac> policy Policy0` (startup config does not).
- Dropping a `tokio::task::JoinSet` ABORTS its tasks: wrap it in a type whose Drop calls `detach_all()` when tasks must never be aborted.
- clippy: `redundant_guards` prefers `Ok(Err(Foreign::A | Foreign::B))` over a `matches!` guard; `significant_drop_tightening` wants an explicit
  `drop(guard)` right after the last use; `drop(bool)`/`drop(i64)` is `dropping_copy_types` (use `let _: T =`); `Result<(), ()>` from a oneshot send:
  `.unwrap_or_default()`.

## [2026-11-20] Todo 17 (wt/n17): e2e Telegram and scheduled-run legs, seccomp re-trace
- e2e.sh: token shape is `<digits>:<30..64 of [A-Za-z0-9_-]>` (kcc-app notify_store/token.rs well_formed), so `0:e2e-fake-token` is refused; the script uses `0:e2e-fake-token-not-a-real-telegram-bot` (0600 file natively, Podman secret `kcc-telegram-token` in container mode).
- `notify events scheduled_success` only: no other event can add a message, so both steps compare the fake's `telegram=` count before/after (helper `telegram_count`/`wait_telegram_above`) instead of `telegram=[1-9]`, which an unrelated event could satisfy.
- Web schedule create: POST /ui/admin/scheduled fields name, router, days (repeatable), hour, minute, zone, kind=backup; field errors also answer 200, so the id is read back with `kcc --json scheduled list`. run-now: POST ?id= with confirm=yes, 200 on admit, 422 on refusal. CSRF token must be read from a page AFTER login (session-bound).
- Gotcha: `kcc-cargo xtask seccomp trace` deadlocks: xtask inherits the wrapper's flock fds, so the e2e's inner `cargo build` (through a kcc-cargo shim) never gets a slot. Build xtask once, then run `$CARGO_TARGET_DIR/debug/xtask seccomp trace ...` directly.
- A union of only local x86_64 traces drops `fchmodat` (arm64-only, CHANGELOG). Unioned with the arm64 traces of CI run 44703192182 (base c1cd67e9, `gh run download -n seccomp-trace-arm64`): profile byte-identical, no syscall added or removed; the new legs need nothing new on x86_64.

## [2026-11-20] Todo 19 (worktree n19): latest-version recheck
- Dry run at 09:37 UTC equal to the RED one of 08:57: root clap/clap_derive 4.6.7->4.6.8, clap_complete 4.6.11->4.6.12, clap_lex 1.1.1->1.1.2, uuid 1.29.2->1.29.3; xtask clap/clap_derive/clap_lex. clap_builder stays 4.6.7 (clap 4.6.8 pins `clap_builder = "=4.6.7"`).
- check_dep_reqs.py flags a patch bump of a DIRECT dependency (clap, clap_complete): raise the manifest requirement even for compatible updates; uuid is transitive (rmcp) so no edit.
- crates.io created_at (for exact cooldown ends): zeroize 1.9.2 2026-11-17T14:47Z, rmcp 3.11.0 15:33Z, bytes 1.12.2 20:59Z, jiff 1.0.1 2026-11-18T00:50Z, regex-* 02:53Z, smallvec 08:10Z, pin-project-lite 0.2.18 2026-11-19T16:48Z, clap 4.6.9 2026-11-20T01:41Z. A dry run after 2026-11-20T21:00Z will show updates again (not a finding per the convergence rule).
- uuid 1.29.3 removes its optional `atomic` dependency (v1/v6 features) and gives ParseOther a message; nothing new pulled in, no build scripts.
- cleanup: /home/andrico/kcc-target-n19 and /home/andrico/n19-* removed at 10:27:29Z

## [2026-11-20] Todo 21 (n21)
- An event to await for "the lease is free again": the scheduled run (or `JobRunner::ended`) returns only after the hold dropped the change set, so tests await the run/job end, never a reserve retry loop. `HandClock::waiting_longer(1 min)` sees the hold's `safety_seconds + 1` wait; advancing by `left - 1s` then `1s` proves "not one second early" deterministically.
- `tokio::select!` between `clock.waiting_longer(..)` and the run's `JoinHandle` gives a fast, telling RED ("the run ended with the lease free") instead of a 60 s timeout.
- clippy here denies `result_large_err` (an `Err` holding a `ChangeSet` is ~580 bytes: box it), `field_scoped_visibility_modifiers` (`pub(super)` fields: use a `const fn` getter), `redundant_imports` (`alloc::boxed::Box`), `shadow_reuse` in closure params, `future_not_send` for `f(x.await?).await` in tests (split the statement), and `too_long_first_doc_paragraph`.
- `preflight::prepare` sits at ~96 of the 100 allowed lines; any growth needs an extraction (the firmware-tier match moved to `support_tier`).
