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
