
## [2026-11-20] Todo 7
- A repair entry written by an append whose event write then fails is durable but not broadcast (append_locked returns
  the error; the writer stops and `is_alive` turns false). Kept as in the plan; the notifier sees the writer failure instead.

## [2026-11-19] Todo 2 (n2): jiff intake
- jiff 1.0.0 taken (cargo add at 2026-11-19T21:29Z under the 3-day cooldown; 1.0.1 was 45 h old, skipped by cargo). jiff-core/jiff-static/jiff-tzdb 1.0.0, portable-atomic-util 0.2.8 come with it. xtask raised 0.2.45 -> 1.0.0; its call site moved: `Timestamp::to_zoned` is `to_zoned_datetime` in 1.0.
- jiff 1.0 renamed `Zoned` to `ZonedDateTime`: the plan's clippy entry `jiff::Zoned::now` would be an invalid (silently ignored) path, so the entry is `jiff::ZonedDateTime::now`. Added `jiff::civil::Date::in_tz` too (also reads the global db). All 9 entries proven to bite by a scratch fn in kcc-app (clippy: 9x "use of a disallowed method"), scratch removed.
- cargo vet main: imports cover portable-atomic-util (bytecode-alliance, imports.lock updated); exemptions added for jiff, jiff-core, jiff-static, jiff-tzdb 1.0.0 (add-exemption). xtask: add-exemption jiff/jiff-core/jiff-static 1.0.0 (must run from xtask/ dir: add-exemption refuses --manifest-path), then `cargo vet prune --no-imports --no-audits` removed only the now-stale 0.2.45/0.1.7 jiff exemptions, syn 2.0.119 (left the xtask lock) and portable-atomic-util (now covered by the import).
- WeeklyTime/ZoneName also got serde (ZoneName deserializes through parse, WeeklyTime through new with deny_unknown_fields) for todo 6's schedules.json; DaySet serializes Monday first.

## [2026-11-20] Todo 6 decisions (n6)
- `begin` takes `Trigger` (Slot(i64) | Now { requested_by }) instead of `slot: Option<i64>`: a run-now always has a requester, a slot never does; the record keeps `slot: Option<i64>` + `requested_by: Option<String>` as the plan says.
- `finish` takes `RunOutcome` (Succeeded/Failed/Skipped only), so Started/Interrupted can never be a "final" state.
- `resume(&Role, id, Owner, now)` cannot re-check a preset's source router (the plan's signature carries no source and the store does not open presets): it checks ManageSchedules + the action's permissions on the target; the source is re-checked at every run (todo 14). create/update check it from `NewSchedule::preset_source`.
- `[schedules] default_timezone` is a `String` validated in `Config::validate` with `ZoneName::parse` (ZoneName has no infallible default); the section lives in `settings/schedules.rs` (settings.rs is already far over 250 LOC; only 4 lines touched there).
- `skip` on a fired slot answers AlreadyFired (at-most-once covers skips too).
- `last_unsaved` = latest `Succeeded { unsaved: true }` by finished_at over policy/preset schedules of the router; it does not compare the checksum with the router (caller does).

## [2026-11-20] Todo 5 (n5)
- The Bot API URL check is its own code in settings/notifications.rs (same rules as the log-sink URL plus never_admitted on
  IP literals) instead of a shared helper extracted from LogSinkConfig::validate: keeps the parallel [schedules] edit of
  settings.rs mechanical and leaves log-sink behaviour untouched. Extending never_admitted to log sinks stays in BACKLOG.
- Chats::new also refuses a repeated chat id (after canonicalization): disabled_chats is keyed by id, and a repeat would
  double every message. ChatLabel also refuses control characters (labels are shown in CLI output).
- NotifySecrets::clear also resets token_set_at/token_rejected_at. Token file writers hold the state lock `notify-token`,
  then take notify_state.json's lock (always in that order).

## [2026-11-20] orchestrator: actual API of todo 6 (later todos 9, 13, 14, 15, 16 use THESE signatures, not the plan's sketch)
- `RunLedger::begin(&self, id: &str, trigger: Trigger, now: i64) -> Result<i64, RunError>` with `Trigger::Slot(i64)` or `Trigger::Now { requested_by: String }` (a run-now is never refused; a slot at or before `last_fired_slot` is `RunError::AlreadyFired`). Returns `now` (the record's `started_at`).
- `RunLedger::finish(&self, id: &str, started_at: i64, outcome: RunOutcome, job_id: Option<String>, now: i64)` with `RunOutcome::{Succeeded{unsaved,checksum}, Failed{code}, Skipped{reason}}`; matches the latest Started-or-Interrupted record whose `started_at` equals the one `begin` returned.
- `interrupt_started(now) -> Vec<(String, Option<i64>)>`, `skip(id, slot, reason, now)`, `runs(id)`, `last_unsaved(router) -> Option<UnsavedRun>`, `forget(id)`; `ScheduleStore::{list,get,create,update,pause,resume,delete,pause_for,pause_router}` with `NewSchedule`/`Edit`/`Owner`/`PauseReason`; preset source router via `NewSchedule::with_preset_source`.
- Todo 5: `NotifySecrets::{set_token,token,clear}` are associated fns taking `&StateStore` (+ `&MasterKey`); `NotifySettings`, `NotifyRuntime`, `NotifyEvent::{ALL,on_by_default}`, `Chats`/`Chat`/`ChatId`/`ChatLabel` in `notify_store::recipients`; `[notify.telegram]` is `settings::notifications::{NotifyConfig, TelegramConfig}` (`config.notify.telegram.api_url: Option<Url>`).

## [2026-11-20] Todo 9 (n9): StateWatch followers
- Mechanism lives in `crates/kcc/src/state_watch/follow.rs` (`Follower`, `Followers::{add,plan,apply}`, `observe_all`); tests in `state_watch/tests.rs` drive `Followers::apply(trigger, observe_all(dir, plan))` directly. `StateWatch::with_follower` carries `#[expect(dead_code)]`: the todo that registers the first follower must delete that attribute.
- Start only records (no reload); Tick reloads when any file's version changed (removal included); Hangup reloads once unconditionally; Unreadable keeps last state, warns once, no reload.
- Clippy gotchas for test modules: put `#[expect(missing_errors_doc, missing_panics_doc, panic_in_result_fn)]` on the `mod tests;` line; tests return io::Result (unwrap denied); `Arc::<T>::clone(&x)` coerces to `Arc<dyn Trait>` via a typed let.

## [2026-11-20] Todo 11 (n11): Web Administration > Notifications
- The page seals the token with the FLEET's backup key (`fleet.workflow().backups().key().duplicate()`, the wizard's
  precedent; kcc composes every store from the one master key), not a new `AdminServices` field: `AdminServices` is
  an exhaustive struct literal built in `crates/kcc/src/server_web.rs`, which todo 11 must not touch, so a new field
  would break the binary's build until todo 10. Without a fleet the token form answers 503.
- The Bot API address reaches the page through `ServerFacts::from_config` (private `telegram_api`, not a summary
  row, so the server page is unchanged).
- Public API in `kcc_web::admin_notify`: `NotifyControl { status, send_test -> TestSend<'_>, reload }`, `TestSend`
  alias (the boxed future), `NotifyStatus { queued, dropped, token_rejected, disabled_chats }` (non_exhaustive; build
  with `NotifyStatus::new(queued, dropped).with_token_rejected().with_disabled_chat(id, reason)`),
  `NotifyTestError::{NoToken, TokenRejected, ChatRefused, RateLimited, Unreachable, Rejected}` with `code()`.
  `WebState::with_notify(Arc<dyn NotifyControl>)`. Todo 10 implements the trait; the page calls `reload()` after
  every stored change and wraps `send_test` in a 20 s timeout (Unreachable).
- The page shows the token as set from `notify_state.json` `token_set_at` (it never opens the sealed token); the
  rejected banner is `token_rejected_at` OR `status.token_rejected`; a chat's state is the status's reason, else the
  runtime file's. Removing a chat also drops its `disabled_chats` mark (so remove + add re-enables it).
- Every form posts to `#page-outcome`; the answer is the whole `#notify-region` out of band with toasts (422 for
  field errors). Token removal uses the kit confirmation with `confirm=yes` checked on the server.
- Audit target `telegram` for every action; params: settings `{enabled, locale, include_client_details, events}`,
  token `{credential_changed|credential_cleared: true}`, chats `{label}`, test `{label}` (+ `failure: <code>` or
  `not_running`, outcome `failed`).

## [2026-11-20] Todo 8 (n8): Telegram client and outbox - actual API (todos 10, 12 use THESE)
- Module names differ from the plan's file names because of clippy::module_name_repetitions: `kcc_telemetry::notify::{bot::{TelegramClient, Outgoing, Sent}, delivery::{Outbox, OutboxHandle, OutboxConfig, OutboxStatus, Timings, Line, ChatFilter}, dns::PolicyResolver, failure::SendError, text::{fit, fits, MAX_MESSAGE}}`.
- `TelegramClient::new(&Url, Option<&Path>).await -> Result<Self, SendError>`; `TelegramClient::with_resolver(&Url, Option<&Path>, PolicyResolver)` (tests: `PolicyResolver::with_lookup(|host| Vec<IpAddr>)`); `send(&SecretString, &Outgoing).await -> Result<Sent, SendError>`; `Outgoing::new(&Chat, &str)` cuts with `fit`.
- `SendError` (Copy, PartialEq): RetryAfter(Duration), TokenRejected, ChatUnavailable(DisabledReason), Rejected, Transient{status: Option<u16>}, AddressRefused, CaFile, Certificate, Client, NotConfigured, Stopped.
- `Outbox::spawn(client, OutboxConfig::new(|dropped| text), store, Option<Arc<SelfMetrics>>, Timings::default()) -> OutboxHandle` (Clone). Handle: `push(Line::new(text, tokio Instant))` (sync, try_send; overload drops+counts queue_full), `configure(Option<SecretString>, Vec<Chat>, enabled)` (sync, latest wins via watch), `send_now(Chat, String).await -> Result<(), SendError>`, `status() -> OutboxStatus{token_rejected, disabled_chats, queued, dropped, sending}`, `watch_status()`, `flush(Duration).await -> bool`, `shutdown().await` (cancels and waits for the task's end).
- Token refusal: the FIRST configure takes `notify_state.json` token_rejected_at; later a different token ends it (and clears token_rejected_at if still set). configure also forgets disabled_chats entries of chats no longer listed (that is the "removed and re-added" path).
- Queues are per chat (256 lines each); `dropped` counts line copies (per chat). A test message honours the 429 hold and the chat's rate spacing, not the transient backoff; it is refused at once (no request) when no token, token refused, or chat disabled.
- Summary: after a delivered message that follows drops, the next message of that chat opens with `OutboxConfig::summary(n)` (subject to the merge window).

## [2026-11-20] orchestrator: APIs landed in W3 (todo 10 and later use these)
- Todo 9: `crates/kcc/src/state_watch/follow.rs`: `pub(crate) trait Follower: Debug + Send + Sync { fn reload(&self); }`, `StateWatch::with_follower(files: &'static [&'static str], follower: Arc<dyn Follower>)`. It has `#[expect(dead_code)]`: REMOVE it when the notifier registers its followers (todo 10), else the unfulfilled expectation fails clippy. No reload at the start baseline; reload once per pass with any change; on SIGHUP.
- Todo 8: `kcc_telemetry::notify::{bot::{TelegramClient, Outgoing, Sent}, delivery::{Outbox, OutboxHandle, OutboxConfig, OutboxStatus, Timings, Line, ChatFilter}, dns::PolicyResolver, failure::SendError, text::fit}`. `TelegramClient::new(&Url, Option<&Path>)`, `Outgoing::new(&Chat, &str)`, `Outbox::spawn(client, OutboxConfig::new(summary_closure), StateStore, Option<Arc<SelfMetrics>>, Timings) -> OutboxHandle`; handle: `push(Line::new(text, Instant))`, `configure(Option<SecretString>, Vec<Chat>, bool)`, `send_now(Chat, String).await`, `status()`, `watch_status()`, `flush(Duration).await -> bool`, `shutdown().await`.
- Todo 11: `kcc_web::admin_notify::NotifyControl` (+ `NotifyStatus`, `NotifyTestError`), `WebState::with_notify(Arc<dyn NotifyControl>)`; the page reads `AdminServices` facts (`telegram_api`). The binary must wire it in todo 10 (`crates/kcc/src/server_web.rs`).
- CI lesson: Rustdoc `-D warnings` rejects a pub doc linking a private item; test fakes must drain request bodies before 404/405 (macOS resets otherwise).

## [2026-11-20] Todo 12 (n12): kcc notify
- `kcc notify test` calls `TelegramClient::new(api_url, ca_file)` + `send(token, Outgoing::new(chat, text))` directly
  (no Outbox): one message needs no merging or pacing, and `Outgoing::new` already applies `fit`. Like the outbox's
  `send_now`, it makes no request when no token is sealed, `token_rejected_at` is set, or the chat is in `disabled_chats`;
  a 401 sets `token_rejected_at`, a 403/"chat not found" disables the chat in `notify_state.json` (as the outbox records).
  It does not require `enabled` (the outbox's test message does not either). Without `--chat` the first listed chat.
- Failure classes reuse `kcc_web::admin_notify::NotifyTestError::code()` (no_token, token_rejected, chat_refused,
  rate_limited, unreachable, rejected), so CLI and Web audit `failure` values match. SendError::{Transient, AddressRefused,
  CaFile, Certificate, Client, Stopped} -> unreachable; NotConfigured -> no_token. Exit 6 (`Exit::Router`) under the
  headline `cli-notify-test-not-sent` (`Failure::headlined` made pub(crate) for that).
- Audit: built in `cli/notify.rs` with `AuditEvent::with_target("telegram")` (Web parity) and appended through
  `Ctx::append` (made pub(crate)); `Ctx::config()` added for `[notify.telegram]` and `[web] default_locale`.
- Token source: `--file`, else the global `--password-file`, else `KCC_PASSWORD`, else a hidden prompt (`read_secret`).
- Every edit command prints a confirmation line, or with `--json` the same document as `show` (token only as
  `{set, set_at, rejected_at}`). Chat ids take `allow_hyphen_values` so `-100...` parses as a value.

## [2026-11-20] Todo 10 (n10): notifier service in kcc serve - actual API (todo 13 uses THIS)
- `crate::server_notify::{NotifyHandle, Deps, Options, FILES}`. `NotifyHandle::start(Deps::from_services(&services), Options::from_config(&config)?).await -> Result<NotifyHandle, ServerError>` (Clone). For the scheduler: `report<F: FnOnce(Locale) -> String>(&self, event: NotifyEvent, render: F)` (renders only when the event is selected and notifications are ready; the plan's `report(line)` needs the locale and the event filter, so it takes a renderer), `mute(&self, router: &str, until_unix_secs: u64)`, `scheduled_jobs() -> ScheduledJobs` (`register(id: String)`; a registered job's Failed event is dropped when the 30 s merge window after it ends). These three carry `#[expect(dead_code)]` (and `ScheduledJobs::register`): todo 13 must DELETE those attributes when it calls them. `writer_stopped()`, `follower()`, `stop().await` (flush 2 s + outbox shutdown + task abort) are wired in server.rs (`wind_down`).
- `status()`/`send_test()`/`reload()` exist only as the `kcc_web::admin_notify::NotifyControl` impl (clippy same_name_method forbids inherent twins). `status()` carries no disabled-chat reasons (the outbox status has ids only): the page falls back to notify_state.json, which the outbox writes when it disables a chat. `send_test` re-reads notify.json + token first (so a token/chat saved a moment ago is used), then `OutboxHandle::send_now`.
- "Ready" = enabled && token set && >= 1 chat; nothing is rendered, tracked for firmware, or polled while not ready (a firmware version seen before the token was set is announced once the token arrives, not lost).
- ServerError gets NO new variant (cli/exit_from.rs matches it exhaustively and is todo 12's file): a bad `[schedules] default_timezone` or an unbuildable Bot API client (CA file) is `ServerError::Config(ConfigError::Invalid { field, reason })` and stops `kcc serve` at start.
- Muted down: tracked, not announced; when the mute ends while the router is still down, the next failed poll announces Down; an Up is announced only if its Down was.

## [2026-11-20] orchestrator: APIs landed in W4 (todos 13+ use these)
- Todo 10: `crates/kcc/src/server_notify.rs` (+ `server_notify/{arrivals,audits,control,current,failed_jobs,handle,health,memory,render,routers}.rs`): `NotifyHandle::start(Deps, Options)`, methods incl. `report(line)`, `mute(router, until)`, `scheduled_jobs()`, `status()`, `send_test(chat)`, `follower()`, `writer_stopped()`, `stop().await`; `FILES` for the state watch; `render::*` builds localized lines with `notify-*` keys; the scheduler (todo 13) registers `schedules.json` with `StateWatch::with_follower` and adds its job ids to `scheduled_jobs()`; `scheduled_problem`/`scheduled_success` events are emitted through `report`.
- Todo 12: `kcc notify ...` in `crates/kcc/src/cli/notify.rs` (+ `notify/{chats,send,token,view}.rs`): single-message `test` goes straight through `TelegramClient` (no Outbox).
- keys.rs is regenerated, never merged: `cargo xtask i18n-gen` after any FTL merge.

## [2026-11-20] Todo 13 (n13): scheduler core - actual API (todos 14, 15, 16 use THESE)
- `crate::server_schedules` (crate-private, binary crate kcc): `FILES = ["schedules.json"]`; `Scheduler::{start(RunDeps, Arc<RouterRegistry>), stop_token(), follower(), finish(grace).await}`; `wiring::start_for_server(&Services, &NotifyHandle, &Config) -> Scheduler` (serve only).
- Run path: `run::run_once(&Arc<RunDeps>, id, Trigger) -> run::Report::{Dropped, Paused(PauseReason), Finished(RunOutcome)}`. A `Trigger::Now` is never retried and is NOT filtered on the schedule's state (the run-now caller decides whether a paused schedule may run); a `Trigger::Slot` of a non-active schedule is dropped. `RunDeps` fields are private to `server_schedules`; todos 15/16 add a constructor there.
- Actions: `actions::{Actions (trait, start(Call) -> Running), Call::new(&Schedule, &Role, Actor, now), ActionResult::{Done{unsaved,checksum,job}, Failed{code,job}, Skipped{reason,job}, Busy}, ActionDeps::for_server(&Services, Option<Arc<dyn Notices>>, Timings)}`. The preset arm is in `impl Actions for ActionDeps` (actions.rs): today `Skipped { reason: "preset_unavailable" }`; todo 14 replaces it and deletes the three `#[expect(dead_code)]` on `ActionDeps::{audit, presets, apply_clock}`, and adds its success `LineKind` in `run::done` + `lines.rs`.
- `ActionDeps.notify` is `Option<Arc<dyn notices::Notices>>` (trait implemented for NotifyHandle: `send_line`, `mute_router`, `claim_job`), not `Option<NotifyHandle>`: tests record mutes/lines/claims without a Telegram fake; trait method names differ from NotifyHandle's inherent `report`/`mute` because clippy::same_name_method.
- Owner: Web owner = `AccountStore::list()` entry (missing/disabled -> owner_unavailable), role via RoleSource; CLI owner = `[cli] role` + `[cli] router_scope` of the loaded kcc.toml (no OS-user check). Scope miss (role or [cli]) -> owner_unavailable; missing ManageSchedules or an action permission -> forbidden. Both pause via `ScheduleStore::pause_for`, audited `schedule.pause` {owner, reason} and reported. Router removed -> `pause_router`, audited the same way.
- Missed slots: ledger `skip(id, last_missed, "late", now)` + `schedule.run` skipped audit + one Missed line {count, local time}. Busy: one begun record, retried every `busy_retry` while `now + retry <= slot + busy_window`; stop or window end -> `Skipped router_busy`. Dequeued after the window -> begun and `Skipped router_busy` without the action.
- Reboot probe ("fresh client"): uses `registry.poll_info` + the shared `registry.client` (the RCI session replays once after the 401 a rebooted router answers); no Migrate-gated bootstrap client. The probe is not cancel-aware: a stop during it leaves the record Started -> Interrupted at the next start.
- Notification lines carry schedule name, router and (policy switch) policy; never a client. Every line of a policy/preset schedule appends `notify-scheduled-unsaved`.
- server.rs: the kit's shutdown token is now named `tokio_util::sync::CancellationToken` (kcc depends on tokio-util; same 0.7.20 in the lock), so the `default_trait_access` expect went away (also kept run_serve <= 100 lines).

## [2026-11-20] orchestrator: APIs landed in W5 (todos 14-16 use these)
- Todo 13: `crates/kcc/src/server_schedules.rs` (+ `server_schedules/{actions,lines,notices,owner,queue,record,run,slots,timetable,wiring}.rs`, `actions/{backup,policy,reboot}.rs`): `run::run_once(&Arc<RunDeps>, id, Trigger) -> Report` is THE run path for Web/CLI run-now (`Trigger::Now { requested_by }`, never retried); `actions::{Actions, ActionDeps, ActionResult::{Done,Failed,Skipped,Busy}, Call}`; `ActionDeps` has `#[expect(dead_code)]` on `audit`, `presets`, `apply_clock`: todo 14 REMOVES them when it uses them and REPLACES the `Action::Preset` arm of `Actions::start` (currently `Skipped preset_unavailable`); `Timings`; `FILES`; `Scheduler::{start, follower, stop_token, finish}`; scheduled lines in `lines.rs` (add the preset lines there with `notify-` keys).
- The CLI run-now (todo 16) builds `ActionDeps` itself (`ActionDeps::for_server` takes `Services`: a CLI-side constructor from the CLI's own services is needed) and calls `run_once`; no Telegram line from the CLI (documented).
