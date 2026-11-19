---
slug: kcc-notify-schedule
status: approved-final
intent: clear
review_required: true
plan_path: .omo/plans/kcc-notify-schedule.md
plan_sha256: 913fefc49727436033c75fa6d8c3fbb86586805930171a4f5c5736c93d6eda5f
review_round_id: round-4cb80ea57f26
round_status: complete
pending-action: none - approved by Metis, Momus and the Oracle on 913fefc4; worker runs `$ulw-execute kcc-notify-schedule` after the CI-fix task (and not while another plan run is in progress)
review:
  metis:
    status: done
    session: ses_e0c254b4cffeiDOkKfNT65mI1U
    round_id: round-4cb80ea57f26
    plan_sha256: 913fefc49727436033c75fa6d8c3fbb86586805930171a4f5c5736c93d6eda5f
    result: READY (no notes)
  momus:
    status: done
    workspace_root: /home/andrico/keenetic-control-center
    runtime_home: null
    target: .omo/plans/kcc-notify-schedule.md
    round_id: round-4cb80ea57f26
    plan_sha256: 913fefc49727436033c75fa6d8c3fbb86586805930171a4f5c5736c93d6eda5f
    launch_id: null
    session: ses_e0c0f0796ffeZcTsFm3dtAotal
    result: OKAY (informational only: confirm the execution precondition at start)
  independent:
    status: done
    workspace_root: /home/andrico/keenetic-control-center
    runtime_home: null
    target: .omo/plans/kcc-notify-schedule.md
    round_id: round-4cb80ea57f26
    plan_sha256: 913fefc49727436033c75fa6d8c3fbb86586805930171a4f5c5736c93d6eda5f
    launch_id: launch-6cd54f6fb827
    session: ses_e0c25916bffe6zcizhcvwMCFqJ
    result: OKAY (no notes)
approach: one plan for (A) Telegram notifications from kcc serve (outbound only, no bot commands) and (B) a kcc-side scheduler for a closed set of weekly actions (client policy switch, preset apply, backup, reboot), with run-time owner and permission checks, the normal change workflow, never saving, at-most-once slots and outcome notifications
---

# Draft: kcc-notify-schedule

## Affected user and ideal state
<!-- Who this output touches (a customer, another programmer, a program or agent consuming it - often more than one) and how each uses it today and will use it after. -->
<!-- IS-n | property of the ideal state: nothing snags, feels odd, regresses, or degrades for them | reason -->
<!-- GAP-n | difference between IS-n and today | reason | closed by todo(s) -->
Users: U1 owner/admin (Web, CLI); U2 household (scheduled policy switches, reboots affect them); U3 operator of kcc serve (outbound to Telegram, state, container); U4 maintainers/worker; U5 AI assistant (no new MCP write tools).
- IS-1 | U1 gets timely Telegram messages for chosen events (router down/up debounced, new unregistered device, account lockout, change failed or rolled back by fail-safe, firmware update available, audit chain problem, scheduled-run outcomes, job failures), localized, deduplicated, rate-limited, never leaking secrets or (by default) client details | awareness without watching the UI
- IS-2 | Telegram delivery is reliable and safe: https only (loopback http for tests/self-hosted API), retries with retry_after, 4096-char cap, bot token never in logs/errors/Debug (URL-stripped reqwest errors), outbound-only (no getUpdates), test message from Web/CLI | rule (d), availability
- IS-3 | U1 creates weekly schedules (days of week, hour, minute, IANA timezone) for a closed set of actions: switch a client's connection policy/access, apply a saved preset, create a backup, reboot a router; Web + CLI | the asked feature
- IS-4 | Each run re-checks the creator's permissions, uses the normal change workflow (lease, backup, conflict check, read-back, audit, fail-safe for risky changes), never saves unless the schedule says so, handles busy routers (retry window) and missed runs (skip + report), suppresses expected down alerts during scheduled reboots, and reports the outcome | safety + project rules
- IS-5 | DST-correct times in any IANA zone inside the static container | correctness
- IS-6 | Everything testable without hardware or Telegram (fake Telegram API, fake router, paused time); docs, i18n x6, CHANGELOG, CI/supply chain green and latest | standing rules
- GAP-1..7 and IS-1..7 as finalized in the plan's Scope table (IS-6 household visibility and IS-7 testability/supply chain were split out after Metis); closing todos: GAP-1 7,10; GAP-2 1,4,5,8,9,11,12; GAP-3 3,6,9,15,16; GAP-4 6,13,14; GAP-5 2; GAP-6 13,15,20; GAP-7 1,17,18,19,20 | explore bg_653a28ec, Metis bg_e2e43149

## Components (topology ledger)
- C1 | Notification core: event model + dispatcher in kcc serve (dedupe, rate limit, quiet hours?) | active | planned: todos 8 (outbox), 10 (dedupe, rendering)
- C2 | Telegram sender: Bot API client (outbound policy, token secrecy, retries, 429, caps), config/secrets, fake Telegram for tests | active | planned: todos 4, 5, 8, 11, 12
- C3 | Event sources wired: router down/up, new unknown device, login failures/lockouts, change failed/rolled back, firmware update, audit problems, job/scheduled-run outcomes | active | planned: todos 7, 10
- C4 | Scheduler core: persisted schedules, time model + timezone, next-run computation, missed-run policy, run-time permission re-check, execution through jobs/workflow | active | planned: todos 2, 6, 9, 13
- C5 | Scheduled actions: client policy switch, preset apply (unattended finish), backup, reboot | active | planned: todos 13 (policy, backup, reboot), 14 (preset)
- C6 | Surfaces + docs: Web admin pages, CLI, (MCP read?), i18n x6, docs, CHANGELOG, live/e2e | active | planned: todos 11, 12, 15, 16, 17, 18, 20
<!-- Lock the SHAPE before depth. One row per top-level component that can succeed or fail independently. -->
<!-- id | outcome (one line) | status: active|deferred | evidence path -->

## Open assumptions (announced defaults)
<!-- Record any default you adopt instead of asking, so the user can veto it at the gate. -->
<!-- assumption | adopted default | rationale | reversible? -->
All announced defaults, with rationale, are the plan's "Adopted defaults" table (Must have); every row is reversible without data loss. Corrections to Metis: a failed preset run's rollback is sent under Migrate (crates/kcc-migrate/src/apply/finish.rs:72-96), so Destructive is not added to preset schedules; Telegram api_url lives in kcc.toml only (Metis P0-1), the Web page edits the rest (D-TGWEB).

## Findings (cited - path:lines)
- Log sinks template: LogsConfig/LogSinkConfig (crates/kcc-app/src/settings.rs:440-572), secret files read async (crates/kcc-telemetry/src/logs/sink.rs:46-81), HTTP client no_proxy/no redirects/5s connect/30s timeout (sink_http.rs:12-41), Retry-After handling (sink.rs:92-129), https unless loopback (settings.rs:618-626); fake sinks FakeLoki (crates/kcc-testkit/src/fake_loki.rs) + kcc-fake-sinks binary.
- Event sources: poller snapshots incl. update_available (crates/kcc-app/src/poller.rs:29-75), firmware check task (crates/kcc/src/server_tasks.rs:16-24), accounts lockout fields (accounts.rs:71-116), job statuses + broadcast JobEvent (jobs.rs:52-216), audit writer (crates/kcc-app/src/audit.rs + audit/writer.rs; unbounded mpsc command channel :399,:467).
- Actions: clients::plan_policy / plan_access (crates/kcc-domain/src/clients.rs:212,244), preset apply + keep_unsaved finish (crates/kcc-migrate/src/apply.rs:225), BackupStore::create (crates/kcc-app/src/backups/store.rs:74), system reboot terminal request (crates/kcc-domain/src/system.rs:299).
- Router schedule model ActionTime minute/hour/day-of-week (crates/kcc-domain/src/schedules.rs:36-84).
- Time: main workspace has no tz crate (Unix seconds); chrono only in kcc-telemetry (RUSTSEC-2026-0543 ignored); chrono-tz unmaintained (RUSTSEC-2026-0555). jiff 1.0.0 (2026-11-15) past cooldown, 1.0.1 (2026-11-18) not yet; MSRV 1.85; Unlicense OR MIT; `tzdb-bundle-always` embeds IANA tzdb. croner 4.0.3 not needed (weekly model computed with jiff).
- Telegram: sendMessage(chat_id, text<=4096, parse_mode HTML escapes < > &, disable_notification, message_thread_id), 429 parameters.retry_after, 401/403 non-retryable, ~1 msg/s per chat; token in URL path -> reqwest::Error::without_url() and a redaction pattern `/bot[0-9]+:[A-Za-z0-9_-]+`.
- Project rule (i) "No stored client telemetry history" -> new-device detection must stay in memory (router's registered flag + in-memory seen set; baseline on first poll).
- Permissions today: Read, Write, Save, Destructive, Migrate, RawRci, RevealSecrets, ManageRouters, ManageUsers, ViewAudit (crates/kcc-app/src/permissions.rs:15-56).

## Decisions (with rationale)
- Owner 2026-11-19: "both, plan" = Telegram notifications AND the scheduler, critic-validated (Metis + Momus + Oracle, every note applied), latest versions past the 3-day cooldown for any new dependency (D-LATEST), one commit per todo.
- Owner 2026-11-19 D-UNSAVED: scheduled changes are never saved; they stay in the running config (preset apply finishes with keep_unsaved after verification; failures roll back).
- Owner 2026-11-19 D-TZ: new dependency jiff (newest past the 3-day cooldown; 1.0.0 on 2026-11-19), feature `tzdb-bundle-always`; schedules carry an IANA zone; DST via jiff disambiguation.
- Owner 2026-11-19 D-TGWEB: Telegram is configured on a Web admin page (token pasted once, sealed in state, never shown again; chat ids, events, language, client-detail toggle editable there); CLI parity for headless setups.
- Defaults announced: events ON by default = router down/up (debounced), change failed / fail-safe rollback, scheduled-run failure or skip, account lockout, audit chain problem, firmware update available (once per version), job failure; OFF = new unregistered device. Client names/MAC/IP redacted in messages unless include_client_details. New-device detection in memory only (rule (i)). Messages in a notification locale (default [web] default_locale). New permissions ManageNotifications and ManageSchedules (admin only by default); each schedule also needs the action's permissions at creation and run time (reboot = Destructive; preset = Read+Migrate+Write+Save; policy = Write; backup = Write). Missed run: run if <= 2 min late, else skip + notify. Busy router: retry every minute up to 10 min. Scheduled reboot suppresses that router's down/up alerts for up to 15 min. No MCP tools for schedules or notifications in this plan. Telegram api_url https (http only on loopback), no proxy, no redirects, outbound only.
- From the earlier recommendation the owner accepted: no Telegram bot commands (outbound only); zero-code Alertmanager path stays documented; scheduler limited to actions the router cannot schedule itself; scheduled actions run only while kcc serve runs.

## Scope IN
Telegram notifier in kcc serve (events listed in plan IS-1), Bot API client + outbox, fake Telegram, notify settings + sealed token, permissions ManageNotifications/ManageSchedules, jiff weekly slots, schedule store + run ledger, scheduler with four actions, StateWatch followers, Web admin pages + dashboard/config notes, `kcc notify` and `kcc scheduled`, overlay deviation 6 + (i'), e2e/seccomp, live Telegram suite, docs, G1/latest recheck.

## Scope OUT (Must NOT have)
See the plan's Must NOT have: no inbound Telegram, no MCP tools, no stored client history, no auto-save, no catch-up past 2 min, no cron, no scheduled access, no Mirror presets, no quiet hours or per-user subscriptions or other channels, no Web-editable api_url, no system time zone, no new ActorKind.

## Open questions
None blocking; defaults announced in the plan.

## Approval gate
status: approved (owner: "both, plan" + answers to the three forks)
<!-- When exploration is exhausted and unknowns are answered, set status: awaiting-approval. -->
<!-- That durable record is the loop guard: on a later turn read it and resume at the gate instead of re-running exploration. -->
- Round 1 (round-4cb80ea57f26, launch launch-49a9f49c9d98): plan written 2026-11-19, sha 913fefc49727436033c75fa6d8c3fbb86586805930171a4f5c5736c93d6eda5f; critics launched (Metis bg_03449fd0 fresh session, since the gap-analysis session could not be resumed; Momus bg_938bfc4a; Oracle bg_f7206d09).
- Round 1 results: Momus OKAY (note: todo 8 needs todo 5); Oracle REJECT (B1 scheduler token never cancelled on SIGTERM; B2 rule (c) vs busy window; notes: busy retry vs ledger, fake request time, kcc-app->kcc-i18n edge, D-UNSAVED wording, StopTimeout sum, F1 greps vs comments, read_capped visibility, LocalCommand location, preset job kind, dead Components refusal); Metis NOT READY (B1 same shutdown defect; B2 busy retry hits AlreadyFired; B3 todo 8 depends on 5; B4 no owner for the SECURITY.md Telegram paragraph; B5 "restored" message unverified after failed keep_unsaved; notes: kcc-telemetry deps (reqwest::Url, secrecy::zeroize, tokio net), Applier::start Err path, preset source-router authorization, AGENTS live-contract exemption, token TRACE via Web POST, CLI run-now vs server start, UpdateCheck::cached tuple, clippy in_tz/get, evidence naming, e2e telegram line wait). Every item applied in round 2.
- Round 2 (round-4cb80ea57f26, launch launch-a8feeda2fbe4): sha 913fefc49727436033c75fa6d8c3fbb86586805930171a4f5c5736c93d6eda5f; waves now W0-W10 with todo 8 in W3; critics launched.
- Round 2 results: Momus OKAY (note: stale StopTimeout=90 in todo 17); Oracle OKAY with notes (ApplyError::Job is not busy; SIGTERM test log format); Metis NOT READY (only blocker: stale StopTimeout=90 in todo 17; notes: sink_http module visibility, ApplyError::Job label, todo 10 docs order, todo 14 test timing with a stalled fake). Every item applied in round 3 (rollback refusal via fail_parse_matching instead of a stall; JSON log assertion; ActionDeps::apply_clock seam).
- Round 3 (round-4cb80ea57f26, launch launch-1782b5f8c28a): sha 913fefc49727436033c75fa6d8c3fbb86586805930171a4f5c5736c93d6eda5f; critics launched.
- Round 3 results on df6cbef2: Metis READY (note: clock wording), Momus OKAY (notes: jiff needs network; todo 14 bullet over 2000 chars), Oracle OKAY (notes: clock wording; name the silent_noop_path + rollback-refusal combination). All notes applied per the owner rule (every note), so a confirmation round follows.
- Round 4 (round-4cb80ea57f26, launch launch-fe00c01ccc52): sha 913fefc49727436033c75fa6d8c3fbb86586805930171a4f5c5736c93d6eda5f; critics launched.
- Round 4 results on 9ab33226: Metis READY (no notes), Momus OKAY (informational: confirm no kcc-entware run is in progress before starting; the precondition already requires it), Oracle OKAY (optional note: the cache holds several jiff 0.x versions, not only 0.2.45). Wording applied per the owner rule.
- Round 5 (round-4cb80ea57f26, launch launch-6cd54f6fb827): sha 913fefc49727436033c75fa6d8c3fbb86586805930171a4f5c5736c93d6eda5f; one-phrase change in todo 2; critics launched.
- Round 5 results on 913fefc4: Metis READY, Momus OKAY, Oracle OKAY, no notes left. Plan final; round copies at ~/.cache/kcc-review/kcc-notify-schedule.r1..r5.md.
