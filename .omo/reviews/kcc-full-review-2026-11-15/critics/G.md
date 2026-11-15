## Lane G verdicts (kcc-migrate and kcc-telemetry)

### G-01 CONFIRMED
- checked: `crates/kcc-migrate/rules/rules.toml:142-168`, `src/rules.rs:240-302,380-460,494-560,632-690`, `src/planner.rs:52-74,177-211`, `src/planner/buildability.rs:12-32`, `src/maps.rs:90-114`, `src/presets/plan/classify.rs:28-47`, `tests/rules.rs:448-481`
- reasoning: The first matching rule wins (`classify_line` loop at 412-433). `copy-wireguard-private-key` and `copy-ns3-secret` come before `remap-mapped-reference`, and `explicit_item` only calls `apply_mappings` for `Disposition::Remap` (522-536). Nothing later re-applies mappings: `retain_supported_item` only checks catalog syntax, and `execution_phases` copies `item.output` as it is. The path needs no unusual operator action. `InterfaceMap::propose` sets `target: None` when the source name collides with a target default of a different type (103-109), so a mapping is required in that case. The secret or key line then goes to the source-named interface, and the mapped interface gets none. Verification passes because `expected_lines` holds that same unmapped output. The preset planner maps the interface word on these lines (classify.rs:30-46), so the two planners do diverge. No guard elsewhere prevents this.
- severity: high
- correction (minor): The Wi-Fi PSK sub-claim does not hold. AP lines use the single token `WifiMaster0/AccessPoint0`, and an exact-token radio mapping `WifiMaster0` would not rewrite it under either rule (see NEW-1).

### G-02 ADJUSTED
- checked: `src/presets/store.rs:114-131,194-262,337-342`, `tests/presets.rs:200-227`, `crates/kcc-mcp/src/preset_tools/capture.rs:84-99,132-195`, `crates/kcc-web/src/presets_page/compose.rs:107-163`, `crates/kcc/src/cli/preset/manage.rs:198-215`
- reasoning: `capture` checks only the new source's scope, then `save` renames over any existing `<id>.json` with no existence check and no check of the old record's `source_router`. `delete` does check that scope, and `source_scope_hides_and_refuses_saved_presets` shows the store is meant to refuse out-of-scope deletes. Overwriting is therefore an out-of-scope delete-and-replace. The finding overstates the reach. The Web path uses `fresh_id(now)` (random), so it cannot collide. The CLI uses the name as the id, but a CLI user already has the state directory. The real vector is MCP, where `slug(&input.name)` is deterministic. The attacker has to guess the victim id, because `list` hides out-of-scope presets. The replaced record then carries the attacker's `source_router`, so a prod-only admin no longer sees it rather than applying it unaware.
- severity: medium (scope control weakened for overwrite plus loss of a preset; needs an authenticated `Migrate` key and a guessed id; no disclosure or router command)
- correction: Vector: an MCP identity with `Migrate` on any router can overwrite and destroy a preset of another scope by naming its capture so the slug matches. Fix as proposed: `create_new`, or `authorize_source` on the existing record.

### G-03 CONFIRMED
- checked: `src/apply/preflight.rs:104-175`, `src/apply/reconnect.rs:17-83`, `src/apply/execute.rs:100,112-139`, `src/planner.rs:177-211`, `src/planner/diff.rs:11-25`, `crates/kcc-app/src/workflow.rs:913-928`, `crates/kcc-rci/src/engine.rs:204-217`, `crates/kcc/src/cli/migrate_plan.rs:170-191`, `crates/kcc-web/src/migrate_wizard/apply_request.rs:116-136`, `crates/kcc-testkit/src/server.rs:710-735`
- reasoning: Front ends set `management_password` whenever a password for the profile's login is supplied. `prepare` turns it into a single `Credentials(login, new)` for the whole run. The management phase runs in source order and is never re-sorted. After every management line, `complete_line` calls `changes.reconnect(url, applier.credential.clone())`. `retarget` then uses the new credential, and `read_last_change` authenticates with it. Nothing switches to the new credential only after the login's own password line has been applied.
  - Scenario A (verified from code): a cross-model migration (realm differs, so `user <login> password plain` is required and becomes management) that also changes the management bridge IP. The `interface Bridge0 ip address …` line runs first and reconnects to `reconnect_url` with a password the router does not have yet. That fails for 120 s, then `recover` returns `RolledBackByRouter`.
  - Scenario B: another user's `password plain` line comes before the login's line. The fake router clears every session on any password change, so a reconnect is forced, and it fails the same way.
  - Interface blocks preceding user blocks in real configs is INFERRED. Scenario B does not depend on order beyond "another user comes first".
- severity: high (the router timer prevents lockout, but the common case of replacing a router with another model while keeping the LAN subnet always fails)

### G-04 ADJUSTED
- checked: `src/presets/apply/convert.rs:23-95`, `src/presets/plan/classify.rs:48-60,118-150`, `src/presets/plan.rs:191-243`, `rules/groups.toml:101-106`, `src/apply/preflight.rs:132-175`, `src/planner/diff.rs:14`, `src/rules.rs:713-740`, `src/apply/reconnect.rs:24-35`, `crates/kcc-testkit/src/server.rs:710-735`, `crates/kcc-domain/tests/users.rs:78-79`
- reasoning: The mechanism is real. Preset items, including a rewritten `user <login> password plain X` or a same-realm `user <login> password md5 H`, all go to `additive` (or to `prune` in Mirror mode), and `reconnect_url` is `None`. `validate_credentials` only scans `phases.management`, which is empty here. `is_management_line` matches only `password plain`. So the README promise ("refuses to change the password of the router account it logs in with") does not hold for presets, or for migrations that overwrite a same-realm hash.
- The impact as written is wrong. The repo models firmware ending every session on a password change (fake router `sessions.clear()`, and the comment in `kcc-domain/tests/users.rs:78`). The next read-back or keep-alive then re-authenticates with the old stored credential and fails. A non-management line takes `complete_line`'s `ReadBack => finish::recover` path, and the router timer restores the old password. The run therefore cannot reach "verified" and cannot be committed. A lockout happens only if the firmware keeps sessions, which the repo itself says real routers do not.
- severity: medium
- correction: The demonstrated consequence is that a `router-users` preset (or a migration that overwrites a same-realm hash) touching kcc's own login always fails and is rolled back by the timer. There is no password check and no clear refusal. Lockout after save is only possible if the firmware keeps sessions (unverified). The fix stands: classify the login's password lines (`plain|md5|nt`, including `no` forms) as management in `convert::migration_plan` and in the planner, or refuse them.

### G-05 ADJUSTED
- checked: `src/apply/finish.rs:28-128`, `src/apply/failure.rs:95-135`, `crates/kcc-web/src/wizard/finish.rs:223-242`, `crates/kcc/src/cli/migrate_apply/migrate_apply_finish.rs:17-52`, `crates/kcc-i18n/locales/en/{migrate.ftl:18,cli.ftl:68}`
- reasoning: `ensure_unchanged` maps to `Drift` in both `commit` and `keep_unsaved`, and `keep_unsaved`/`rollback` use `context(applier).await?`, which gives `Unreachable` or `Validation`. All of these have `fate() == None` while the timer is still armed, so the Web and CLI audit `fail_safe_armed: false`. The CLI one-shot `commit` that fails with `Drift` prints "plan again" and exits, while the router later rolls the run back. In the Web path the applier stays in its slot, so the operator can retry, which softens the impact. In `rollback`, a wrong "not armed" report is harmless because the timer does what the user asked.
- severity: medium
- correction: `Drift` comes from `commit` and `keep_unsaved`, not from `rollback`. The harmful cases are commit and keep; rollback's misreport is cosmetic.

### G-06 CONFIRMED
- checked: `src/apply/verify.rs:80,142-178`, `src/inventory.rs:245-248`, `docs/MIGRATION.md` (no mention of this health requirement)
- reasoning: `health` hard-requires `internet == true` and `/Bridge0/link == "up"`, and there is no option to skip it. A bench target with no uplink can never set `verified`, so commit and keep are refused (`Verification`). The management interface is the first `Bridge` in the inventory list. This is not documented as a requirement anywhere.
- severity: medium

### G-07 REFUTED
- checked: `src/planner.rs:106-120`, `src/planner/types.rs:28-42`, a repo-wide grep for `prune_lines`, `src/presets/apply/convert.rs:61-62`, `src/presets/plan.rs:203-243`, `rules/groups.toml:41-113`
- reasoning: The operator-prune path is unreachable. `Choices.prune_lines` is written nowhere outside the planner. `Choices` is not `Deserialize`, and no Web, CLI or MCP code sets the field, so "the operator (or the Web residual list) prunes the old Bridge0 IP" cannot happen. The only reachable prunes are preset Mirror removals, and no settings group includes `interface * ip address`, `ip http port|ssl` or the management security level. The one dangerous Mirror prune, `user **` lines, is already covered by G-04. The plumbing is latent public API with no live consequence.

### G-08 CONFIRMED
- checked: `crates/kcc-telemetry/src/logs/sink.rs:120-124,290-307`, `logs/elastic_sink.rs:119-123,177-189`, `logs/pipeline_delivery.rs:197-257`, `docs/MONITORING.md:104-114`
- reasoning: `Transport` and `BulkError::Delivery(_)` are not retriable, so the batch goes to `dropped(...,"permanent")`. This contradicts the doc claim "Delivery is at-least-once while kcc runs" (MONITORING.md:112). Up to 1,000 records are lost per connection reset or sink restart.
- severity: medium

### G-09 CONFIRMED
- checked: `logs/sink.rs:76`, `logs/elastic_sink.rs:76`, `logs/pipeline_delivery.rs:135-153,197-257`, `logs/retry.rs:29-35`, `logs/pipeline.rs:85-103`, `logs/queue.rs` (no count on drop), `docs/MONITORING.md:112-114`
- reasoning: Neither client sets a timeout. The retry loops have no attempt cap and never check cancellation. On shutdown, `abort()` drops the in-flight batch and the queue without any `log_records_dropped`. The docs claim that "records still queued at exit … are counted in `kcc_log_records_dropped_total`", which the code does not do.
- severity: medium

### G-10 CONFIRMED
- checked: `logs/service.rs:191-203,241-257,279-297`, `logs/parser.rs:33-51,95-146`, `logs/dedupe.rs:39-60`
- reasoning: `collect::<Result<…>>()?` fails the whole response on one bad id, message or prefix, and `emit` returns silently with no log line and no metric. In poll mode every snapshot returns the same 200-line window, so forwarding stops until the bad record ages out. In stream mode, if each chunk carries only new lines (INFERRED), the loss is per chunk rather than perpetual, but it is still silent.
- severity: medium

### G-11 CONFIRMED
- checked: `logs/service.rs:280-285`, `logs/parser.rs:100-167`, `logs/types.rs:13`, `tests/logs.rs:58-88`
- reasoning: Production always passes a `+00:00` "now", so bracket times (router-local wall clock) are stamped as UTC. For a router at UTC+3, records are 3 h in the future. Loki's future-timestamp rejection (INFERRED) would then answer 400, and per G-08 that is a permanent drop. The test uses a +03:00 "now" that production never supplies.
- severity: medium

### G-12 ADJUSTED
- checked: `logs/service.rs:191-257`, `logs/runtime.rs:113-125`, `crates/kcc/src/server.rs:203-217`, `crates/kcc-app/src/settings.rs:452-473`, `docs/BACKLOG.md:31`
- reasoning: The sleeps at service.rs:201, 226, 236 and 255 are outside `select!`, and collectors are shut down one after another after "jobs drained". The default stream mode (5 s interval) explains the BACKLOG "exit about 4.4 s after jobs drained" symptom. So this is the root cause of a known BACKLOG gap, not a new defect. The finding does add the multiplication by router count (poll mode 30 s × N, which can exceed the shipped 80 s StopTimeout and get the process SIGKILLed, losing only queued log records).
- severity: low
- correction: Treat as the root cause of BACKLOG "Known gaps" `server.rs:203-206`, plus the per-router multiplication.

### G-13 CONFIRMED
- checked: `logs/pipeline_delivery.rs:82-90,156-186`, `RUST_GUIDELINES.md` §5 (std `Mutex` "only when the critical section is strictly synchronous and short"; yield in CPU-bound loops)
- reasoning: `encoded_len(&batch)` re-encodes the growing batch on every pop, under the queue's std mutex. That is about 500k record encodings per 1,000-record batch, and every relay `push` blocks on the same lock meanwhile.
- severity: medium

### G-14 ADJUSTED
- checked: `crates/kcc-migrate/src/source.rs:16-30,129-160,202`, `src/inventory.rs:57-65`, a repo-wide grep (only tests call `InventoryClient::connect`; no callers of `from_live`, `load_source` or `MigrationSource`), `crates/kcc-rci/src/outbound.rs:97-110`
- reasoning: The code is as described: the default policy allows RFC 1918, CGNAT and fd00::/8 plus loopback, and ignores `[outbound]`. But no production path reaches it today, so the consequence is hypothetical.
- severity: low
- correction: This is dead public API that would bypass the outbound policy if wired up, not a reachable bypass. The fix stands.

### G-15 CONFIRMED
- checked: `src/planner/types.rs:143-154`, `src/report.rs:100-178`, `src/apply/verify.rs:83-86`, `src/presets/apply/convert.rs:88-90`, `crates/kcc-mcp/src/preset_tools/apply.rs:69-71`, Web, CLI and MCP `from_plan` callers, `docs/MIGRATION.md:119`, project rule (f)
- reasoning: Every item renders as `<redacted> → <redacted>`, so `report_safe_line` is dead. Preset reports have no items, and the headings and `lang="en"` are hardcoded. The docs promise "lines in replay order, with redacted reports".
- severity: low

### G-16 CONFIRMED
- checked: `metrics/collector.rs:98-117`, `metrics/catalogue.rs:354-359`, `docs/METRICS.md:63`
- reasoning: The counter adds the current overflow on every scrape, so its rate tracks scrape frequency, and entries are never removed. The "summed over scrapes" semantics are documented, but the counter is still misleading.
- severity: low

### G-17 ADJUSTED
- checked: `metrics/clients.rs:125-187`, `metrics/collector.rs:44-45,80-86`, `metrics/service.rs:63`, project overlay rule (i)
- reasoning: The map only grows and is shared across routers, so its memory is unbounded under randomized MACs. Rule (i) ("no **stored** client telemetry history") is misapplied: this is an in-memory MAC-to-pseudonym set with no telemetry values. Rebuilding it on every scrape, as proposed, would also break pseudonym stability.
- severity: low
- correction: This is an unbounded-memory and identifier-retention issue, not a rule (i) violation. Prefer a keyed hash (HMAC with a per-process key).

### G-18 CONFIRMED
- checked: `metrics/interfaces.rs:28-43`
- reasoning: The free-text `description` is a label on `keenetic_interface_up`, which causes series churn and puts arbitrary text into labels.
- severity: low

### G-19 CONFIRMED
- checked: `metrics/instrumentation.rs:189-240`
- reasoning: `Lagged` is skipped without resyncing. A missed terminal event leaves the `running` gauge incremented and the `known` entry leaked.
- severity: low

### G-20 ADJUSTED
- checked: `src/apply/finish.rs:134-168`, `src/apply/verify.rs:91-95`, `src/apply/preflight.rs:128-132`, `logs/service.rs:240-264`, `logs/pipeline_delivery.rs:134-225`, `metrics/service.rs:145-146`, `docs/BACKLOG.md:77`
- reasoning: The `recover` annotation is wrong: it calls `wait_restored`, which is marked NOT cancel-safe, and it mutates `report.finished`. The missing annotations are all on non-`pub` functions. That is exactly the BACKLOG cleanup item, whose fix ("extend the check to `pub(crate)` and private functions") would catch them, even though these specific locations are not listed there.
- severity: low
- correction: The new part is the wrong `recover` comment. The missing annotations are instances of BACKLOG:77.

### G-21 CONFIRMED
- checked: `src/rules.rs:693-711` vs `presets/plan/classify.rs:145-150`, `presets/selection.rs:128-138` vs `classify.rs:165-174`, `verify.rs:190-196`, `diff.rs:76-82`, `source.rs:257-260`, `finish.rs:150-168`, `raw.rs:137-161`, `reconnect.rs:50-78`, `components.rs:83-106`, the three `lock()` helpers
- reasoning: All the cited duplicates exist, and the reconnect loops have different bounds. This is not the BACKLOG "two glob matchers" decision.
- severity: low

### G-22 CONFIRMED
- checked: `presets/store.rs:139-199,225-230`, MCP `capture.rs:190-193`, Web `compose.rs:148`
- reasoning: `load_for_apply` and `get_for_apply` have identical bodies. Synchronous `std::fs` and decryption run in async handlers. One malformed in-scope record makes `list` fail with `?`.
- severity: low

### G-23 CONFIRMED
- checked: a repo-wide grep (`ContinueOnNonCritical` appears only in `types.rs` and test support), `execute.rs:69-82,146-173`
- reasoning: No front end can select the option. On retry, `Indeterminate` falls through to `Stopped`, while the main loop calls `recover`.
- severity: low

### G-24 ADJUSTED
- checked: `logs/parser.rs:72-76,213-215`, `logs/format.rs:61-63`
- reasoning: The stream label is lowercased firmware-supplied `level`. Only the router firmware sets that field. "A LAN device writing arbitrary `level` values" has no shown path, so the router is the only source. Stream cardinality stays bounded by what the firmware emits.
- severity: info

### G-25 CONFIRMED
- checked: `tests/logs.rs:58-88`, `crates/kcc-migrate/tests/finish_recovery.rs:48,60,72,81,108,119,151,160,185`, `tests/support/matrix_run.rs:116-123`, `tests/rules.rs:448-455`
- reasoning: All cited test gaps and noise exist. The `user ` filter in the matrix also hides G-04-style password lines from verification.
- severity: low

## Summary

| Verdict | Count | Findings |
|---|---|---|
| CONFIRMED | 16 | G-01, 03, 06, 08, 09, 10, 11, 13, 15, 16, 18, 19, 21, 22, 23, 25 |
| ADJUSTED | 8 | G-02 (to medium, MCP-only vector), G-04 (to medium, fails and rolls back rather than locking out), G-05, G-12 (to low, root cause of a BACKLOG item), G-14 (to low), G-17, G-20, G-24 (to info) |
| REFUTED | 1 | G-07 (`prune_lines` is never set by any front end) |

Final severities: high for G-01 and G-03; medium for G-02, 04, 05, 06, 08, 09, 10, 11, 13; low for the rest, except G-24 (info).

**NEW-1 (needs validation):** radio mappings probably never rewrite Wi-Fi access-point lines in either planner. `apply_mappings` (`rules.rs:682-690`) and `classify.rs:30-46` replace exact `Token::Word` matches only. `RadioMap` entries are radio ids such as `WifiMaster0` (`maps.rs:67-78`), but AP lines carry the single token `WifiMaster0/AccessPoint0` (`tests/presets.rs:100`, `interface_names.rs:64`). A `WifiMaster0 → WifiMaster1` mapping would leave SSID and PSK lines on the source radio's access point. I have not checked whether the tokenizer splits on `/`, or whether the interface map also lists AP names.

**Docs contradiction (supports G-08 and G-09, not a separate finding):** `docs/MONITORING.md:112-114` claims at-least-once delivery and counting of records lost at exit. The code does neither.