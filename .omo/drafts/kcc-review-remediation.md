---
slug: kcc-review-remediation
status: complete
intent: clear
review_required: true
plan_path: .omo/plans/kcc-review-remediation.md
plan_sha256: c01875cb76666135f2220ec1d82ce2cdc3728db3430c3f6c1875961456280f48
review_round_id: round-b0622f7fddce
round_status: approved
pending-action: none - hand off to $ulw-execute kcc-review-remediation
review:
  momus:
    status: approved
    workspace_root: /home/andrico/keenetic-control-center
    runtime_home: null
    target: .omo/plans/kcc-review-remediation.md
    round_id: round-b0622f7fddce
    plan_sha256: c01875cb76666135f2220ec1d82ce2cdc3728db3430c3f6c1875961456280f48
    launch_id: launch-a39f77562beb
    session: ses_e2b724274ffec6o6Tfva6zFwAf (bg_13a91b9e)
    result: OKAY (notes: RetryPolicy::testing is cfg(test) - todo 16 integration tests need it exposed differently; todo 5 helper is valid_router_id today)
  independent:
    status: approved
    workspace_root: /home/andrico/keenetic-control-center
    runtime_home: null
    target: .omo/plans/kcc-review-remediation.md
    round_id: round-b0622f7fddce
    plan_sha256: c01875cb76666135f2220ec1d82ce2cdc3728db3430c3f6c1875961456280f48
    launch_id: launch-655c06bd6eb8
    session: ses_e2b7219a1ffeF9MosdYmz3bl4x (bg_4e3bd9a9)
    result: OKAY (R5-B1 closed; note: transition already seals managed paths at :318-320, change is the external-file branch :321-322)
final_validation: sha256 c01875cb76666135f2220ec1d82ce2cdc3728db3430c3f6c1875961456280f48 re-checked before handoff (matches round-b0622f7fddce, both lanes OKAY)
round5: sha f51beb2a; momus OKAY (ses_e2b73ffadffefvIgzsKqn8WzYs); independent REJECT (ses_e2b73d7adffeWS9783JYvxjImc) R5-B1 todo 52(b) bootstrap_workflow.rs:49 both 'no change' and 'assert sealed' -> FIXED: removed from no-store list, update sentence attaches CredentialStore at :49; nits registry.rs:326, token profile without store
previous_approval_round4: sha256 a6259e21bc40473557fb096eaa1f9ac85a4d4bc9a9563a414824efbeaac22492 re-checked before handoff (matches round-c09bd06c09a7, both lanes OKAY)
notes_folded_round5: registry without CredentialStore keeps today's file write (test-only); token-profile reconnect saves URL and drops cached password client; acceptance (7) builds external-file profile via RouterRegistry::create + new (8); grep -F for (300..=3600); BACKLOG line for documentation-based 4.3/5.0 fail-safe.active
amendment_rounds:
  - round: round-130be9295c22 (sha 6bd35bc9)
    momus: OKAY (ses_e2b823af1ffedME89gdfqM34G1)
    independent: REJECT (ses_e2b820685ffe8yL883j0Xzr8h2)
    ledger_blockers (frozen for D-Q7 amendment):
      C1 RouterRegistry::transition writes replacement password plaintext into external file (registry.rs:301-325) + undefined token behavior -> FIXED todo 52(b) + todo 19 sentence + acceptance (7)
      C2 WireGuard .conf reader (cli/dom_vpn.rs:112-124) outside todo 54 -> FIXED added to todo 54 + test
    notes applied: doc-test sandbox 0600 + umask out of tagged blocks; 0600 fixture helper + fixture list; 54 now after 8/13/16/18/27; unified endpoint rule (URL/login/TLS); --auth switching; remove_kind; token-only placeholder creds; data-show CSS path; D-Q7 in convergence rule, CHANGELOG, README Safety model, TL;DR
previous_approval: round-64d200404e7e both OKAY on sha256 31ef47c02d88bd67fecc9e79aa1b470c45eff8d80425f6a044fb123703fb1736 re-checked before handoff (matches round-64d200404e7e)
review_history:
  - round: round-700a91b6f487
    plan_sha256: abdb9546748b73fdad1f44c0511e6fcf0d3e0f1dd3664b5eb8ad37978fb7b1c7
    momus: OKAY (ses_e2bb8a345ffeoJCHiyimtQ0JkX; notes - todo 21/45 matrix, todo 28 phrasing)
    independent: REJECT (ses_e2bb1b7acffe3RRHOkxoyoYIwd on claude-opus-5 after opus-5.5 overload)
    ledger_blockers (frozen):
      B1 D-Q2 None->refuse unreachable: read_last_change maps missing fail-safe to {} (workflow.rs:1336) -> FIXED predicate = boolean `active` member
      B2 todo 3/F1 rollback-literal grep unsatisfiable (catalog data, verification.rs, web safety.rs) -> FIXED scope to crates/kcc/src + crates/kcc-migrate/src
      B3 todo 1 grep unsatisfiable (clap help texts) -> FIXED grep '(300..=3600)' + named exceptions
    notes applied: GAP-15/IS-15 for todos 27-29; 28 BACKLOG bullets; 7 before 1; context.rs:217 in todo 12; client_view/dhcp readers; WEB_EXPLORER_ARMED pinning tests; todo 16 deferral mechanism; todo 18(b) recover sends nothing; Web standalone rollback BACKLOG line; From<WorkflowError> for McpFailure; cargo-mutants fallback; jobs.rs:539
approach: one remediation plan from the 2026-11-13 read-only review - correctness fixes first, then one shared safety bracket seam in kcc-domain used by Web/CLI/MCP/migrate, then app/config wiring, then kcc-web consolidation, dead/test-only code and test cleanup, repo hygiene; G0 green per todo, G1 at the end
---

# Draft: kcc-review-remediation

## Affected user and ideal state
Users: U1 router owner/admin (Web UI main, also CLI/MCP); U2 AI agent via MCP; U3 operator deploying kcc (Podman Quadlet, serve); U4 CLI scripter; U5 maintainers/agents (strict rust-guidelines); U6 household members (lose internet on unexpected reboot/rollback).
- IS-1 one recovery-mechanism rule (timer vs scheduled reboot), one timer constant and range, same on Web/CLI/MCP/migrate/interface guard | same change must not behave differently per surface (U1,U2,U6)
- IS-2 one shared bracket (arm->work->disarm->finish) used by every surface; an armed timer is never left unreported (incl. migration preflight/components failures) | lockout safety (U1,U6)
- IS-3 same failure => same meaning on every surface (armed fate, not-sent, ApplyError messages, MCP codes) and one audit format | truthful outcome (U1,U2)
- IS-4 closing a run (keep/save/rollback) identical in engine and CLI for both modes | no wrong rollback command in reboot mode (U4,U6)
- IS-5 no bracket is cut by shutdown on any surface; serve/stdio wait for every held bracket (Web+MCP); StopTimeout covers the budget; held bracket answers within a bounded time under a held audit lock | (U3,U1)
- IS-6 every documented config key works (login_max_failures, router auth/token_file per decision), router names valid in config are valid in registry | (U3)
- IS-7 startup never fails because of a stale interrupted job; recovery notices visible; ChangeSet drop never panics/races | (U3)
- IS-8 permission model per owner decision; one rule for management/destructive permissions | (U1)
- IS-9 CLI migrate apply confirms like preset run; exit/headline say clearly when a rollback restored the router; no 'not saved yet' for actions that change no config | (U4)
- IS-10 kcc-web: one result view, one submit pipeline, one request-helper module, one form engine, one confirm module, one wizard engine (migrate+presets), one table renderer, no hand-written Localize boilerplate, firewall page reads via kcc-domain | (U5)
- IS-11 no dead/test-only code in prod crates, no unused i18n keys, one workflow request type, env overrides generated from one table | (U5)
- IS-12 tests: each safety rule tested once at the core + thin per-surface wiring tests; no source-grep tests replaceable by lints; no fabricated postconditions; no mock-echo; no timing-luck; shared fixtures | (U5)
- IS-13 repo hygiene (per decision) + plain-language BACKLOG of remaining follow-ups; one dependency version per crate via [workspace.dependencies] | (U5)
- IS-14 G0 green after every todo, G1 green at the end; no user-visible regression beyond intended fixes | (all)
GAPs: each IS-n differs today per Findings B1-B13, D1-D3, kcc-web F2-F14 (verified bg_ca87ae86), BACKLOG.md items.

## Components (topology ledger)
C1 safety seam + surface migration (kcc-domain configuration, kcc-web/cli/mcp/migrate) | active
C2 app/config correctness (kcc-app settings/registry/jobs/workflow/accounts, kcc-rci wiring) | active
C3 worker open items + BACKLOG.md items (CLI migrate confirm, not-saved label, permissions, audit-lock bounds, StopTimeout, MCP codes) | active
C4 kcc-web consolidation | active
C5 dead/test-only code, i18n keys, test cleanup, deps, repo hygiene, docs | active

## Open assumptions (announced defaults)
- page_kit/reveal.rs: delete (todo 37 of the old plan made the Wi-Fi PSK write-only; no caller) | reversible
- session keepalive (kcc-rci start_keepalive) + configure_argon2_concurrency: delete (never wired, not documented; reactive re-auth + pollers keep sessions) | reversible
- kcc migrate apply: call existing cli::secret::confirm(Risk::Management) like preset run (--yes or terminal yes) | settled by in-repo pattern
- exit after an automatic rollback that restored the router: keep exit 6 (Router), headline MIGRATE_APPLY_RESTORED, document in docs/MIGRATION.md | reversible
- MCP transport 403s: stay out of audit.jsonl, logged via tracing warn with request id | reversible
- no new direct dependencies (strsim/ipnet replacements skipped unless already direct deps of that crate) | reversible
- interface guard: becomes a non-bracketing planner; surfaces bracket via ChangeOp.risk (removes web nested-timer workaround) | internal
- MCP: rmcp 3.9 spawns handlers (service.rs:1609-1631) and only cancels a token on disconnect/cancel (1660-1665); no request timeout in rmcp-server-kit; real gap is shutdown not counting MCP brackets -> process-wide bracket counter in kcc-app Workflow

## Findings (cited - path:lines)
Source: my review this session (verified by me unless marked R=reviewer claim). Gates at 5d7ccae: clippy exit 0, cargo test --workspace --all-features exit 0 (1294 passed, 0 failed, 7 ignored) log /tmp/opencode/review-tests.log.
- B1 SafetyMode for None: web page_kit/facts.rs:85-88 -> Router (cached 600 s facts.rs:16); cli/change.rs:261-266, mcp support/raw_change.rs:82-85, migrate apply/preflight.rs:91-98 -> ScheduledReboot (preflight: unknown future variant -> Validation); components.rs:109-113 uses inventory.fail_safe_available probe; interfaces/guard.rs:99 always Router. Timer: literal 300 raw_change.rs:87 + guard.rs:99, CLI context.rs:516 MANAGEMENT_TIMER, web FAIL_SAFE_SECONDS (confirm.rs:25-28), ranges 300..=3600 cli/persist.rs:98 + preflight.rs:34.
- B2 preflight.rs:101-107 arms then initialize()/components::install() may return Err without disarm; components.rs:115-120 arms then returns ReplanRequired; ApplyError::recovery_armed types.rs:345-349 = FinishFailed|DisarmFailed|SavedDisarmFailed only.
- B3 CLI rollback: cli/persist.rs:123-129 and cli/preset/finish.rs:110-118 call SafetyNet::rollback (configuration.rs:232-244, always 'system configuration fail-safe rollback') in every mode; engine apply/finish.rs:132-146 uses 'system reboot' for ScheduledReboot.
- B4 web.login_max_failures settings.rs:182,199,888,1236 shown admin.rs:297; lockout uses accounts.rs:34 LOCKOUT_FAILURES=5 at :414.
- B5 router name: settings.rs:1103 is_valid_name [A-Za-z0-9._-]{1,64} no leading '.', used settings.rs:514,993, persist.rs:650; registry.rs:936 valid_router_id [a-z0-9-]{1,32} enforced registry.rs:95.
- B6 jobs.rs:323 open_with_ids calls recover(); recover (523-569) does registry.client(&router).await? at :538 -> error aborts startup; notices pushed to self.recovery, reader recovery_notices (:336) has no caller.
- B7 workflow.rs:743-752 Drop spawns tokio task to remove lease_actors entry (panic outside runtime, race with next begin).
- B8 settings.rs:1002-1022 validates auth/token_file; registry.rs:750-754 rejects token profiles; ManagedRouterProfile (registry.rs:50-70) has no auth field -> ndw2/ndw4/digest selections silently ignored. Original accepted plan IS-1 + row 9 REQUIRE ndw2/ndw4/token/digest (KeenDNS port 79); row 8 required keepalive GET /auth every 120 s while job/SSE needs session; row 9 required configurable max_argon2_memory_kib and Argon2 semaphore. kcc.example.toml:161-162, docs/CONFIG.md:211-216 advertise auth/token_file.
- B9 MCP migration_tools/apply.rs:51-53 RollbackRestarting -> RouterUnreachable; finish.rs:89-91 any recovery_armed -> ManagementOutcomeUnknownFailSafeArmed (loses SavedDisarmFailed).
- B10 deploy/podman/kcc.container StopTimeout=40 vs budget shutdown_timeout 30 + BRACKET_GRACE 10 + job drain 30.
- B11 web audit: page_kit/audit.rs:52-57 outcome 'fail_safe_armed' (+param) from change.rs:278; wizards (presets_page/finish.rs:136-142, migrate_wizard/finish.rs) write 'failed' + fail_safe_armed param; CLI/MCP write failed+flag.
- B12 presets_page/events.rs:109 ReplanRequired -> WEB_MIGRATE_FAILURE_DRIFT vs migrate_wizard/run.rs:155 -> REPLAN; both match on serialized names.
- B13 kcc/tests/docs/firmware.rs:33-36 accepts docs/FIRMWARE.md:10 'live verification not yet run'.
- D1 crates/kcc/src/cli/coverage.rs (232) + exclusions.rs (28) read only by kcc/tests/cli_domain_writes/coverage.rs.
- D2 39 i18n keys unreferenced (e.g. CLI_ABOUT, CLI_DRY_RUN, ERRORS_CSRF, WEB_NAV_ROUTERS/INTERFACES/AUDIT/SETTINGS) - confirmed: no constant use and no raw-id string use in .rs/.html/.js/.toml; no dynamic key mechanism (only test MessageKey::new in kcc-i18n/src/bundle.rs). Listed in todo 44.
- D3 workflow.rs ChangeRequest/DeleteRequest/BatchChangeRequest/CliChangeRequest(+Terminal) parallel types; apply/apply_delete ~857-956 near-identical (R).
- R (reviewer, verify via explore bg_ca87ae86): kcc-web F2-F14 duplication list; settings env block 1167-1506 + KCC_ENV_VARS 37-77; persist.rs migration machinery unused; send_loki test-only; reveal.rs dead; strsim osa_distance; outbound AllowedNetwork vs ipnet.
- Rejected reviewer claims: spikes target tracked (false); xtask catalog unused (false, catalog/README.md:15-31); CLI commit-without-save (ChangeSet::commit workflow.rs:1132 waits unsaved clear); presets DisarmFailed missing (fallback events.rs:105); tokio split cosmetic (single tokio in Cargo.lock).

## Decisions (with rationale)
Owner answers 2026-11-13:
- D-Q1 Operator: arming/keep-alive/disarm INSIDE a kcc bracket run under the protected change's own permission (Write for curated/raw management changes, Migrate for migration/preset/copy runs). Destructive remains for: explicit user-chosen rollback finish, explicit standalone timer control (`kcc config failsafe arm|rollback`, cli/persist.rs:84-97), reboot-class steps (component install components.rs:65,76; same-hardware restore raw.rs:94; finish reboot finish.rs:150), and any op classified Risk::Destructive. Apply set becomes Read+Migrate+Write+Save, plus Destructive only when the request installs components, uses raw restore, or asks for finish=rollback up front.
- D-Q2 (REVISED 2026-11-13 after Metis: show system mode exists only in catalog/5.1/show.json:8522): Some(Router) -> fail-safe timer; Some(Extender|Ap|Repeater) -> scheduled reboot; Some(Other(_))/future -> refuse; None -> fail-safe timer if the change set's baseline `show last-change` has a `fail-safe` object, else refuse. Mode source = ChangeSet (fresh detect in ChangeWorkflow::begin workflow.rs:642-648 + baseline last-change), never the Web 600 s facts cache.
- D-Q6 Audit under held lock: writer keeps a lock-timed-out entry at the head of its queue and retries (FIFO, chain intact); callers wait bounded; reply says 'entry pending'; loss only on writer death/process exit, logged with count.
- D-Q3 Wire router auth/token_file for config-file routers (registry -> RciClientOptions auth Options); Web/CLI-added routers keep password+Auto.
- D-Q4 .omo: track everything (no hygiene change).
- D-Q5 Tests: TDD (failing test first) for every bug fix; refactors keep suite green, new tests only for new shared seams; pure moves no new tests.
- D-Q7 (2026-11-13, after the credential-storage question): Web-first sealed credentials - Web router page + CLI router add/edit set password, login mode/token and read-only polling login, all sealed under the master key (kinds Password <id>.sealed AAD id, Token <id>.token.sealed AAD <id>:token, ReadPassword <id>.read.sealed AAD <id>:read); CLI --password-file/--token-file/--read-password-file are input only; kcc.toml routers stay file-based; every secret file kcc reads (router creds, CLI input, log-sink creds, TLS key) is refused on Unix when mode & 0o077 != 0. Old state profiles pointing at external files keep working (subject to the rule) with a startup warning; kcc never deletes them. Todos 52, 53, 54; todo 19 persists auth/token_file with serde default + skip_serializing_if.
Metis (bg_7c52cca8) defaults adopted:
- D-Q1 needs a permission parameter on SafetyNet arm/disarm/keep_alive (ChangeSet::apply_cli re-checks it, workflow.rs:1059,1163); raw changes protect with RawRci; standalone timer control (cli/persist.rs:86-96, cli/dom_jobs.rs:62-63, web config_page/safety.rs:52) keeps literal Destructive; MCP raw allow_destructive server switch kept + documented; todo 9 owns the rule, 18 the apply sets/docs.
- todo 2 acceptance on fake router state (handle.recovery_armed() kcc-testkit/src/lib.rs:637; extend crates/kcc-migrate/tests/support/apply_lifecycle.rs:43-71); after components commit no disarm, read last-change, Unknown only if read fails/timer active.
- todo 6 keeps the router probe (with timeout), reports via tracing warn + audit entry job.recovered; deletes only the unread reader; never fails startup (also the ? at jobs.rs:525-537).
- todo 7 adds a guard for early returns in begin (workflow.rs:620-648).
- todo 4 passes max_failures like lockout_seconds into authenticate (accounts.rs:413-416), not AccountStore::new.
- todo 45 (source_guards -> disallowed-methods) DROPPED; slot reused for golden HTML capture before W4.
- IS-5 narrowed to serve/stdio; CLI has no SIGINT/SIGTERM handling -> BACKLOG.
- ApplyError names are on-disk contract: from_name -> Option, unknown -> generic key, old-record fixture test.
- todo 19: ManagedRouterProfile (deny_unknown_fields, registry.rs:47-69): password_file Option<PathBuf> serde-identical for Some; auth spec #[serde(skip)] config-only.
- Web ordinary writes also hold() from first router write (confirm F3-2/F3-3).
- ordering per Metis gap 13; todo 50 last and alone; keys.rs regenerated, never hand-merged.
Settled by evidence:
- components.rs:82-120 re-arms after the components reboot and returns ReplanRequired, leaving a timer armed with no owner -> remove that arm (router rebooted onto saved config; nothing pending); test asserts recovery_armed()==false after ReplanRequired.
- kcc-domain gains internal dep kcc-i18n (kcc-migrate/mcp/web/kcc already depend on it) for ArmedFate::message_key.
- Process-wide bracket counter lives on kcc-app ChangeWorkflow (constructed once per process: kcc/src/server.rs:374, cli/context.rs:308); kcc-web keeps Claim/own/budget/hold.
- rmcp 3.9 spawns each request (service.rs:1609-1631, spawn_service_task 1327-1333) and only cancels a token (1660-1665); stdio drains 5 s then cancels tokens; the kit has no per-request timeout -> MCP brackets are cut only by process exit -> counted+drained like Web.
- lease_actors (workflow.rs:524) is never held across .await (610-637,749) -> std::sync::Mutex OK.
- persist.rs:650 check_name keeps is_valid_name for file names; router names use registry rule.
- Keep (not bloat): persist.rs schema-migration machinery (tested, data/schema safety), kcc-domain DomainDescriptor inventory, Clock traits as test seams, audit chain/append_lock, Argon2/SSRF/secret code.

## Scope IN

## Scope OUT (Must NOT have)

## Open questions
None. All resolved by the owner on 2026-11-13 (see Decisions): Q1 -> D-Q1 arm under the change's own permission; Q2 -> D-Q2 revised (timer if fail-safe.active reported, else refuse); Q3 -> D-Q3 wire; Q4 -> D-Q4 track everything; Q5 -> D-Q5 TDD fixes + tests in todo; Q6 -> D-Q6 keep and retry audit entries; Q7 -> D-Q7 Web-first sealed credentials + 0600 secret files.
Execution-time choices left to the owner (not plan decisions): $ulw-execute delivery options and commit permission; optional live 5.1 run with KCC_LIVE_* after the plan.

## Approval gate
status: approved (owner answered Q1-Q7 2026-11-13); plan written; rounds 1-6 reviewed; final round 6 both OKAY
next: on answers -> scaffold plan, Metis, append todos, TL;DR, dual review (momus + oracle) until approval
<!-- When exploration is exhausted and unknowns are answered, set status: awaiting-approval. -->
<!-- That durable record is the loop guard: on a later turn read it and resume at the gate instead of re-running exploration. -->
