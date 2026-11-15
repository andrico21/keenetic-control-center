---
slug: kcc-review-fixes
status: plan-written
intent: clear
review_required: true
plan_path: .omo/plans/kcc-review-fixes.md
plan_sha256: 28e73b6deb100cda7d563e6e18fcb0e28b3ec9474acca7f75f58c7e0ae981f17
review_round_id: round-2fcef78a5da2
round_status: complete
pending-action: none - approved by Metis, Momus and the Oracle on 28e73b6d; worker runs `$ulw-execute kcc-review-fixes`
review:
  metis: {status: done, session: ses_e1fb19264ffeU5zjJk9RqHJmIH, result: READY (no P0/P1/P2)}
  momus: {status: done, round_id: round-2fcef78a5da2, plan_sha256: 28e73b6deb100cda7d563e6e18fcb0e28b3ec9474acca7f75f58c7e0ae981f17, session: ses_e1f8af9a5ffes6QJ4xwzNyJWPn, result: OKAY (note: trust quoted code over line numbers - already a plan rule)}
  independent: {status: done, round_id: round-2fcef78a5da2, plan_sha256: 28e73b6deb100cda7d563e6e18fcb0e28b3ec9474acca7f75f58c7e0ae981f17, launch_id: launch-dfbf440c1b8e, session: ses_e1f8adda2ffekANmVwC4T8X7qV, result: OKAY (no notes)}
round1: sha eab29816; momus OKAY (ses_e1fd74d02ffeokRgrM6Zo8zzk3); independent REJECT (ses_e1fd72119ffeR0KSogYyucPffe) ledger: R1 leads offering alternatives rejected by the binding table (todos 41/E-22, 25, 15, 65/B-24, 54/G-23, 26/D-14, 71/X-11, 49/D-05) -> FIXED; R2 todo 16 CAS on non-existent account version -> FIXED (snapshot token, no new field); R3 todos 70/72/73 placeholder commands -> FIXED (actionlint/seccomp gen diff/xtask tests/shellcheck); R4 todo 66 multi-commit vs D-DELIVERY -> FIXED (one commit). Notes applied: marker per surface, torn-line at spawn+append, live-e2e.sh, success-criteria lists, B-16 critic wins, deps 26<-14 and 71<-69, Actor::new const, key role compare, std RandomState, convergence (c).
round2: sha 172befc0; momus OKAY (ses_e1fccee6cffeak770NpJ2Fc3b0); independent REJECT (ses_e1fccbda2ffeIrXgwAsa17Jtdz): R1-R4 closed; B1 (regression of D-NODEPLOY edit) lazy-migration leftovers at IS-7 scope row, todo 21 commit line, F2 checklist, IS-7 proving scenario -> FIXED. Notes applied: todo 5 re-seal sentence removed, todo 73 X-10 --env-file + all three scripts, QA chains wrapped `set -o pipefail; { ...; } 2>&1 | tee`.
round3: sha 2fdd29db; momus OKAY (ses_e1fc98bf3ffecmFccZKd2PD6Xh); independent OKAY (ses_e1fc9657dffeWZY0sCMJqqjHM0); B1 closed. Non-blocking notes (not applied, to keep the approved sha): todo 21 could name a test that schema-1 records and old-AAD account hashes are refused (code already refuses: credentials.rs:190-192, accounts.rs:405); F2 'no legacy fallback' means AAD only, not the plaintext migrate_legacy path; old-AAD account open returns an error, not Invalid.
owner 2026-11-15 (after round 3): "all critics notes should be considered, only fully validated plan" + "latest possible versions of crates" -> D-LATEST. Applied: Oracle r3 notes (todo 21 refusal tests; F2 AAD-only wording, migrate_legacy stays; login error not Invalid documented in CHANGELOG + docs/SECURITY.md, also r1 note 6); Metis leftovers (A-19 Stage order in todo 40; G-14 single choice delete incl. InventoryClient::connect; leads with open alternatives resolved: 13/W1-14 critic correction, 35/A-07, 56 Rendered newtype, 72 profile-eq extension; table rows added); IS-1 proving scenario markers per surface; overlay deviation 4 (quote YAML Rust versions) in todo 70; NEW todo 75 D-LATEST (deps + gate tools latest past 3-day cooldown, overlay deviation 3; sha3 0.12, cargo-deny 0.20.2, cargo-audit 0.23.0 as of 2026-11-15; check_dep_reqs.py added to the review dir); Must NOT version rule rewritten; F1/F2/convergence/IS-13/TL;DR updated. Momus r1 record not reloadable (session id not found); Momus r2/r3 OKAY with no notes.
round4: sha a544e961; momus OKAY (ses_e1fb18f57ffet57rBdGf9SoBDo; note: failure boilerplate on 70/72/73/74); independent REJECT (ses_e1fb1512dffeuIWN2KUcMQYOWI): N1 'no Updating line' unreachable -> FIXED (package-line regex, QA asserts with !grep); notes applied (SEC2-06 row trimmed, CredentialStore::migrate name, vet procedure targeted add-exemption in 71+75, crates.io created_at + taplo-cli, 75 failure scenario, 'except 67-73 and 75'); metis NOT READY (ses_e1fb19264ffeU5zjJk9RqHJmIH): P0 rule vs todo 6 serde_json/todo 68 tracing-subscriber -> rule reworded + superset test in kcc-mcp tests; P0 todo 42 -> InvalidIndent; P0 todo 51 -> line number only + test; P1 vet --locked + xtask store/CI (71) + xtask deny; P1 tool pins via workflow_call, grep, out-of-scope list; P1 open choices 9/28/43/29 resolved; P1 xtask CI command forms; P1 per-todo failure scenarios 70-75; P1 43 after 41; P2 all applied (15 fingerprint, 5 failure behaviour, 75 semver/generators/e2e container/crates.io/deny comments, F4/IS-13, F2 pins, 33 numbers 10 runs/1 day/30 days, 39 iterations cap 16, 45 doc agreement, 36 skip+report, 58 '_'->error/unknown, 66 A-18 NOT cancel-safe logins, 23 fix model, 8 catalog source fix, 71 keep embark, check_dep_reqs --all-features).
round5: sha ba7b1cf0; momus OKAY (ses_e1fa1a7a1ffekoWJK1Tz5rvvUI); independent REJECT (ses_e1fa17030ffepSprBWLbu3tMmW): B1 e2e.sh needs --container + image build -> FIXED; B2 plain cargo machete fails (spikes/) -> FIXED (cargo machete crates xtask, CI form); notes applied (todo 28 one channel + permits for bounded callers, receipts unbounded, disarm exempt, login audit bounded; dry-run output to files then !grep; todo 68 tracing-subscriber features); metis NOT READY: P0 seccomp gen needs trace -> FIXED (README trace procedure in 70/75, gen --check); P0 e2e -> FIXED; P0 C-01 row vs todo 9 -> FIXED (row + identifier list per D-02); P1 add-exemption --criteria safe-to-deploy; P2 applied (cargo-zigbuild pin in step 7, todo 73 runs native e2e, todo 33 sweep extended + migration sweep, todo 71 cargo vet import isrg/zcash, todo 39 [outbound] argon2_max_iterations setting, todo 70 container e2e under new profile); G1 list gains xtask workspace commands and vet --locked.
round6: sha 9936971e; momus OKAY (ses_e1f9930fbffeIivbWbaQRtxmnb; notes: 75 listed before 74 by design; long leads); independent OKAY (ses_e1f98fb8effehk0T3Awizv6G4o) with notes -> applied (seccomp union of two traces via --traces; todo 28 every Receipts::record and log-only callers take no permit, distinct timeout error not Pending); metis NOT READY: P0 'only ADDED syscalls' impossible -> FIXED (commit regenerated profile from 2-trace union, name added+removed, container e2e proves); P1 70/73 e2e port collision -> 73 blocked by 70; P2 --check-missing mode for container.yml drift step; todo 39 tests kcc-app/kcc, commit fix(rci,app).
round7: sha d62ea8b6; momus OKAY (ses_e1f94b95dffewd87YZRzX5excQ); independent OKAY (ses_e1f9491d9ffeW8ODu0IxFV23vN) with 3 notes; metis READY with 4 P2 -> all applied (75 acceptance gen --check --traces union; --check exit status not chained; unmapped syscalls -> seccomp_groups.rs; todo 28 names page_kit/audit.rs:141-161 and server_shutdown.rs:186, permit only in bounded append never in submit, queue growth accepted cost in rustdoc; todo 39 Default impl 16 + transition_tests.rs:41; podman build counts toward 2-build cap).
round8: sha 8249df2d; momus OKAY (ses_e1f918f34ffeKJSXj6mbus52XT); independent OKAY (ses_e1f9165bdffemGxTG9eIGhhE2m) with 4 notes; metis READY with 3 P2 -> all applied (todo 28: separate bounded entry point submit_within, both login audits bounded incl. audit_login under LOGIN_AUDIT_WAIT, server_shutdown.rs:186 relabelled as a test; todo 39: manual Default impl, serde default fn must return 16, no struct-literal edit needed).
round9: sha 21f92fab; momus OKAY (ses_e1f8eb55fffe8tPz0WOLQXY1OY); independent OKAY (ses_e1f8e92deffeTHsYw9P1cLaCaZ) 2 notes; metis READY 1 P2 -> applied (todo 28: exactly the two auth.rs helpers use the bounded entry point, shared audit helper covers failed login/logout/password change, every other caller stays on submit/append capped by AUDIT_WAIT; todo 39: remove Default from derive).
round10: sha 0f1936e7; momus OKAY (ses_e1f8cbd23ffeu4PMn3xnUDoUHm); metis READY, no P0/P1/P2; independent OKAY (ses_e1f8c9da7ffe42ltZYzN8CYIyR) 1 note -> applied (todo 39: kcc.example.toml writes argon2_max_iterations = 16 because tests/example_config.rs:48 asserts example [outbound] == default).
round11: sha 28e73b6d; all three approve, no actionable notes. Open owner question (non-blocking, default applied): D-LATEST includes the pinned gate tools (cargo-deny 0.20.2, cargo-audit 0.23.0).
owner D-NODEPLOY (2026-11-15): no deployments -> todo 21 simplified (no legacy fallback/migration), D-DOWNGRADE removed, F-26 delete duplicates, compat guardrails relaxed except audit hash rule.
metis: ses_e1ff9509effeqYCZrErHU5FGtw - P0.1-P0.6, collision table, alternatives, guardrails applied; owner answered D-DOWNGRADE (accept, clear error) and D-VET (import public audits); E-03 default (lease timeout tied to timer, no cross-identity finish)
approach: one fix plan covering every validated finding of the 2026-11-15 full review (~/.cache/kcc-review/VALIDATED.md: 6 high, 59 medium, 188 low, 44 info); highs first with TDD, then central seams that remove the drifting copies (one masker, one CLI-word rule, risk-derived confirmation/bracket, one error mapping), then grouped area fixes, tests and build; every finding id assigned to exactly one todo or to an explicit accepted-with-reason row
---

# Draft: kcc-review-fixes

## Affected user and ideal state
<!-- Who this output touches (a customer, another programmer, a program or agent consuming it - often more than one) and how each uses it today and will use it after. -->
<!-- IS-n | property of the ideal state: nothing snags, feels odd, regresses, or degrades for them | reason -->
<!-- GAP-n | difference between IS-n and today | reason | closed by todo(s) -->

## Components (topology ledger)
<!-- Lock the SHAPE before depth. One row per top-level component that can succeed or fail independently. -->
<!-- id | outcome (one line) | status: active|deferred | evidence path -->

## Open assumptions (announced defaults)
<!-- Record any default you adopt instead of asking, so the user can veto it at the gate. -->
<!-- assumption | adopted default | rationale | reversible? -->

## Findings (cited - path:lines)
Source of truth: /home/andrico/.cache/kcc-review/ (VALIDATED.md table, REPORT.md, APPENDIX-LOW-INFO.md, findings/<lane>.md, critics/<lane>.md, critics/SECOND-*.md, db.json). Review HEAD 349b7fb, guidelines 49898c9. All findings passed a first critic; highs and critic-raised items passed a second critic; highs re-read by me. To be copied into .omo/reviews/kcc-full-review-2026-11-15/ so worktrees see them.

## Decisions (with rationale)
Owner answers 2026-11-15:
- D-H1 Secret-bearing reads for roles without RevealSecrets: redact (ns3 blobs, keys, passwords) on Web, MCP, RCI console and CLI alike via one shared masker; RevealSecrets gets the raw reply. Viewers keep explorer and kcc_rci_read.
- D-H7 CLI revoke/disable/reset: `kcc serve` watches api_keys.json and users.json (mtime poll every 2 s); on change reloads keys and ends Web sessions of disabled or password-reset accounts; SIGHUP does the same.
- D-INFO Fix literally all findings, including info; SEC2-18 needs a one-time migration that re-seals router passwords and account hashes with record-type associated-data prefixes.
- D-DELIVERY One commit per todo on master, no push; the plan and .omo/reviews/kcc-full-review-2026-11-15/ are committed first.
- D-LATEST (owner 2026-11-15): every crate and gate tool at the latest version past the 3-day cooldown (core Version Policy), majors included; todo 75, after all code todos; resolves overlay deviation 3.
- D-DOWNGRADE superseded by D-NODEPLOY (no deployments): no backward compatibility needed; SEC2-18 switches AAD directly, credential schema 2, no legacy fallback.
- D-VET Import public cargo-vet audit sets (network once); never certify unreviewed crates.
Defaults (no owner question; reversible, settled by validated findings/critics):
- B-02: conflict check compares checksum only (critic-endorsed); N1: remove the dead `last_read` parameter.
- H2: call the existing `validate_username` (accounts.rs:667) at the start of `authenticate`; bound Actor.id.
- W3-02: firewall pages follow D-Q1 (change's own permission), like every other page.
- X-01: workflows trigger on both `master` and `main`.
- Tests: TDD for every bug fix (failing test first), as in D-Q5 of the previous plan.
- Items a critic judged behaviour-preserving (A-19, B-22) are still changed (D-INFO) but must keep behaviour and error precedence identical, proven by a test.

## Scope IN

## Scope OUT (Must NOT have)

## Open questions
None (4 owner questions answered 2026-11-15).

## Approval gate
status: approved (owner answered 4 + 2 questions 2026-11-15); plan written; Metis applied; review round 1 launched
<!-- When exploration is exhausted and unknowns are answered, set status: awaiting-approval. -->
<!-- That durable record is the loop guard: on a later turn read it and resume at the gate instead of re-running exploration. -->
