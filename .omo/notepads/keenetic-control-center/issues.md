# Issues - keenetic-control-center

Problems and gotchas encountered during work on this plan.

_Auto-scaffolded by /ulw-execute. Append new entries below - never overwrite._

---

## [2026-11-05] Task: todo-16 catalog validation follow-up
- `kcc-catalog` still has no stable runtime command-query API usable by `kcc-testkit`; fake-router CLI parse currently uses the plan-permitted minimal allowlist for interface description/address plus simulator control commands. Replace it with profile-aware generated catalog lookup when that API lands.
- Full workspace G0 is currently blocked by concurrent unrelated work: nightly fmt reports `crates/kcc-catalog/src/generated.rs` and `crates/kcc-rci/src/auth.rs`, and workspace tests reject unused `kcc_catalog::generated::FILES` in the catalog lib-test harness. Testkit-scoped fmt/clippy/tests/rustdoc and workspace rustdoc/gates are clean.

## Todo 5 (CI) - blockers found while running scripts/ci-local.sh (2026-11-05)
- macOS and Windows legs of the `test` job are CI-only; not verifiable on this Linux host.
- `cargo clippy --manifest-path xtask/Cargo.toml --all-targets --all-features -- -D warnings` FAILS AT HEAD (verified in a clean `git archive HEAD` copy): `xtask/src/main.rs:7` `#![expect(clippy::multiple_crate_versions)]` is unfulfilled, most likely because root clippy.toml `allowed-duplicate-crates` (extended in todo 18 with getrandom etc.) is picked up from the parent dir and silences the lint. Needs an xtask/main.rs (or xtask clippy.toml) fix by an owner of xtask; todo 5 was told not to touch it.
- `taplo fmt --check` FAILS AT HEAD for Cargo.toml (root, byte-for-byte R-GUIDE template), clippy.toml, deny.toml, xtask/Cargo.toml, crates/kcc-{app,rci,testkit}/Cargo.toml, catalog/*.toml: no .taplo.toml existed and the files use 4-space indent + aligned comments. Added `.taplo.toml` (excludes target, spikes, supply-chain, catalog/.cache, stray literal `~/` dir created by cargo-audit's db-path); remaining failures need either a decision on taplo formatting options vs the vendored template or reformatting those files.
- `cargo machete crates xtask` fails in the working tree only because another agent has uncommitted kcc-rci/Cargo.toml dependency edits (todo 7); passes on `git archive HEAD`. The same in-progress kcc-rci edits (and xtask/src/catalog_build.rs) break workspace clippy/msrv in the working tree.
- A stray directory literally named `~` exists in the repo root (`~/.cargo/audit-advisory-db` from `.cargo/audit.toml` db-path with no tilde expansion); also deny.toml `db-path = "~/.cargo/advisory-db"`. Consider fixing.

## [2026-11-05] Todo 20 verification constraints

## [2026-11-06] Todo 26 unit 1 verification
- LSP diagnostics timed out for the changed kcc-domain files and directory. Compiler, focused tests, strict Clippy, and package build were clean and are the verification authority for this unit.

## [2026-11-06] Todo 26 unit 2 verification
- LSP diagnostics timed out for the kcc-domain directory. Nightly fmt, component/storage integration tests (4/4), strict all-target/all-feature kcc-domain Clippy, and all-feature package build passed.
- The first deterministic component test attempt timed out because it advanced `MockClock` after `committing`, before terminal dispatch necessarily armed the fake reboot window. Adding an exact `rebooting` structured event after dispatch made clock advancement event-driven and deterministic.

## [2026-11-06] Todo 26 final verification
- LSP diagnostics timed out for kcc-domain. Compiler and strict workspace Clippy were clean.
- Full G0 passed: nightly workspace format check; workspace all-target/all-feature Clippy with warnings denied; workspace all-feature tests; warnings-denied workspace rustdoc; `cargo xtask allow-gate`; `cargo xtask profile-eq`.
- LSP diagnostics timed out twice. The scoped compiler, focused no-deps Clippy, and integration tests are clean.
- Dependency-inclusive `cargo clippy -p kcc-app --all-targets --all-features -- -D warnings` reaches concurrent out-of-scope kcc-testkit additions and fails there (anonymize.rs/capture.rs strict-lint diagnostics). Full-workspace nightly fmt also reports those sibling files. Todo 20 did not modify kcc-testkit.

## [2026-11-05] Todo 33 follow-ups
- Todo 48 must use `kcc_web::csp::security_headers(tls)`; with the kit default the CSP would block every Web UI script/style and `Cache-Control: no-store` would defeat the hashed-asset cache. With it, `/mcp`, `/healthz`, `/readyz`, `/version` carry no Cache-Control (accepted: authenticated POST/SSE and small status documents without validators); revisit if the kit gains a per-route Cache-Control opt-out.
- Theme and language menus write their cookies client-side in `assets/js/app.js` (no state-changing endpoint before CSRF exists); without JavaScript they do nothing. Recorded as accepted debt in `crates/kcc-web/DESIGN.md` section 8; todo 34 may add a POST fallback behind CSRF.

## [2026-11-06] Todo 34 partial execution
- The single-task directive required stopping after the first logical unit. Session storage, CSRF, web routes/templates, authorization middleware, account UI, audit wiring, and `crates/kcc-web/tests/auth.rs` remain unimplemented; todo 34 is not complete.

## [2026-11-06] kcc-testkit prerequisite Unit 4 workspace compatibility
- `cargo test --workspace --all-features` passes every suite until `kcc-rci/tests/capabilities.rs::every_model_profile_reports_brand_hw_id_and_components`, which asserts the old fake shape `radios == ["WifiMaster0"]`; Unit 4 explicitly requires both `WifiMaster0` and `WifiMaster1`. The protected downstream test was not edited. Focused `kcc-app --test poller` (1/1) and `kcc-web --test dashboard` (7/7) pass with the expanded fake.

## [2026-11-06] kcc-testkit amendment final gate
- Final workspace tests, rustdoc, format, allow-gate, and profile-eq pass. Workspace Clippy is blocked only by the out-of-scope `crates/kcc-app/tests/audit.rs:168` use of `fs::create_dir`, rejected by `clippy::create_dir` with the suggested `create_dir_all`; the orchestrator explicitly authorized only one cross-crate edit in kcc-rci, so kcc-app was not modified. Strict all-target/all-feature Clippy for kcc-testkit itself passes.

## [2026-11-06] Todo 25 partial execution
- The single-task directive required stopping after the first logical unit. VPN client domains, WireGuard `.conf` parsing/import and secret gates, VPN server domains, `DomainId::{VpnClients,VpnServers}` wiring, `tests/vpn.rs`, final combined task-25 evidence, and full G0 remain unimplemented.

## [2026-11-06] Todo 25 after VPN client unit
- DNS and VPN client units are implemented. Remaining work is VPN servers, `DomainId::VpnServers` wiring, server tests, secret-bearing request emission after the prerequisite lands, final combined DNS/VPN evidence, and full G0. The earlier partial-execution entry is superseded by this progress update.

## [2026-11-06] Todo 25 completed non-secret scope
- DNS, VPN clients, WireGuard parsing/non-secret import, and VPN servers are implemented and all verification gates are green. Only the explicitly deferred secret-bearing request emission remains dependent on the separate secret-safe transport prerequisite; no plaintext secret was placed in a `ChangeOp`, `ValidatedRequest`, `CliCommand`, audit parameter, log, error, or default read by this task.

## [2026-11-06] Todo 24 routing blocker
- `kcc-catalog` generated route metadata cannot validate a real IPv4 next hop. The 5.1 `ip route` command declares `network: IpAddress` and `mask: IpMask`, but declares `gateway: Keyword(values=["becomes"])` and `interface: Keyword(values=["is"])`. A focused runtime probe using `Catalog::for_firmware_and_model(FirmwareVersion::from_title("5.1.1"), Some("KN-1811"))` rejected the required named object `{"network":"198.51.100.0","mask":"255.255.255.0","gateway":"192.0.2.254"}` with `InvalidValue { field: "gateway" }`.
- Todo 24 explicitly forbids editing outside `crates/kcc-domain/**` and requires every `ip route` body to pass the catalog validator before transmission. Therefore routing implementation and its wipe-guard acceptance test cannot be started honestly: no production API may construct the real route while satisfying the validator-first invariant. The disposable probe was deleted, leaving the t24 worktree unchanged.
- Required prerequisite: fix catalog extraction/generated argument typing for `ip route` (and audit `ipv6 route`, whose `prefix` is also emitted as a keyword enum rather than an address-prefix type), regenerate catalogs, and add catalog regressions proving real named route objects validate for POST and DELETE. Redispatch todo 24 after that prerequisite lands.

## [2026-11-06] Todo 30 unit-one prerequisite blocker (private t30 worktree)
- No applier implementation was retained. A temporary integration probe against the actual `SessionManager` compiled and passed, proving that unauthenticated `GET /auth` returning HTTP 200 with an empty admin password yields `RciError::Http { status: 200 }` and no local session. Evidence: `.omo/evidence/task-30-preflight-contract.log` (1 passed, 0 failed). Probe and debug journal were removed.
- Root path: `ChangeWorkflow::begin` requires `read_last_change` and `registry.poll_info`; these reach `SessionManager::ensure_password_session` / `authenticate`. In `kcc-rci/src/session.rs:490-499`, HTTP success refreshes only an existing session and then becomes an HTTP error when no cookie exists. `request` additionally requires `usable_session` at lines 345-347. A factory-fresh state and password bootstrap cannot be supplied by a tiny additive accessor. Adding a fake that issues a normal challenge would evade the requested scenario.
- The required protected secret path is also absent: `kcc-app/src/workflow.rs:248-265` stores `CliCommand.line` as `String` and derives Debug, while `ChangeRequest.body` is debug-printable JSON. `ChangeSet::dispatch_cli` takes these commands, and no secret-bearing protected mutation API exists. The t30 planner currently also has `PlannedLine.command: String` and serde/Debug derives (`planner.rs:71-85`), contrary to the task's stated SecretString prerequisite; that planner correction is in scope, but cannot fix the workflow boundary.
- Further source-read limitations for later units: `dispatch_cli` collects per-item results into one Result (loses partial status on error); `RciClient::batch` submits the entire array before inspecting any error, so client-side stop_on_error cannot stop the router executing later lines in a submitted chunk. `ChangeSet` owns an immutable client and exposes neither reconnect nor protected startup upload. These observations are static, not runtime-tested here.
- Unit one and all later units remain incomplete. G0 and LSP were not run because no product source change was retained. Required owner prerequisite or expanded authorization: factory-fresh session/bootstrap support in kcc-rci, a secret-safe protected workflow request path in kcc-app, and credential/client transition support. Current authorization permits only tiny additive accessors outside migrate/testkit, which cannot implement these behavioral changes.

## 2026-11-06 todo 54 unit 1
- Testkit additive fixture: `show/internet/status` (synthetic.rs; keys internet, gateway-accessible, dns-accessible, host-accessible, captive-accessible - key names UNVERIFIED against a real router).
- kcc-rci `RciClient::show` 404 fallback POSTs `{}` (query dropped) and caches POST-only per path: follow-up for kcc-rci owner.
- poller.rs was 275 pure LOC on master (already > 250); now 341 with round planning/heavy fetch split into poller/extended.rs (145). Needs a split of the pre-existing helpers by the module owner.

## 2026-11-06: tsec incomplete acceptance, do not mark secret-write prerequisite complete
- Implemented and passing: protected catalog storage/projections; direct SecretString argument validation; quoted CLI template assembly; JSON write wrappers; response/status/RciError scrubbing at dispatch; presence/length JSON and show-rc verification; real password/PSK fake-router acceptance; request redaction properties; full G0.
- R1/R3 redaction-by-construction is not yet absolute: existing mutable public Value/path/audit fields can be overwritten after construction. Derived Debug/Serialize then trust those fields. Achieving an invariant requires private printable fields or context-aware custom serialization/Debug, with a deliberate compatibility review.
- R2 template matching checks catalog path/context tokens and pointer slots, but does not use the retained synopsis to prove placeholder grammar. Catalog::validate_cli remains conservative and cannot accept these config-user/config-if forms. Explicit CliCommand::secret also accepts an arbitrary line paired with structural metadata. These are not yet a complete validated transport contract.
- R4 post-write read-back/last-change errors and unrelated response field names/pointers can still retain router-controlled text outside the dispatch scrubber. Exact secret substring scrubbing does not establish full taint tracking. Secret-bearing DELETE is rejected before dispatch because the existing RCI transport encodes query data in URLs.
- R5 is partial: properties cover public requests (1..64 Unicode characters, catalog test 1..256) and fixed result/error echoes, not every result/error under random inputs. TRACE capture is a scoped current-thread subscriber, not proof of arbitrary worker-thread propagation. No deliberate mutation-testing pass was completed beyond the naturally failing scrubber regression.
- Scope blocker for strict end-to-end zeroization: kcc-rci::RciClient::{batch,parse,parse_batch} and Session HTTP serialization allocate ordinary Value/String/Vec request buffers. They cannot be made value-zeroizing solely from the allowed app/catalog/config files. Transport changes need an explicitly assigned kcc-rci task; do not claim all transient plaintext is zeroized.
- Architecture self-review: new modules have distinct responsibilities; no unsafe, numeric casts, unwrap/expect, new logging, or allow attributes added. Existing modified validate.rs (358 pure LOC), runtime.rs (555), workflow.rs (929) still exceed the programming-skill ceiling and need scoped extraction; secret_value.rs (239) and secrets_write.rs (244) are in the warning band. This was not completed. No final merge-ready claim is made.

## [2026-11-06] Todo 42 follow-ups
- Wire `WebState::with_jobs` in `crates/kcc/src/server.rs` (kcc was out of scope for todo 42).
- kcc-catalog `Command` lacks since/page/source_url/interface_type/context; kcc-web reads them from `kcc_catalog::generated::FILES` (`advanced/meta.rs`). Expose them on `Command` and drop the second parse.
- kcc-catalog has no secret flag on arguments; extraction also types `dyndns profile password` and `interface web-api password` as Keyword(values=["length"]).
- `BackgroundHandle` exposes only the final answer (`poll` loops internally), so explorer jobs stream status changes live and the output at completion; live line output needs a per-poll API in kcc-rci.
- `ChangeSet::apply_batch` audits `applied_unsaved` even when an item came back with an RCI error status; the web audit (`web.explorer_execute`/`web.console_rci`) records the real outcome.
- Pre-existing design-system defect seen in QA: `.toast[data-tone]` uses the translucent status wash as its background, so in dark mode the content under a toast shows through it (E5). Fix with an opaque raised base under the wash.

## [2026-11-06] Todo 44 follow-ups
- `kcc_mcp::KccMcp` resolves identities against its startup `roles` snapshot: a custom role created or edited in the Web UI reaches the kit RBAC (outer gate) at once, but inside the handlers a new role is `Forbidden` and an edited role keeps its old definition until restart (two-router migration scope checks rely on that inner check). Needs a role-source seam in kcc-mcp (not editable in todo 44).
- Nothing calls `api_keys::record_api_key_use`, so the API-key "Last used" column always says "Never"; kcc-mcp or a kit auth hook should record use.
- The Web UI role cache is refreshed by Web UI role changes only; a SIGHUP reload of an externally edited `roles.json` reaches MCP RBAC but not the Web UI until restart.
- The visual-qa dual-oracle review could not be dispatched (no oracle subagent available to this executor); captures were self-reviewed with a 390 px overflow probe, a CSP-violation listener and DOM checks.
- Typed-name confirmations clear the typed value when it does not match.
