All 25 findings hold up in some form: 12 are confirmed as written and 13 are adjusted, none refuted and none duplicates. All verdicts below come from code I opened this session; I made no edits and ran no `cargo`.

### X-01 ADJUSTED
- checked: `git branch -a` (only `* master`), `git symbolic-ref HEAD` (`refs/heads/master`), `git remote -v` (empty), `.github/workflows/ci.yml:3-8`, `.github/workflows/container.yml:3-9`, `.github/workflows/release.yml:5-8`, `CONTRIBUTING.md:3`, `deploy/podman/kcc.container:12`, `.github/dependabot.yml`
- reasoning: The finding is correct. `ci.yml` and `container.yml` filter `push`/`pull_request` on `branches: [main]`, but the only branch is `master` and CONTRIBUTING.md says to branch from `master`. Once the repo is pushed with `master` as default, pushes, PRs and Dependabot PRs start no CI and nothing turns red, so the "Failure blocks merge" requirement in §12 fails silently. Several things limit the damage, though:
  - There is no remote, so nothing is published or bypassed today.
  - The `v*` tag triggers in `container.yml` and `release.yml` still fire.
  - Both workflows have `workflow_dispatch`.
  - G0 is a local gate in AGENTS.md.
  
  Nothing at runtime breaks and no product security control is defeated, so this does not reach "high".
- severity: medium
- correction: Medium, not high: the gap is in the CI process and has no runtime consequence. Fix it with `branches: [master]` in `ci.yml` and `container.yml`, or by removing the branch filter. Also fix `kcc.container:12` `blob/main`, which will 404.

### X-02 ADJUSTED
- checked: `ci.yml:177-199`; `xtask/src/cargo_lints.rs:37-49`; `xtask/src/lint_completeness.rs:51-65`; dtolnay/rust-toolchain `action.yml` at the pinned SHA `7e38f4b` (`rustup toolchain install … --profile minimal`, then `rustup default <toolchain>`); RUST_GUIDELINES.md:2012-2036; overlay:98-100; no `rust-toolchain.toml`
- reasoning: The core claim holds. The `gates` job installs 1.100.0 with the minimal profile, sets it as default, and adds no `rust-docs`. `rustc --print sysroot` then points at a sysroot without `share/doc/rust/html/cargo/reference/lints.html`, so `cargo_lints::run` returns `GateError::Read`. The step fails and the later steps in the job (`allow-gate` … actionlint) never run. The sub-claim about `rustup run stable` is not a repository defect: it copies the vendored core script verbatim (`rustup run stable clippy-driver -W help`, guideline line 2015), which the overlay says xtask mirrors. The failure is also loud and fail-closed (a red job on the first run), not a silent pass.
- severity: low
- correction: Drop the "stable" sub-claim as mandated by the vendored script. What remains is that `components: rust-docs` (and `clippy` if it should not depend on the runner's stable) is missing from the gates job, and the job fails deterministically and visibly.

### X-03 CONFIRMED
- checked: `deploy/podman/e2e.sh:20,73-88,184,323-333,414-422,450-468`; `deploy/podman/live-e2e.sh:22,72-80,200-225`; `deploy/podman/README.md:161-178`
- reasoning: `step` runs each function as an `if` condition, where bash suspends `errexit` for the whole function body. In `domain_write_save`, failures of `set-description`, `static-host` and `config save` are masked by the last command, `config state`, which does not check them. In `sighup_reload`, the `wait_line` result is ignored and only `healthz` decides. `live-e2e.sh` `reversible_write` passes when `clients register` fails, because the final check only proves absence. `web_login_dashboard`'s mid-function `[[ -n "${csrf}" ]]` is also ignored, though later checks catch it. README:172-178 explicitly relies on the functional steps, not the log grep, to prove the profile, so this weakens the only seccomp proof.
- severity: medium

### X-04 ADJUSTED
- checked: `release.yml:5-8,59-61,104-106,121-123,154-182`; `container.yml:61-108,120-133`; `CONTRIBUTING.md:21-28`; `AGENTS.md:30`
- reasoning: Correct as stated: neither workflow runs or `needs` deny, audit, vet, test or clippy before publishing. However, G1 is documented as a gate the contributor runs before release, not as something CI enforces. A tag push needs repository write access. The container push does wait for the full container e2e. The real cost is a missed advisory or an unreviewed commit at release time, which is a process gap rather than a weakened runtime control.
- severity: low
- correction: Low. The fix is unchanged: a `cargo deny check` plus `cargo audit` job that the build/push jobs `need`.

### X-05 ADJUSTED
- checked: `RUST_GUIDELINES.md:1628-1670,1672-1897,2006-2036`; root `Cargo.toml` `[workspace.lints.*]`; `xtask/Cargo.toml` `[lints.*]`; `xtask/src/lint_completeness.rs:95-101`; `xtask/src/profile_eq.rs:1-80`; overlay:93-100
- reasoning: I normalised comments and whitespace and diffed the tables myself. The root tables equal the §9 profile line for line (only the markdown fence differs). The xtask tables are equal apart from `[lints.x]` versus `[workspace.lints.x]`, which is the single-package form §9 allows. The gate is indeed names-only and `profile-eq` compares xtask to root only. But the core's own completeness procedure is names-only too (`grep -oE '^[a-z0-9_]+' Cargo.toml`, line 2018), and the core mandates no level check. Nothing is violated today, and a level change would be a visible manifest diff.
- severity: info
- correction: This is hardening, not a defect: nothing violates it today and the core asks for no such check. Optional fix: compare the root tables against the TOML block extracted from the checksummed `RUST_GUIDELINES.md`.

### X-06 CONFIRMED
- checked: `supply-chain/audits.toml` (an empty `[audits]` table); `supply-chain/config.toml:1-20,51,159,695,703-713,735` (307 `[[exemptions` entries); `supply-chain/imports.lock` (176 imported audits); `ci.yml:147-150`; RUST_GUIDELINES.md:3033-3048
- reasoning: Every first-party trust decision is an exemption. The CI comment makes "regenerate exemptions" the standing bump procedure, so a new version of `rmcp-server-kit`, `rustls` or `reqwest` is exempted automatically and `cargo vet` can never fail on a bump. §10's purpose ("someone actually read this dependency's source code") is not met. The cooldown and deny/audit remain.
- severity: low

### X-07 ADJUSTED
- checked: `xtask/Cargo.toml:13-25`; `xtask/Cargo.lock` (128 packages); `ci.yml:123-150,201-218`; `deny.toml:1-12`; `docs/BACKLOG.md:78`
- reasoning: The advisory half is wrong. The `xtask` CI job runs `cargo deny --manifest-path xtask/Cargo.toml check`, and `check` includes the `advisories` check (the root `deny.toml` `[advisories]` is the config it picks up; BACKLOG:78 confirms that config is being read). RUSTSEC advisories in xtask's lockfile are therefore reported. Only `cargo vet` does not cover the xtask workspace, and that is developer and CI tooling, not shipped code.
- severity: info
- correction: "never advisory-checked" is false. What remains is that xtask has no `cargo vet` coverage.

### X-08 ADJUSTED
- checked: `ci.yml:12-13,34,64,88,103,114,127,140,156,170,181,205,224`; `container.yml:38-40`; `release.yml:43,90,129`
- reasoning: Accurate: none of the `ci.yml` checkouts set `persist-credentials: false`. But the token is `contents: read`, the workflow uploads no artifacts (the "artipacked" path), and code that can read `.git/config` (`build.rs`, proc-macros) already has the full checkout. The token adds next to nothing.
- severity: info
- correction: This is a consistency fix with no demonstrated consequence.

### X-09 CONFIRMED
- checked: `container.yml:61-69,120-133`; `release.yml:173-176`; `Containerfile:61-66`; `deploy/podman/run.sh:15`; `deploy/podman/kcc.container:18`
- reasoning: Every `v*` tag, including `v0.2.0-rc.1`, is pushed as `:latest`, and `run.sh` and the Quadlet unit default to `:latest`. `VERSION` is never passed to `podman build`, so the label is always `0.1.0`.
- severity: low

### X-10 CONFIRMED
- checked: `scripts/live/web-smoke.sh:52,149-161`; `scripts/live/web-smoke.mjs:5,57-58`
- reasoning: The per-run admin password for `smoke` goes into the `podman run` argv, which other local users can read via `/proc/<pid>/cmdline` (absent `hidepid`) while the run lasts. With it they can log in to the loopback kcc that holds live router credentials. One sub-claim is wrong: `podman inspect` is not a cross-user vector, because rootless containers are per-user.
- severity: low

### X-11 ADJUSTED
- checked: `crates/kcc-rci/Cargo.toml:12`; `crates/kcc-rci/src/auth_ndw4.rs:88`; `crates/kcc-rci/src/auth_digest.rs:188`; `Cargo.lock` (the packages depending on `getrandom 0.2.17` are `kcc-rci` and `ring`); `deny.toml:36-41`; `clippy.toml:16-22`
- reasoning: `ring` really does pull in `getrandom 0.2.17`, so the skip reason is accurate today. The "if ring leaves" impact is hypothetical. The only concrete point is that first-party `kcc-rci` uses the old major at two call sites while 0.4 is already in the tree.
- severity: info
- correction: The skip reason is not wrong. Optionally move `kcc-rci` (`auth_ndw4.rs:88` and `auth_digest.rs:188`) to `getrandom` 0.4 / `rand` and add `kcc-rci` to the reason while 0.2 remains.

### X-12 CONFIRMED
- checked: `scripts/ci-local.sh:1-10,51-58`; `ci.yml:186-191`
- reasoning: The script says it is kept in step with `ci.yml`, but its `gates` step lacks `cargo xtask cancel-safety`, which CI runs at line 191.
- severity: low

### X-13 CONFIRMED
- checked: `container.yml:86-91`; `deploy/podman/seccomp-kcc.json:1-11`; `deploy/podman/README.md:113-155`
- reasoning: The drift check is `continue-on-error: true`, and the profile lists X86, X32 and ARM next to the two shipped architectures. The README documents both as deliberate, and the generator already fails on any syscall with no group. Nothing to fix urgently.
- severity: info

### T-01 CONFIRMED
- checked: `crates/kcc-app/tests/secrets_write.rs:60-155`; `crates/kcc-domain/tests/users.rs:72-110`; `wifi.rs:128-165`; `wan.rs:115-152`; `vpn_credentials.rs:30-115`; `crates/kcc-app/src/workflow.rs:246-249,387-390`; `crates/kcc-app/src/workflow_cli/command.rs:62-140`; `crates/kcc-config/src/quoting.rs:12-24`; `crates/kcc-domain/tests/support/mod.rs:71-85`; `crates/kcc-app/src/audit/writer.rs:40-70`; for contrast, `crates/kcc/tests/cli_domain_writes/secrets.rs:22-75,153-181`
- reasoning: The secret markers are `"a secret with \"quote\" and \\ slash"`, `"…with spaces \"quotes\""`, `"wireless passphrase with \"quotes\""`, `"ppp password with \"quotes\""` and `"vpn fixture with \"quote\""`. Each is checked with `!output.contains(secret)` against `{:?}`, `serde_json::to_string`, `audit.jsonl` (JSON) and `{:?}` of `request_log()`. All of these escape `"`, so the assertions cannot fail. The worst case is `secrets_write.rs`: it deliberately passes the plaintext as `json!({"detail":secret})` to test the scrub at `workflow.rs:390`. If the scrub broke, the audit line would hold the JSON-escaped secret and the test would still pass. It is even broader than reported: `quoting.rs:23` always double-quotes and escapes `"`/`\` on the wire, so the raw-text `running_config_text()` and `request_log` checks are vacuous too. The `set_default`/`spawn_blocking` sub-point is plausible and remains INFERRED.
- severity: medium
- correction: Scope note: "only catch leaks printed raw" is overstated. `kcc/tests/cli_domain_writes/secrets.rs` (`PASSWORD = "s3cret-Vpn-Passw0rd"`, WireGuard keys) and `kcc-migrate/tests/support/apply_secrets.rs` use quote-free secrets against the audit log. The `kcc-app` scrub test and the four domain suites listed are vacuous.

### T-02 CONFIRMED
- checked: `crates/kcc/tests/live_presets.rs:147-170,176-231`; `crates/kcc-mcp/tests/live_mcp/session.rs:75-95,205-225`; `crates/kcc-app/src/registry.rs:379-399`; `crates/kcc-rci/src/outbound.rs:96-121,156-159,241-259`; `crates/kcc-testkit/src/capture.rs:168`; `live_domains/campaign.rs:155-161`; `live_migration/rehearsal.rs:208-215`
- reasoning: `OutboundPolicy::default()` allows RFC1918 addresses, but `RouterRegistry::new` replaces them with `with_allowed_networks` built from an empty `OutboundConfig`. `allows()` then admits only loopback (when enabled), configured networks, or global addresses with a matching suffix. The `kcc` child (`live_presets`) and the MCP registry (`live_mcp`) therefore refuse `192.168.x.x`, after `admit`/`capture::connect` (default policy) has already passed. The loopback twins hide this, while `live_domains` and `live_migration` already pass `admission.outbound`.
- severity: medium

### T-03 ADJUSTED
- checked: `crates/kcc-testkit/src/server.rs:415-451,966-1046,1162-1170`; `crates/kcc-rci/src/engine.rs:471-486`; `crates/kcc-app/src/workflow.rs:1278-1295`; `crates/kcc-testkit/BEHAVIOUR.md:242-246`; `crates/kcc/tests/live_domains/harness.rs:145-186`
- reasoning: The batch collapse is real. `record_request` pushes one record per HTTP request, and `post_one` calls `record_command` for each array item on `last_mut()`, so a `[a, b]` batch logs only `b`, and a secret last item blanks it. That contradicts BEHAVIOUR.md ("non-secret root parser lines"). However, no current assertion is shown to pass wrongly. The arm/disarm lines are single-line requests (`any(line == ARM)`, `last() == DISARM`), and "the suite saved" is also checked through `startup_config_text` equality. The concurrency interleaving remains INFERRED.
- severity: low
- correction: This is a fidelity bug in the fake that could mask future absence assertions. No current test is demonstrated to be wrong.

### T-04 ADJUSTED
- checked: `crates/kcc-testkit/src/cli_engine/secrets.rs:55-105`; `crates/kcc-testkit/src/server.rs:438-451,702-737`; `crates/kcc-domain/src/router_users.rs:210-221`; `crates/kcc-domain/src/vpn_clients/secrets.rs:57`; `crates/kcc-testkit/BEHAVIOUR.md` (grep for wpa/md5/plain/ns3; lines 55,177,242-262,270-275); `crates/kcc/tests/live_migration/probe.rs:74-80`
- reasoning: The headline is weak. kcc is supposed to send `password plain` and plaintext `wpa-psk` (the router hashes or encodes them), and `secrets_write.rs` labels these assertions "fake must store a hash" and "fake must encode the PSK". So no kcc property is mis-attributed. The sub-points are real:
  - The plain-to-md5 and wpa-psk-to-NS3 conversions are not marked assumed in BEHAVIOUR.md, which CONTRIBUTING requires.
  - The stored `md5(password)` disagrees with the realm HA1 that both the fake's auth (`server.rs:726`) and the project's own live probe (`probe.rs:76`, `ndw2::ha1` as `password md5`) use. `password md5 <x>` also never updates the fake's auth, so password replay can't be covered.
  - `crypto ike key <name> <psk>` matches none of the request-log secret markers, contradicting BEHAVIOUR.md:242-244.
- severity: low
- correction: Drop "tests check the fake, not kcc" as a defect. Keep these items: the undocumented conversions, the md5-versus-HA1 inconsistency, and the missing `ike key` marker.

### T-05 ADJUSTED
- checked: `crates/kcc/tests/live_migration/rehearsal.rs:205-215,250-282`; `crates/kcc/tests/live_migration.rs:85-140`; `crates/kcc/tests/live_migration/guard.rs:8-27,85`; `AGENTS.md` live env contract
- reasoning: Correct: the `SourceInput::Live` router is registered and its startup config downloaded with no `verify_serial`, which contradicts AGENTS.md's "Every live test reads the serial … and refuses any router not listed". It is mitigated in three ways:
  - The access is read-only.
  - The operator has to explicitly supply `KCC_LIVE_SOURCE_URL` and its admin password file.
  - The source registry uses the admitted target's `outbound` policy, so it must sit inside the test config's `allowed_networks`.
  
  The default source is a file.
- severity: low
- correction: This is a contract violation on a read-only path the operator opts into explicitly, so low rather than medium. The fix is unchanged.

### T-06 CONFIRMED
- checked: `crates/kcc-mcp/tests/live_mcp.rs:40-97`; grep for `tracing_subscriber` in `live_mcp.rs`, `live_mcp/` and `crates/kcc-mcp/Cargo.toml` (none); `crates/kcc/tests/live_smoke.rs:78`
- reasoning: With no subscriber installed, `tracing::warn!("live-skip:…")` goes nowhere. It is not completely silent, because `live_matrix::record_skip` writes a skip row to the evidence file. `write_config: config.filter(|_| write)` drops writes silently, but the matrix then says "reads only".
- severity: low

### T-07 CONFIRMED
- checked: `crates/kcc/tests/serve_bracket/process.rs:85-95`; `crates/kcc/tests/metrics_serve.rs:99-103,155-165`; `crates/kcc/tests/cli/health.rs:25-35`
- reasoning: The bind-to-0, read port, drop listener, pass to child pattern is a real TOCTOU in parallel test runs. The frequency is kernel-dependent (INFERRED), and the false-pass case in `health.rs` needs another kcc on the reused port.
- severity: low

### T-08 CONFIRMED
- checked: `crates/kcc/tests/live_smoke.rs:1-6,73-100`; `crates/kcc/tests/live_domains/gate.rs:45-70`; `crates/kcc-mcp/tests/live_mcp/session.rs:83-95`; overlay rule (g) line 55-56; `AGENTS.md` test tiers ("only against `test_device = true` profiles")
- reasoning: Rule (g) and AGENTS.md state the restriction with no read-only exception, and these suites log in as admin and read `running-config` with only the serial allowlist as a guard. It is not listed as an owner decision.
- severity: low

### T-09 ADJUSTED
- checked: `crates/kcc/tests/live_migration/rehearsal.rs:110-140`; `crates/kcc/tests/live_migration/probe.rs:55-100`; `crates/kcc/tests/live_domains/matrix.rs:95-115`
- reasoning: The probe runs after `applier.rollback()`/`commit()`, with no timer armed. A `?` failure between `password md5` and `no user` leaves a readonly-tagged account in running config (unsaved, so a reboot clears it). `results[1]`, the target-realm control, is recorded and never asserted, so a probe that always fails yields an uninformative pass. The `matrix.rs` sub-claim is wrong: `campaign()` is a skip-row recorder by design, not a behaviour test.
- severity: low
- correction: Drop the `live_campaign_matrix` sub-claim and keep the probe ordering, cleanup and missing control assertion.

### T-10 ADJUSTED
- checked: `crates/kcc-web/tests/explorer_pages/bracket.rs:50-145`; `crates/kcc-mcp/tests/support/bracket.rs:30-47`; `crates/kcc-mcp/tests/support/bracket_failures.rs:40-95`; `crates/kcc-domain/tests/bracket.rs:76-90`; `crates/kcc-web/tests/explorer_pages/bracket_batch.rs:15-35`; `crates/kcc-mcp/tests/support/bracket_batch.rs:20-40`
- reasoning: The duplication is real: `edges()` is copied verbatim in Web and MCP, `lines()` is the same in the domain tests, and the batch table is identical. But each surface asserts its own mapping (Web message keys versus MCP codes such as `management_outcome_unknown_fail_safe_armed`), which already is the "one row per fate per surface" the fix proposes. Only the copied arm/disarm constants and fault rows carry drift risk.
- severity: info
- correction: Move the arm/disarm lines and fault constructors into `kcc-testkit`. The per-surface rows are justified.

### T-11 ADJUSTED
- checked: `crates/kcc/tests/source_guards.rs:1-63`; `clippy.toml` (no `disallowed-*`); `crates/kcc/src/privileges.rs:432-472` (unit tests); `container.yml:79-83`; `deploy/podman/e2e.sh:450`
- reasoning: The cited bypass is wrong: `use std::process::Command as Run;` contains `std::process::Command` and is caught. A real bypass is `use std::process::{Command as Run}; Run::new(..)`. Exit 77 is already tested through the real binary (container CI `--user 0`, the e2e `privilege-floor` step and the unit tests), so the first-statement grep only adds an ordering check. The substring ban remains weaker than a `clippy::disallowed_types` entry.
- severity: low
- correction: Bypass example: `use std::process::{Command as Run}`. Exit-code coverage of the privilege floor exists outside this test.

### T-12 CONFIRMED
- checked: `crates/kcc-web/src/page_kit/request.rs:169-193`; `crates/kcc-web/src/table/rows.rs:52-55`; RUST_GUIDELINES.md:3538-3554
- reasoning: Both sides are `{:?}` of the same type, so §13's instability concern (comparing against a literal rendering) does not apply. Equality-through-Debug is still a weak proxy, and `TableQuery` has no `PartialEq`.
- severity: info

## Summary
- **X lane:** 6 confirmed (X-03, X-06, X-09, X-10, X-12, X-13), 7 adjusted (X-01, X-02, X-04, X-05, X-07, X-08, X-11), 0 refuted, 0 duplicates.
- **T lane:** 6 confirmed (T-01, T-02, T-06, T-07, T-08, T-12), 6 adjusted (T-03, T-04, T-05, T-09, T-10, T-11), 0 refuted, 0 duplicates.
- **Total:** 12 confirmed, 13 adjusted, 0 refuted, 0 duplicates.
- **Main calibrations:**
  - X-01 drops from high to medium: there is no remote and the gap has no runtime consequence.
  - X-02 drops to low: the `stable` part mirrors the vendored script, and the failure is loud and fail-closed.
  - X-07: `cargo deny check` on xtask already covers advisories.
  - T-01 is broader than reported: on-wire quoting makes the raw-text checks vacuous as well.
- **No NEW issue.** One combination is already covered by T-01 and T-04: the fake keeps the quoted plaintext IKE PSK in `request_log()` (no `ike key` marker), and `vpn_credentials.rs` cannot detect it, because the secret contains `"`.