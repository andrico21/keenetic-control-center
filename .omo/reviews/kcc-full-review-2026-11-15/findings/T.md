# Lane T review: test quality across the workspace, the fake router and the live suites

I found 12 issues: 5 medium, 6 low and 1 info. None is critical or high. Every source location cited below was opened in this session. Repository files were not changed and no `cargo` command was run.

The four findings that matter most:
- **T-01:** the main secret-leak tests cannot fail for audit JSON, `Debug`, serde JSON or `?`-formatted trace fields, because their secrets contain a quote.
- **T-02:** `live_presets` and `live_mcp` will be refused by kcc's own outbound policy on any real router, and their hermetic twins hide this.
- **T-03:** the fake router's request log keeps only the last parse line of a batch and can attach a line to the wrong request when requests overlap.
- **T-04:** the fake hashes or NS3-encodes plaintext secrets itself, so tests that claim "kcc hashes / never stores plaintext" are checking the fake, not kcc.

### T-01 Secret-leak tests cannot fail for JSON, `Debug` or `?`-formatted traces: each secret contains `"` (and `\`)
- severity: medium
- kind: test-quality
- rule: project rule (d); RUST_GUIDELINES.md §13 "Use mutation testing to verify test effectiveness" (3518)
- evidence:
  - `crates/kcc-app/tests/secrets_write.rs:72` `let secret = "a secret with \"quote\" and \\ slash";`. The request carries `json!({"detail":secret})` as its audit detail (around lines 85-94). At lines 136-146 it checks `assert!(!String::from_utf8(audit)?.contains(secret), "audit must not retain plaintext")` and `!format!("{:?}", handle.request_log()).contains(secret)`.
  - `crates/kcc-domain/tests/users.rs:77` secret `...with spaces \"quotes\"`. Lines 86-107 run `!format!("{operation:?}").contains(secret)` and `!serde_json::to_string(&result)?.contains(secret)`.
  - `crates/kcc-domain/tests/wifi.rs:134,140-161`, `wan.rs:119,125-150` and `vpn_credentials.rs:37,98-112` follow the same pattern.
- impact:
  - `Debug` and JSON both write `"` as `\"` and `\` as `\\`. The raw secret is therefore never a substring of those encodings.
  - Example: a regression that copied the plaintext into the audit entry's `detail` would produce `...with \"quote\" and \\\\ slash` in `audit.jsonl`, and every assertion above would still pass. The same holds for a `#[derive(Debug)]` on a secret-holding type or a `?`-formatted tracing field.
  - The suites that guard rule (d) only catch leaks printed raw through `Display`.
  - A smaller gap (INFERRED): `TraceCapture` is installed with the thread-local `set_default` (`kcc-domain/tests/support/mod.rs:83`). The audit writer works inside `spawn_blocking` (`kcc-app/src/audit/writer.rs:53`), so events from that thread are not captured.
- fix: Check each sink against every encoding the secret can take there: `serde_json::to_string(secret)` without its outer quotes, `secret.escape_debug()`, and the CLI-quoted form. Alternatively, add a second secret with no characters that need escaping and run the checks on both.
- confidence: high

### T-02 `live_presets` and `live_mcp` cannot reach a real router; their twins hide it with `allow_loopback`
- severity: medium
- kind: test-quality
- rule: project rule (g); AGENTS.md "Live env contract"
- evidence:
  - `crates/kcc/tests/live_presets.rs:186-190` writes `"[outbound]\nallow_loopback = {allow_loopback}\n\n[state]\n...[[routers]]\nname = \"target\"\nurl = {:?}..."`, with no `allowed_networks`.
  - `crates/kcc-mcp/tests/live_mcp/session.rs:218-220`: `let mut outbound = OutboundConfig::default(); outbound.allow_loopback = target.allow_loopback; let registry = Arc::new(RouterRegistry::new(state.clone(), &[], &outbound)?);`
  - `crates/kcc-app/src/registry.rs:387-395` builds the policy with `.with_allowed_networks(networks)` from that empty list.
  - `kcc-rci/src/outbound.rs:254-259` then admits only addresses inside `allowed_networks` or matching a suffix. Both lists are empty, and README states this default refuses every router.
- impact:
  - With the live variables set against, say, 192.168.1.1, both suites pass the gate and the serial check: `capture::connect` uses `OutboundPolicy::default()`, which allows private networks.
  - The `kcc` process (`live_presets`) and the MCP registry (`live_mcp`) then refuse the router, so both suites always fail on hardware.
  - The twins pass because loopback is allowed, so the fake runs never exercise the real outbound path. The live campaign cannot produce `live_presets` or `live_mcp` evidence.
- fix: Copy `outbound` from the admitted `KCC_LIVE_TARGET_CONFIG` into the hermetic `kcc.toml` and into the MCP registry, as `live_domains/campaign.rs:157-161` and `live_migration/rehearsal.rs:211-215` already do. In the twins, set `allowed_networks` instead of relying on loopback alone.
- confidence: high

### T-03 Fake router request log keeps only the last parse line of a batch and can misattribute lines under concurrency
- severity: medium
- kind: bug
- rule: overlay `http-services.md`: none; BEHAVIOUR.md says the log "records ... non-secret root parser lines" (lines 242-246)
- evidence: `crates/kcc-testkit/src/server.rs:439-453`
  ```rust
  fn record_command(&self, line: &str) {
      ...
      if let Some(record) = lock(&self.request_log).last_mut() {
          record.command = (!secret).then(|| line.to_owned());
      }
  }
  ```
  - It is called for each batch item at `server.rs:974-976` (`post_one`, called per item from `post`, lines 1024-1046).
  - The record itself is pushed earlier, in middleware (`server.rs:416-436`, called at line 1169), before the body is read across an await.
  - kcc sends multi-line CLI changes as one batch: `kcc-app/src/workflow.rs:1284-1292` (`many => self.client.parse_batch(...)`).
- impact:
  - A two-line change `[a, b]` appears in `request_log()` as `b` only. A secret line in a batch also overwrites the previous item's line with `None`.
  - Two overlapping requests (A records, B records, A's body arrives) put A's line on B's record, and B then overwrites it.
  - Absence assertions built on this log can pass wrongly. Examples: "never saved" (`live_domains/harness.rs:153-158`), "never disarmed" (`harness.rs:183-186`), "nothing sent" in the bracket matrices.
  - Order and presence assertions with concurrent posts (`kcc-web/tests/explorer_pages/bracket_budget.rs:225-228`) can flake.
- fix: Record parse lines per request, not at `last_mut()`. Carry a record index in a request extension set by the middleware, and store `Vec<Option<String>>` of lines per record. Document batch behaviour in BEHAVIOUR.md.
- confidence: high for the batch collapse; medium for the concurrency interleaving (INFERRED: depends on the scheduling of the body-read await).

### T-04 The fake hashes or encodes plaintext secrets itself, so "kcc hashes / never stores plaintext" tests check the fake; the conversion is undocumented
- severity: medium
- kind: test-quality
- rule: §13 "Mocks must preserve the behavior being asserted"; brief item "fake router behaviour that diverges ... without being marked assumed"
- evidence: `crates/kcc-testkit/src/cli_engine/secrets.rs:84-104`
  ```rust
  if starts_with(command, &["user"]) && command.get(2)... == "password" && command.get(3)... == "plain" {
      let digest = Md5::digest(secret.as_bytes());
      ...
      *format_token = Token::Word("md5".to_owned());
      *secret_token = Token::Word(encoded);
  ```
  - Lines 69-76 likewise `encode_last` any plaintext `authentication wpa-psk|password`.
  - kcc sends `user {name} password plain {/password}` (`kcc-domain/src/router_users.rs:217`).
  - The test `users.rs` `password_write_hashes_and_never_exposes_plaintext` asserts `running_config_text().contains("password md5")` and that the running config does not contain the secret (around lines 99-105). `wifi.rs` asserts `contains("wpa-psk ns3")`.
  - BEHAVIOUR.md has no entry for plain→md5 (grep for `md5|plain` hits only lines 55 and 274).
  - The hash is `md5(password)`, not the realm-bound HA1 that the fake uses for login (`server.rs:726`).
- impact:
  - These tests pass whether kcc sends plaintext or not; the "hashes" and "never in running config" properties are the fake's.
  - A config that has been through the fake carries a `password md5` that does not authenticate on the fake, so migration tests cannot cover password replay.
  - A related gap: the request-log secret filter (`server.rs:440-449`) has no marker for `crypto ike key <name> <psk>`. A plaintext IKE PSK therefore stays in `request_log()`, contrary to BEHAVIOUR.md lines 242-244.
- fix: Mark the plain→md5 and plaintext→NS3 conversions **assumed** in BEHAVIOUR.md. In the tests, assert on what kcc sent (the parse line before the fake's conversion), not on the stored text. Add `"ike key"` to the request-log secret markers.
- confidence: high

### T-05 Live migration reads a live source router without the serial allowlist
- severity: medium
- kind: security
- rule: AGENTS.md "Every live test reads the serial via `show identification` and refuses any router not listed"; project rule (g)
- evidence: `crates/kcc/tests/live_migration/rehearsal.rs:260-273`
  ```rust
  SourceInput::Live { url, login, password_file } => {
      let profile = ManagedRouterProfile::new("source".to_owned(), Url::parse(url)?, ...);
      self.registry.create(&self.role, profile).await?;
      let client = self.registry.client("source").await?;
      let bytes = client.download_config(ConfigKind::Startup).await?;
  ```
  Only the target goes through `guard::admit` (`live_migration.rs:119-127`).
- impact: `KCC_LIVE_SOURCE_URL` can name any router, typically the production one, and the suite downloads its full startup config with secrets without checking its serial against `KCC_LIVE_ALLOW_SERIAL`. The owner's "refuse any router not listed" guarantee does not hold for the source.
- fix: Call `connect` plus `verify_serial(&client, &live.allowed)` on the source before `registry.create`, and return a `Refusal::SerialNotAllowed` for it.
- confidence: high

### T-06 `live_mcp_smoke` skips silently: no tracing subscriber, so `live-skip:` is never printed
- severity: low
- kind: test-quality
- rule: AGENTS.md "A missing variable makes the live test log `live-skip:<reason>` through `tracing` ... It never passes silently."
- evidence: `crates/kcc-mcp/tests/live_mcp.rs:79-89`
  ```rust
  async fn live_mcp_smoke() -> TestResult {
      let target = match live_env() {
          Ok(target) => target?,
          Err(reason) => {
              tracing::warn!("live-skip:{reason}");
  ```
  There is no `tracing_subscriber` initialisation in this file or in `live_mcp/session.rs` (grep: none). The other live suites call `tracing_subscriber::fmt()...try_init()` first, for example `live_smoke.rs:78`.
- impact: `cargo test -p kcc-mcp --test live_mcp -- --ignored` without the variables reports `ok` and nothing names the skip. `KCC_LIVE_ALLOW_WRITE=1` without `KCC_LIVE_TARGET_CONFIG` also drops to read-only with no message (`live_mcp.rs:59-70`).
- fix: Add `drop(tracing_subscriber::fmt().with_writer(io::stderr).try_init());` as the first line, and warn when writes are requested without a config.
- confidence: high

### T-07 Ports reserved by bind-0-then-drop are reused by child processes
- severity: low
- kind: test-quality
- rule: §13 test tiers / determinism; brief item "ports ... that collide in parallel runs"
- evidence:
  - `crates/kcc/tests/serve_bracket/process.rs:91` `let port = TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port();`
  - The same pattern appears at `metrics_serve.rs:99-102` and `:160` (`let (port, metrics_port) = (reserve_port()?, reserve_port()?);`), `metrics_serve/runtime.rs:62`, `serve.rs:242-246`, `serve_origin.rs:211-214`, `cli/health.rs:31-34` and `serve_refresh/support.rs:153`.
- impact:
  - The listener is closed before `kcc serve` binds, so a parallel test or a fake router can take the port in between.
  - Two reservations in a row can even return the same port. `metrics_serve` then has `listen_port == metrics.bind`, and the child fails to bind.
  - In `cli/health.rs` the healthcheck can answer 0 against another test's server (a false pass).
- fix: Have `kcc serve` accept `listen_port = 0` and log the bound address, then parse it from the "listening" line. Alternatively, pass an inherited, already-bound socket.
- confidence: medium (INFERRED: the kernel's reuse timing decides how often this happens)

### T-08 Read-only live suites contact routers without a `test_device = true` profile
- severity: low
- kind: guideline
- rule: project rule (g) "Live suites run only against router profiles marked `test_device = true`"
- evidence:
  - `crates/kcc/tests/live_smoke.rs:87-93` connects, verifies the serial and reads every captured path, including `running-config` and the `rci-root` tree. No profile is checked.
  - `live_domains/gate.rs:59-62`: `WriteMode::ReadOnly => None` skips `admission`.
  - `kcc-mcp/tests/live_mcp/session.rs:85-89`: `None => false` reads without a profile.
- impact: Only the serial allowlist stands between these suites and a production router. They still log in as admin and download its full configuration. Rule (g) has no read-only exception.
- fix: Require `KCC_LIVE_TARGET_CONFIG` with `test_device = true` for every live suite, and keep the serial check as the second gate. If read-only runs on non-test devices are intended, record that as an owner decision in the project overlay.
- confidence: high

### T-09 Live migration probe writes after the safety net and records results instead of asserting them
- severity: low
- kind: test-quality
- rule: brief item "tests that print 'evidence' instead of asserting"; project rule (g)
- evidence:
  - `crates/kcc/tests/live_migration/rehearsal.rs:126-134`: `applier.rollback().await?` (or `commit`), then `probe::password_hash(...)`.
  - `live_migration/probe.rs:74-94` then runs:
    ```rust
    client.parse(&format!("user {PROBE_USER} password md5 {}", hash.as_str())).await?
    client.parse(&format!("user {PROBE_USER} tag readonly")).await?
    results.push(login(rehearsal, &password).await);
    ...
    drop(client.parse(&format!("no user {PROBE_USER}")).await?);
    evidence.record(&json!({... "target_realm_hash_accepted":results.get(1)}))?;
    ```
  - `live_domains/matrix.rs:99-115` (`live_campaign_matrix`) only writes `LiveSkip` rows and cannot fail.
- impact:
  - The probe account is created with no fail-safe timer armed. A `?` failure between the create and `no user` leaves it on the router's running config.
  - The target-realm control (`results[1]`) is never asserted. A probe that always fails (wrong tag, outbound refusal) records `false/false` and the suite passes.
- fix: Run the probe inside an armed fail-safe timer, or before the rollback, and remove the account on every path. Assert that `target_realm_hash_accepted == Some(true)` before trusting the source-realm result.
- confidence: high

### T-10 Bracket fate matrices are copied across the Web, MCP and domain tests
- severity: low
- kind: duplication
- rule: brief item "duplicated scenarios across surfaces"
- evidence:
  - The five-row fault table (`disconnect_after_parse("ip http port")`, `fail_parse_matching("no system",1)`, `(timer,2)`, `(timer,1)`, `("no ",1)`) appears in both `kcc-web/tests/explorer_pages/bracket.rs:111-142` and `kcc-mcp/tests/support/bracket_failures.rs:47-92`.
  - `batch_completion_controls_recovery_message` is a copy in `bracket_batch.rs:19-31` (Web) and `bracket_batch.rs:25-37` (MCP).
  - The same holds for `recovery_mechanism_follows_the_reported_mode` (Web `bracket_mode.rs:18`, MCP `bracket.rs:152-153`), the dead-audit pair, and `edges()`/`lines()` (`web bracket.rs:56-65`, `mcp bracket.rs:36-45`, `kcc-domain/tests/bracket.rs:80-89`).
  - The fate logic itself lives in `configuration::bracket::guarded`, which `kcc-domain/tests/bracket.rs:55-66` already covers.
- impact: Changing an arm or disarm line or adding a fate means editing three tables in step. A row fixed in one surface silently drifts in the others.
- fix: Keep the full fate matrix in `kcc-domain`. Have each surface test one row per fate to its code and message, from a shared table in `kcc-testkit` or test support.
- confidence: high

### T-11 Source-grep tests stand in for behaviour tests
- severity: low
- kind: test-quality
- rule: brief item "source-grep tests"
- evidence: `crates/kcc/tests/source_guards.rs:37-40` and `57-62`
  ```rust
  assert!(body.starts_with("if let Err(error) = kcc::privileges::enforce()"), ...);
  for spawner in ["std::process::Command", "Command::new", "exec("] {
      assert!(!source.contains(spawner), ...);
  ```
- impact:
  - A formatting or naming change breaks the first test. `use std::process::{self as p}; p::Command::new` is still caught, but `use std::process::Command as Run; Run::new(..)` or `std::os::unix::process::CommandExt` are not.
  - Both tests check the text, not the property: that the process runs with privileges dropped and never spawns.
- fix: Test the privilege floor through the binary (run as a uid that should be refused, check exit code 77). Express the subprocess ban as a `clippy::disallowed_methods`/`disallowed_types` entry for `std::process::Command`.
- confidence: high

### T-12 `Debug` strings compared as an equality proxy
- severity: info
- kind: test-quality
- rule: RUST_GUIDELINES.md §13 "DON'T: Assert on `Debug` output as a stable format" (3538)
- evidence: `crates/kcc-web/src/page_kit/request.rs:173-176`, `186-188`: `assert_eq!(format!("{:?}", shown_query(&headers)), format!("{expected:?}"));`
- impact: Both sides use one toolchain, so it does not break on upgrades. But a field that `Debug` skips or redacts would be compared as equal.
- fix: Derive `PartialEq` for `TableQuery` in tests, or compare its fields.
- confidence: high

## Coverage
- **Read in full:**
  - Brief and standards: `BRIEF.md`, `docs/BACKLOG.md`, the project overlay, RUST_GUIDELINES §13.
  - Fake router: `crates/kcc-testkit/BEHAVIOUR.md`; testkit `src/lib.rs`, `server.rs`, `server/parse_command.rs`, `failsafe.rs`, `connection_fault.rs`, `inflight.rs`, `config_state.rs`, `time.rs`, `migration.rs`, `capture.rs`, `live_matrix.rs`, `cli_engine/engine.rs`, `cli_engine/rules.rs`, `cli_engine/secrets.rs`, `bin/kcc-fake-router.rs`.
  - Mandated tests: `kcc-domain/tests/bracket.rs`; `kcc/tests/serve_bracket.rs` and `serve_bracket/*`; `kcc-app/tests/audit_multiprocess.rs`; `kcc-web/tests/explorer_pages/bracket*.rs`; `kcc-mcp/tests/support/bracket*.rs`.
  - Live suites: `kcc/tests/live_smoke.rs`, `live_domains.rs` and `live_domains/*`, `live_migration.rs` and `live_migration/*`, `live_presets.rs` and `live_presets/twin.rs`; `kcc-mcp/tests/live_mcp.rs` and `live_mcp/session.rs`.
  - Other: `kcc/tests/source_guards.rs`, `kcc/tests/docs/firmware.rs`.
- **Skimmed** (hits from grep sweeps for sleeps, `{:?}` asserts, secrets, port reservation, `#[ignore]`, statics/env/temp paths, `println!`, `if let Ok`, `include_str!`):
  - `projection.rs` (lines 1-140), `testkit/tests/faults.rs`, `kcc-domain/tests/{users,wifi,wan,vpn_credentials}.rs` and `support/mod.rs`, `kcc-app/tests/{secrets_write,audit,state,poller}.rs`, `kcc-telemetry/tests/{metrics,exporter_follow}.rs`.
  - `kcc/tests/{serve,serve_origin,metrics_serve}.rs`, `cli/health.rs`, `kcc-mcp/tests/support/lab.rs`, `kcc-web/tests/foundation.rs`, `kcc-web/src/page_kit/request.rs` tests, `kcc-rci/tests/session.rs`.
- **Not read** (testkit `src` was not completed in full): `anonymize.rs`, `auth_fixture*.rs`, `components.rs`, `fake_elasticsearch.rs`, `fake_loki.rs`, `fixtures.rs` and `fixtures/synthetic.rs`, `model.rs`, `ndw2.rs`, `ntp.rs`, `tree.rs`, `projection/*`, `cli_engine/{acl_rules,tokens}.rs`, `firmware_update.rs`, `bin/kcc-capture.rs`, `bin/kcc-fake-sinks.rs`; most other `crates/*/tests/**` files beyond the sweep hits.

## Clean
- Fake fail-safe and scheduled-reboot state machine: arm range, keep-alive, expiry handled before connectivity checks, reboot restoring startup and dropping sessions all match BEHAVIOUR.md.
- Fake lock ordering: there are no nested lock inversions across `settings`, `config`, `fail_safe` and `scheduled_reboot`, so no deadlock inside `post()`.
- `FaultInjection` is per instance with no shared statics. `MockClock` is deterministic.
- Shared state between tests: no `static`/`OnceLock`/`set_var` in test code. Temp state comes from `TempDir`, and the capture test path is per-PID.
- Live-suite gating: every `#[ignore]` is on a `live_*` test with the contract reason. Write gates check `test_device` before contacting the router (the hermetic refusal tests prove zero requests). The serial check comes before any read in all target-side gates.
- `serve_bracket` relay and hooks wait on `Notify`/`mpsc` signals with bounded timeouts. The single fixed `sleep(2s)` is the timed behaviour under test.
- `audit_multiprocess` uses a stdin barrier and a holder handshake (`LOCKED` line), not sleeps, and runs on a paused clock.
- `kcc-domain/tests/bracket.rs` matrix: each row asserts fate, armed flag, exact arm/disarm lines and the fake's timer state, so the rows are able to fail.