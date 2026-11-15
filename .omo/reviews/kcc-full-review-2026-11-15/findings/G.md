# Lane G review: kcc-migrate and kcc-telemetry

I found four high-severity issues, all in kcc-migrate:

- **G-01:** a remap is not applied to a source line that carries an `ns3` secret or a WireGuard key.
- **G-02:** saving a preset over an existing id skips the scope check of the preset it replaces.
- **G-03:** after the first management line, every reconnect uses the new password, even before that password has been sent.
- **G-04:** a preset, or a same-realm hash line, can change the password kcc logs in with, and nothing treats it as a management change.

In kcc-telemetry the main problems are in log forwarding:

- **G-08:** a dropped connection discards the batch with no retry.
- **G-09:** there is no HTTP timeout.
- **G-10:** one malformed router record blocks a router's logs.
- **G-11:** router-local timestamps are sent as UTC.

I did not run `cargo` or tests and edited nothing. Every claim below comes from code I opened in this session, and the parts that depend on real router or Loki behaviour are marked INFERRED. I read every source file in scope, but only some of the test files (see Coverage).

---

### G-01 Lines carrying an `ns3` secret or a WireGuard key ignore interface, port and radio mappings
- severity: high
- kind: bug
- rule: project rule (b), spirit (the line sent is not the reviewed mapped line) | none
- evidence: `crates/kcc-migrate/rules/rules.toml:142-161`. The first matching rule wins, and both copy rules come before `remap-mapped-reference`:
  ```
  id = "copy-wireguard-private-key"   match = "interface * wireguard private-key **"  disposition = "copy"
  id = "copy-ns3-secret"              match = "**"  disposition = "copy"  condition = "contains-ns3"
  id = "remap-mapped-reference"       match = "**"  disposition = "remap" condition = "references-mapped-name"
  ```
  `crates/kcc-migrate/src/rules.rs:522-536`: mappings are applied only for `Disposition::Remap`.
  ```
  Disposition::Copy => (Some(redacted_line.to_string()), Some(SecretString::from(line.to_string()))),
  Disposition::Remap => { let mut mapped = line.clone(); ... apply_mappings(&mut mapped.tokens, mappings);
  ```
  The preset planner does map every word, including secret lines (`presets/plan/classify.rs:30-46`), so the two planners now behave differently.
- impact: the operator maps `PPPoE0 → PPPoE1` or `Wireguard0 → Wireguard2`. Every line is remapped except `interface PPPoE0 authentication password ns3 …` and `interface Wireguard0 wireguard private-key …`. Those go to the source-named interface on the target, which is a wrong router command: the credential or key lands on an interface the operator did not choose, and the mapped one has none. Remapped Wi-Fi access-point PSK lines have the same problem. These lines also skip the `scalar-conflict` check, so they silently overwrite a different target secret.
- fix: apply mappings inside `explicit_item` for `Copy` too. A simpler alternative is to move `remap-mapped-reference` (and `scalar-conflict`) above the two copy rules. Add a rules test for an `ns3` line plus a mapping.
- confidence: high

### G-02 Preset capture silently overwrites any existing preset, including one outside the caller's router scope
- severity: high
- kind: security
- rule: overlay mcp-servers.md "authorization per tool / least privilege" | project rule (none specific)
- evidence: `crates/kcc-migrate/src/presets/store.rs:120-129` checks only the scope of the new source, then `save` renames over whatever file exists (`:258-261`):
  ```
  validate_id(&request.id)?;
  authorize_source(role, request.source.router_id.as_deref())?;
  ...
  let _lock = self.state.lock("presets")?;
  fs::write(&temporary, bytes).map_err(PresetError::Io)?;
  fs::rename(&temporary, self.path(&preset.id)).map_err(PresetError::Io)
  ```
  `delete` (`:207-213`), by contrast, reads the existing record and authorizes its `source_router`. The MCP tool derives the id from the name (`crates/kcc-mcp/src/preset_tools/capture.rs:155`: `(slug(&input.name)?, Some(presets.store()?))`).
- impact: an MCP client (possibly prompt-injected) or a Web or CLI user who has `Migrate` only on `lab-*` captures a preset named like an existing `prod` preset. The `prod` preset is destroyed (data loss) and replaced with lab-derived lines. A `prod`-scoped admin who later applies "their" preset pushes foreign configuration. Same-scope overwrites are also silent.
- fix: in `capture`/`save`, refuse when `self.path(id)` exists (`create_new`), or read the existing record and require `authorize_source` on its `source_router`, the same check `delete` does.
- confidence: high

### G-03 The management phase reconnects with the *new* password before that password has been sent
- severity: high
- kind: bug
- rule: none
- evidence: `crates/kcc-migrate/src/apply/preflight.rs:105-109` sets one credential for the whole run:
  ```
  let credential = request.options.management_password.as_ref()
      .map(|password| Credentials::new(original.credentials().login, password.clone()));
  ```
  `apply/reconnect.rs:37-60` uses it after every management line:
  ```
  let password_change = line.expose_command().starts_with("user ");
  ...
  .reconnect(url.clone(), applier.credential.clone()),
  ```
  `planner/diff.rs:14` treats `user <any> password plain` as a management line.
- impact: two cases break.
  - The kcc login `kcc` and the user `admin` both need new passwords (different realm). `user admin …` sorts first and runs first. The reconnect then authenticates as `kcc` with the new password, which is not set yet. That fails for 120 s, then `recover` waits out the timer and the result is `RolledBackByRouter`.
  - The same happens when the management IP line runs before the login's password line. The plan fails every time; the router timer protects the router.
- fix: track the credential per line. Use the old credential until the login's own `user <login> password plain` line has been applied, then switch `applier.credential`.
- confidence: medium (INFERRED: the source line order puts interface lines before user lines; the multi-user case does not depend on order)

### G-04 Changes to kcc's own login password bypass the management safeguards (preset path, same-realm path, Mirror mode)
- severity: high
- kind: bug
- rule: none
- evidence: `crates/kcc-migrate/src/presets/apply/convert.rs:61-65` puts every non-`no` line in `additive`, and `:87` sets `reconnect_url: None`:
  ```
  if matches!(plan.mode, PresetMode::Mirror) && planned.expose_command().starts_with("no ") {
      phases.prune.push(planned);
  } else {
      phases.additive.push(planned);
  ```
  `presets/plan/classify.rs:48-51` rewrites `user X password md5` to `plain <new>`. The `router-users` group includes `user **` (`rules/groups.toml:104`). `preflight.rs:148` (`for line in &request.plan.phases.management`) checks credentials only in the management phase. `planner/diff.rs:14` matches only `password plain`, so a same-realm `user <login> password md5 <hash>` copied by the migration planner after a scalar overwrite is also additive.
- impact: a preset with `router-users` (or a migration with overwrite) changes the password of the account kcc uses. There is no `PasswordRequired` check, no reconnect and no credential update, and the result can be reported verified and committed. After the save, kcc can no longer log in to that router until someone runs `router edit`. In Mirror mode, the target's `user <login> …` lines that are absent from the preset are pruned the same way. INFERRED: if the firmware drops sessions on a password change, the rest of the run fails mid-way.
- fix: run `is_management_line` (extended to `md5|nt` for the login user) in `convert::migration_plan` and in the planner's prune and copy paths, and require `management_password` there as `validate_credentials` does.
- confidence: medium (code path verified; router session behaviour INFERRED)

### G-05 Finish failures report "timer not armed" while the timer is still armed
- severity: medium
- kind: bug
- rule: RUST_GUIDELINES §2 error handling (typed error must carry the right fact)
- evidence: `crates/kcc-migrate/src/apply/finish.rs:32-39`. `commit` deliberately maps a failed context read to `FinishFailed` (armed):
  ```
  .ensure_unchanged().await.map_err(|_error| ApplyError::Drift)?;
  let ctx = context(applier).await.map_err(|_error| ApplyError::FinishFailed)?;
  ```
  `keep_unsaved` (`:61-66`) and `rollback` (`:93`) use plain `context(applier).await?`, which yields `Unreachable` or `Validation`. `Drift` is returned in both paths. `failure.rs:113-133` gives all of these `fate() == None`. Front ends show `fail_safe_armed: error.recovery_armed()` (`crates/kcc-web/src/wizard/finish.rs:232`).
- impact: the operator clicks Keep. A transient `detect()` failure or a concurrent change makes the UI, CLI or MCP report a plain failure with the timer off, while the router timer is still armed. The router then rolls back the changes the operator believed were kept.
- fix: map every pre-close failure in `commit`, `keep_unsaved` and `rollback` (including `ensure_unchanged`) to an armed variant: `FinishFailed`, or a new `Drift`-with-armed fate.
- confidence: high

### G-06 Verification always fails without WAN Internet or without `Bridge0`; the management interface is guessed as "first bridge"
- severity: medium
- kind: bug
- rule: none
- evidence: `crates/kcc-migrate/src/apply/verify.rs:152-174`:
  ```
  if internet.value.get("internet").and_then(serde_json::Value::as_bool) != Some(true) {
      return Err(ApplyError::Verification);
  ...
  if interfaces.value.pointer("/Bridge0/link").and_then(serde_json::Value::as_str) != Some("up") {
  ```
  `inventory.rs:245-248`: `.find(|interface| interface.kind == "Bridge")`.
- impact: pre-staging a replacement router on the bench (no uplink), the typical migration flow, can never reach `verified`. Commit and Keep are refused, and only rollback remains. A router managed through `Bridge1` gets its management-IP change classified as additive (no reconnect), and verification still checks `Bridge0`.
- fix: make the Internet check informational or an explicit option. Derive the management interface from the interface carrying the management URL's address, and check that interface's link.
- confidence: high

### G-07 Prunes run before the management phase and are never classified as management
- severity: medium
- kind: bug
- rule: none
- evidence: `crates/kcc-migrate/src/planner.rs:106-118` pushes operator prunes straight into `phases.prune`, with no `is_management_line`. `execute.rs:40-47,100`: additive and prune lines run first, then `management(...)`. `convert.rs:61-62` handles Mirror removals the same way.
- impact: the source changes the LAN IP. The operator (or the Web residual list) prunes the old `interface Bridge0 ip address 192.168.1.1 …`, which is a residual target line. It runs before the new IP is set, so kcc cuts itself off. The next submit fails with `Workflow` (fate `None`, see G-05) instead of recovering, and the router rolls back later.
- fix: classify prune lines with `is_management_line` (including `no` forms) and refuse them, or move them into the management phase after the replacement line.
- confidence: medium

### G-08 Log-sink transport errors are not retried; the batch is dropped as "permanent"
- severity: medium
- kind: bug
- rule: none
- evidence: `crates/kcc-telemetry/src/logs/sink.rs:290-305`:
  ```
  Self::Status { status, retry_after: _ } => status.as_u16() == 429 || status.is_server_error(),
  ...
  | Self::Transport
  | Self::PartiallyAccepted { rejected: _ } => false,
  ```
  `pipeline_delivery.rs:216-219` then calls `dropped(worker, batch.len())`. `elastic_sink.rs:188` treats `Delivery(_)` the same way.
- impact: any Loki or Elasticsearch restart, connection reset or DNS blip permanently loses up to 1,000 records per batch. The retry and backoff machinery covers only HTTP 429 and 5xx.
- fix: treat `Transport` (and `BulkError::Delivery(Transport)`) as retriable.
- confidence: high

### G-09 No HTTP timeout and unbounded retries: a stuck sink stalls the worker, and shutdown aborts records without counting them
- severity: medium
- kind: bug
- rule: overlay http-services.md "timeouts on every outbound call"
- evidence: `sink.rs:76` and `elastic_sink.rs:76`: `Client::builder().redirect(Policy::none())`, with no `.timeout`/`.connect_timeout`. `pipeline_delivery.rs:199-209` loops `loop { match client.send(batch).await { … Err(error) if error.is_retriable() => { … continue` with no attempt cap and no cancellation check. `pipeline.rs:91-101`: after 10 s, `task.abort()`.
- impact: a sink that accepts the TCP connection but never answers, or keeps answering 503, blocks that worker forever while the queue overflows. On shutdown the in-flight batch and the queue are aborted, and none of them reach `kcc_log_records_dropped_total`, so loss counting is incomplete.
- fix: set request and connect timeouts on both clients. Select `worker.cancellation.cancelled()` against `clock.wait` and `send`. On abort, count the pending and in-flight records as `dropped{reason="shutdown"}`.
- confidence: high

### G-10 One malformed router log record silently blocks all forwarding for that router
- severity: medium
- kind: bug
- rule: RUST_GUIDELINES §2 (swallowed errors)
- evidence: `crates/kcc-telemetry/src/logs/service.rs:285-287`:
  ```
  let Ok(records) = parser::parse_records(&collection.router, value, now) else {
      return;
  };
  ```
  `parser.rs:42-48` collects with `?`, so one bad entry (a non-numeric key, or a message without the `[Mon dd hh:mm:ss] ` prefix) fails the whole response.
- impact: none of the records in a failing response pass dedupe, so every poll or stream read returns the same bad record and drops the whole batch again. Forwarding for that router stops until the record leaves the router's 200-line window. Nothing is logged and no metric counts it.
- fix: parse per record, skip and count the bad ones (`log_records_dropped("collector","parse")`), and keep the rest.
- confidence: high

### G-11 Router-local log timestamps are stamped as UTC
- severity: medium
- kind: bug
- rule: none
- evidence: `service.rs:280-284`:
  ```
  let utc: DateTime<Utc> = SystemTime::now().into();
  let Some(offset) = FixedOffset::east_opt(0) else { return; };
  let now = utc.with_timezone(&offset);
  ```
  `parser.rs:130` (`local_datetime(router_now, …)`) builds bracket timestamps in `router_now`'s offset. `types.rs:13` says "Timestamp interpreted in the router timezone". The unit test (`tests/logs.rs:60`) passes a +03:00 `now` that production never supplies.
- impact: for a router at UTC+3, every record is sent 3 h in the future (INFERRED: Loki then rejects these as "too far in the future", and Elasticsearch stores the wrong `@timestamp`). Year inference near midnight on New Year's is also off by the offset.
- fix: obtain the router's UTC offset (for example from `show clock date`) per collector and pass it to `parse_records`. Otherwise label the field "naive local time" and do not claim UTC.
- confidence: medium (INFERRED: the firmware sends no `time` member)

### G-12 Log-collector shutdown waits out uncancellable sleeps, one router after another
- severity: medium
- kind: bug
- rule: RUST_GUIDELINES §5 "Use `tokio::select!` for cancellation" (1136); KNOWN-BACKLOG (likely the cause of BACKLOG "Known gaps": exit about 4.4 s after "jobs drained")
- evidence: `service.rs:201` `time::sleep(collection.poll_interval).await;` (default 30 s), `:226`, `:236`, `:255` `time::sleep(collection.stream_interval).await;` (minimum 5 s), all outside `select!`. `runtime.rs:114-116` shuts collectors down one after another:
  ```
  for (_, collector) in mem::take(&mut self.collectors) {
      drop(collector.shutdown().await);
  ```
- impact: `kcc serve` (`crates/kcc/src/server.rs:213`) takes up to about 5 s × routers to shut down in stream mode, and up to 30 s × routers in poll mode or after the stream falls back to polling.
- fix: wrap each sleep in `select!` with `cancellation.cancelled()`, and cancel all collectors before awaiting them (`join_all`).
- confidence: medium (latency verified; link to the BACKLOG symptom INFERRED)

### G-13 Batch selection re-encodes the whole batch for every record while holding the queue's std `Mutex`
- severity: medium
- kind: guideline
- rule: RUST_GUIDELINES §5 "Use `yield_now()` in CPU-bound async loops" (1183) / "DON'T hold locks …" (1147)
- evidence: `pipeline_delivery.rs:157-162`:
  ```
  let mut queue = lock(&worker.queue);
  while batch.len() < MAX_RECORDS {
      let Some(record) = queue.pop() else { break };
      batch.push(record);
      match worker.sink.encoded_len(&batch) {
  ```
- impact: up to about 500,000 record serializations (O(n²)) per 1,000-record batch run on a runtime worker thread. Meanwhile every relay's `push` blocks on the same std mutex and stalls its executor thread during log bursts.
- fix: add each record's encoded size incrementally (plus a fixed envelope), and pop the batch under the lock but measure it outside.
- confidence: high

### G-14 Shipped but unused public APIs bypass the configured outbound policy and allow loopback
- severity: medium
- kind: dead-code
- rule: project rule (a) "Outbound requests go only to registered router profiles that pass the router outbound policy"
- evidence: `crates/kcc-migrate/src/source.rs:130-134`:
  ```
  let options = RciClientOptions::default()
      .with_outbound(OutboundPolicy::default().with_loopback(true));
  let client = RciClient::connect_with(profile.router.clone(), profile.credentials.clone(), options)
  ```
  `inventory.rs:57-60` is the same for `InventoryClient::connect`. `OutboundPolicy::default()` allows all of RFC 1918 and 100.64/10 (`kcc-rci/src/outbound.rs:100-105`), while the operator's `allowed_networks` defaults to empty. Grep finds no production caller of `load_source`, `MigrationSource`, `SourceConfig::from_live` or `InventoryClient::connect` (the last is used only in tests).
- impact: the first front end that wires these up contacts any private or loopback address regardless of `[outbound]`.
- fix: delete `MigrationSource`, `LiveRouterProfile`, `load_source` and `from_live`. Move `InventoryClient::connect` into test support, or make it take the registry's policy-checked client.
- confidence: high

### G-15 Migration reports contain no command text at all, and the HTML/Markdown skeleton is English-only
- severity: low
- kind: anti-pattern
- rule: project rule (f) "Every user-visible string comes from kcc-i18n"
- evidence: `planner/types.rs:146-151`: `before: "<redacted>".to_owned(), after: item.after.as_ref().map(|_line| "<redacted>".to_owned())`. That makes `report.rs:176-178` (`line.replace("ns3 <redacted>", "<redacted>")`) dead. `report.rs:156` hardcodes `lang="en"`, "Migration report", "Counts", "Items", "Residual target settings", and `to_markdown` (`:101-117`) does the same. `convert.rs:88-90` gives preset plans `items: Vec::new()`, so the MCP preset report is empty. `verify.rs:83-86` fills `residual` with identical `"<redacted>"` strings.
- impact: the Web download, CLI `migrate --report` and MCP report list every line as `<redacted> → <redacted>`, even though `ClassifiedItem.before`/`after` already hold properly secret-redacted text. Non-English users get English headings.
- fix: copy `item.before`/`item.after` (already redacted by `redact` and `redact_ns3`) into `PlanItem`, and localize the template strings.
- confidence: high

### G-16 `kcc_metrics_series_dropped_total` grows per scrape, not per event
- severity: low
- kind: bug
- rule: none
- evidence: `metrics/collector.rs:106-108`:
  ```
  let newly = shared.render(router, cached, now);
  let total = dropped.entry(router.clone()).or_default();
  *total = total.saturating_add(newly);
  ```
  The help text says "summed over scrapes" (`catalogue.rs:357`).
- impact: with 10 clients over the cap, two Prometheus servers scraping every 15 s add 80 per minute. `rate()` measures scrape frequency, not dropped series. Entries are never removed on `unwatch`.
- fix: export the current drop count as a gauge (`kcc_metrics_series_dropped`).
- confidence: high

### G-17 The per-client pseudonym map grows without bound and is shared across routers
- severity: low
- kind: bug
- rule: project rule (i) "No stored client telemetry history"
- evidence: `metrics/clients.rs:180-185`:
  ```
  let next = pseudonyms.len().saturating_add(1);
  pseudonyms.entry(mac.to_owned()).or_insert_with(|| format!("client-{next}")).clone()
  ```
  Nothing ever removes entries (`collector.rs:44-45`).
- impact: every MAC ever seen, including randomized phone MACs and those of guest networks, stays in memory for the life of the process. That is an unbounded, process-lifetime client history driven by LAN input.
- fix: keep pseudonyms only for MACs present in the current snapshot (rebuild each scrape), or hash the MAC with a per-process key.
- confidence: high

### G-18 `keenetic_interface_up` carries the free-text interface description as a label
- severity: low
- kind: anti-pattern
- rule: none
- evidence: `metrics/interfaces.rs:35-43`: `&[router, id, kind, text(entry, "description").unwrap_or_default()]`.
- impact: renaming an interface's description creates a new series and resets alert `for:` timers. Arbitrary text (which may contain personal data) becomes a label.
- fix: move `description` to an info-style family.
- confidence: high

### G-19 The `kcc_jobs` gauge drifts on broadcast lag
- severity: low
- kind: bug
- rule: none
- evidence: `metrics/instrumentation.rs:197`: `Err(RecvError::Lagged(_)) => continue,`. `:237-239`: only `running` is tracked in `known`.
- impact: if a job's terminal event is lagged, the `running` gauge stays +1 forever and the `known` entry leaks.
- fix: on `Lagged`, re-read every `known` id from `jobs.get` and settle its state.
- confidence: medium

### G-20 Wrong or missing cancel-safety annotations
- severity: low
- kind: guideline
- rule: RUST_GUIDELINES §5 "Annotate every async fn with cancel safety" (1188); KNOWN-BACKLOG pattern (these locations are not in the BACKLOG list)
- evidence: `apply/finish.rs:134` says `// cancel-safe: waiting and recovery probes do not mutate the router.`, but `recover` calls `wait_restored`, which `:149` marks `// NOT cancel-safe: the local credential is restored …`, and it sets `report.finished`.
  Annotations are missing on:
  - `apply/verify.rs:95` (`collect_wireguard_public_keys`)
  - `apply/preflight.rs:132` (`validate_credentials`)
  - `logs/service.rs:241` (`consume_stream`) and `:264` (`snapshot`)
  - `logs/pipeline_delivery.rs:135,189,197,225`
  - `metrics/service.rs:146` (`follow`)
- impact: wrapping `recover` in a timeout on the strength of its comment would leave the connection half-restored.
- fix: correct the `recover` comment to NOT cancel-safe and add the missing annotations.
- confidence: high

### G-21 Copy-paste duplication that has already drifted
- severity: low
- kind: duplication
- rule: none
- evidence:
  - `replace_password` exists twice with different semantics: `rules.rs:693-711` keeps `Ns3` tokens, while `presets/plan/classify.rs:145-150` always writes a `Word`.
  - `words()` is identical in `presets/selection.rs:129-138` and `presets/plan/classify.rs:165-174`.
  - The MD5-hex helper exists three times: `apply/verify.rs:190-196`, `planner/diff.rs:76-82`, `source.rs:257-260`.
  - The reconnect loop exists four times with different bounds: `finish.rs:151-167`, `raw.rs:146-161` (timeout plus 120 tries), `reconnect.rs:50-78` (clock budget) and `components.rs:83-106` (120 tries with no overall timeout).
  - `Catalog::for_router(&client.detect()…)` is repeated in `execute.rs:33-39` and `:182-188`, `finish.rs:120-126` and `preflight.rs:190-196`, which means one extra `show version` per keep-alive.
  - `LokiClient::load` and `ElasticsearchClient::load` share the CA, client and `install_default` block (`sink.rs:76-87`, `elastic_sink.rs:76-87`).
  - The `lock()` helper exists three times: `pipeline.rs:206`, `pipeline_delivery.rs:289`, `collector.rs:55`.
- impact: fixes land in one copy only. G-01 and G-04 are already examples of the two classifiers diverging.
- fix: extract one helper for each and reuse it.
- confidence: high

### G-22 `PresetStore` duplicates a method and does blocking file and crypto I/O on async handlers
- severity: low
- kind: guideline
- rule: RUST_GUIDELINES §5 "DON'T: Call blocking I/O in async functions" (1112)
- evidence: `presets/store.rs:194-199` (`load_for_apply`) and `:225-230` (`get_for_apply`) are byte-identical. `capture`, `list` and `save` use `std::fs` and decrypt every record (`:142-160`), and are called from async code: `kcc-mcp/src/preset_tools/capture.rs:190-193` (same fn awaits at `:157`) and `kcc-web/src/presets_page/compose.rs:148`. One malformed record also makes `list` fail for everyone.
- impact: this stalls executor threads on slow disks, and one corrupt file breaks the preset list.
- fix: drop one of the two methods, call the store through `spawn_blocking` (or `tokio::fs`), and skip and log bad records in `list`.
- confidence: high

### G-23 The `ContinueOnNonCritical` retry path is test-only, and its Indeterminate case is not recovered
- severity: low
- kind: dead-code
- rule: none
- evidence: grep finds `StopPolicy::ContinueOnNonCritical` only in `tests/support/apply_policy.rs` and `apply_secrets.rs`. `execute.rs:161-170` ignores `ReplayOutcome::Indeterminate` on retry (the line just stays in `failed`, giving `Stopped`), while the main loop at `:81` calls `finish::recover`.
- impact: this is a shipped option no front end can select, and its unknown-outcome handling differs from the main path.
- fix: remove it, or wire it up and match the outcome the same way as the main loop.
- confidence: high

### G-24 The Loki `level` stream label comes straight from untrusted router input
- severity: low
- kind: security
- rule: none
- evidence: `logs/parser.rs:73-76` (`.map_or_else(|| level_from_label(label.as_deref()), normalize_level)`, which only lowercases) feeds `format.rs:62` (`"stream": {"job": "keenetic", "router": router, "level": level}`).
- impact: a router or LAN device writing arbitrary `level` values creates unbounded Loki streams.
- fix: map `level` to a fixed set (error, warning, info, debug, other).
- confidence: medium

### G-25 Test quality: real bugs above have no tests, and some test code is noise
- severity: low
- kind: test-quality
- rule: RUST_GUIDELINES §13
- evidence:
  - `tests/logs.rs:58-88` checks the parser with a +03:00 "now" that production never passes (G-11).
  - Nothing tests a malformed record inside a batch (G-10), transport-error retry (G-08), or `ns3` plus mapping in `tests/rules.rs:448-455` (G-01).
  - `tests/finish_recovery.rs:60,81,119,160` hide a password from scanners with `['a','d','m','i','n'].into_iter().collect()`.
  - `#[tokio::test]` functions carry `// NOT cancel-safe:` comments (`finish_recovery.rs:72,108,151,185`).
  - `matrix_run.rs:123` drops `user ` lines from the committed-line check, so management password lines are never verified in the matrix.
- impact: the high and medium bugs above are untested, and the noise hides that.
- fix: add the four missing scenarios, use `kcc_testkit::DEFAULT_PASSWORD`, and remove the cancel-safety comments from tests.
- confidence: high

## Coverage
- **Read in full:**
  - kcc-migrate src: every file under `crates/kcc-migrate/src/**` except `planner/buildability_tests.rs`, plus `rules/rules.toml` and `rules/groups.toml`.
  - kcc-telemetry src: every file under `crates/kcc-telemetry/src/**`.
  - kcc-migrate tests: `tests/apply.rs`, `tests/finish_recovery.rs`, `tests/preset_apply.rs`, `tests/matrix.rs`, `tests/support/matrix_run.rs`.
  - kcc-telemetry tests: `tests/logs.rs`, `tests/logs/pipeline.rs`, `tests/logs/retry.rs`, `tests/logs/transport.rs`, `tests/monitoring.rs`, `tests/support/settle.rs`.
  - Out of lane, for context: `kcc-app/src/workflow_cli/command.rs`.
- **Skimmed (grep or partial):** `tests/exporter_follow.rs` (lines 185-218), `tests/metrics.rs` (sleep and paused-time grep), `tests/rules.rs` (`ns3` and WireGuard grep); outside the lane, `kcc-rci` `engine.rs` (`show`, `retarget`, `connect_with`, `session`), `outbound.rs` (`Default`), `kcc-app` `settings.rs` (`LogsConfig` default, `LogMode`) and `jobs.rs` (`JobStatus`), and the MCP and Web preset capture callers.
- **Not read:**
  - kcc-migrate test files: `planner.rs`, `bridge_members.rs`, `presets.rs`, `preset_plan.rs`, `preset_transient.rs`, `inventory.rs`, `planned_classification.rs`.
  - kcc-migrate test support: `apply_*.rs` other than `apply_fixture` usage, plus `matrix_cases.rs`, `matrix_source.rs`, `matrix_snapshot.rs`, `state_scan.rs`.
  - Other: `planner/buildability_tests.rs`, `kcc-telemetry/examples/metric-docs.rs`.

## Clean
- `ApplyError`: an exhaustive `fate`/`message_key`, stable serde names, `from_name` round-trip, and a unit test that is exhaustive over rows.
- `command::build`: one-line parse, refusal of `system configuration|reboot` and `components commit`, `ObjectName` checks, and secret arms that validate through the catalog with the line kept in `SecretString`.
- Preflight order: authorization, then source, then the tier gate, then firmware order, then drift (startup MD5, running digest, last-change), then a dry build of every line, all before arming. An arm whose result was lost is disarmed (`settle.rs`).
- `Debug` redaction for `ClassifiedItem`, `Preset`, `PresetPlanItem`, `PresetApplyRequest`, `LokiClient`/`ElasticsearchClient`/`Auth`, and `CliCommand`.
- Preset encryption at rest (AAD bound to the id, `deny_unknown_fields`, id and source-router cross-check on open) and the file-safe id validator.
- Preset apply authorizes both source and target scopes before contacting any router.
- Mode-specific rollback permission (`Migrate` for a failed run, the control permission for a verified run), matching the owner decision.
- Log queue bound with oldest-first eviction counted as `overflow`, the Loki partial-refusal parser (bounded body, overflow-safe), and the MAC redactor (bounds-checked, no panic).
- `LogFeed` holds a `WeakSender`, so relays end cleanly. The dedupe window is bounded.
- The scrape collector never calls a router, the per-client cap is enforced, the default label is a pseudonym, staleness gating works, and non-finite or negative counter values are skipped.