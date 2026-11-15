## Lane E: kcc-mcp review (read-only)

I read all of `crates/kcc-mcp/src/**`, `tests/**` and `examples/**`, plus the overlays, BACKLOG and the rmcp/kit sources the findings depend on. I made no edits and ran no `cargo`. There are 24 findings: 2 high, 10 medium, 11 low, 1 info.

### E-01 MCP secret redaction is a weaker, separate denylist from the Web and kcc-config ones, and it skips text bodies
- severity: high
- kind: security
- rule: project rule (d); overlay mcp-servers.md "Tool inputs are untrusted" / core §10
- evidence: `crates/kcc-mcp/src/support/shape.rs:211-226`
  ```rust
  if [ "password","passwd","token","secret","api_key","private_key","ns3","psk","preshared" ]
      .iter().any(|needle| lowered.contains(needle))
  ```
  Compare `crates/kcc-web/src/page_kit/secret.rs:15-29`, which uses `EXACT = ["key","psk","pin",...,"community"]` and `SUFFIXES = ["-key", ...]`. The catalog argument names are `"key"` (`interface iapp key`) and `"private-key"` (`interface wireguard private-key`), checked in `catalog/5.1/interface.json:7010,22353`. kcc-config treats both as secrets (`crates/kcc-config/src/secrets.rs:76-79`). Text bodies go out unredacted: `crates/kcc-mcp/src/support/errors.rs:122` `RciBody::Text(text) => json!({ "text": text, ...})`. `show running-config` is a catalog `Show` command (`catalog/5.1/show.json:7812`), and `kcc_rci_read` is in the default `core` toolset with `Permission::Read` (`registry/definitions.rs:116-122`). Only the backup diff uses `redact` plus the ns3 mask (`config_tools/backups.rs:157-173`).
- impact: An agent with a viewer key calls `kcc_rci_read {catalog_path:"show running-config"}` or reads a WireGuard/IAPP setting. It gets the `ns3` blobs, the `wireguard private-key` value, the `iapp key` and plaintext lines such as `web-api password`, none of which go through `RevealSecrets`. The same read in the Web explorer is masked.
- fix: Move one secret-name classifier (Web's `is_secret`) into a shared crate and use it in `redact_secrets`. Run text and `message` line arrays through `kcc_config::secrets::redact` plus the ns3 mask, or refuse `show running-config` in `rci_read`.
- confidence: high for the code gap. The exact real-router answer shapes are INFERRED: the fake serves no `show running-config` (`tests/support/raw_paths.rs:201-202`).

### E-02 `kcc_preset_capture` overwrites any stored preset by name slug, skipping the source-scope check
- severity: high
- kind: security
- rule: overlay http-services authz; project scope model
- evidence: `crates/kcc-mcp/src/preset_tools/capture.rs:152-156,190-193`
  ```rust
  (slug(&input.name)?, Some(presets.store()?))
  ...
  let stored = store.capture(&identity.role, &config.ast, request)
  ```
  `crates/kcc-migrate/src/presets/store.rs:120-129`: `capture` authorizes only the new source and then calls `self.save(&preset)`. `save` at `:259-261` does `fs::rename(&temporary, self.path(&preset.id))` with no existence or ownership check. `delete` at `:210-211` does check the existing record's `source_router`. The Web uses random ids (`kcc-web/src/presets_page/compose.rs:127` `fresh_id(now)`).
- impact: A `lab-*` identity with `Migrate` captures `{"source":"lab-src","name":"Office",...}` and silently replaces the `office` preset that an admin captured from `prod-1`. A later `kcc_preset_apply office` on prod then pushes lab settings to prod, and prod-scoped users lose the preset. This is a write to an out-of-scope object that `delete` would refuse.
- fix: Have `PresetStore::capture` refuse an existing id (or require the old record's source scope plus an explicit replace flag). In MCP, either give the slug a random suffix or return `conflict` when the id exists.
- confidence: high

### E-03 An applied migration or preset holds the router write lease indefinitely, and records are never evicted
- severity: medium
- kind: bug
- rule: core §5 "Audit Drop impls of async resources"; BRIEF item 1 (unbounded growth)
- evidence: `crates/kcc-mcp/src/migration_tools/state.rs:38-39,69-74,177-190`
  ```rust
  /// Lease retained for commit or rollback.
  applier: Option<Applier>,
  ...
  if self.owner != identity.name { return Err(McpFailure::Forbidden); }
  ...
  drop(entries.insert(key, migration));
  ```
  There is no `remove` anywhere in `migration_tools/` (grep). `Applier.changes` is "Exclusive write lease retained through explicit finishing" (`kcc-migrate/src/apply.rs:70-71`), backed by a file lock with no expiry (`kcc-app/src/persist.rs:277-282`). Transient presets (`preset_tools/state.rs:63-71`) are removed only by an explicit delete.
- impact: An agent (or a built-in operator, which cannot roll back) applies and then stops. Every Web, CLI and MCP write to that router gets `RouterBusy`/`conflict` until `kcc serve` restarts. Only the same identity can finish, and an admin cannot. Each `kcc_migration_plan` call with different `exclude` sets adds an entry that keeps a whole `MigrationPlan` (secret buffers) in memory for the life of the process.
- fix: Give records a TTL tied to the armed timer: after the router's timer window, close and drop the `Applier`. Evict unapplied plans by age and count. Allow a `Destructive` holder on the target to finish another identity's migration.
- confidence: high

### E-04 Result truncation replaces the whole payload, including error codes and fail-safe messages, and returns a meaningless cursor
- severity: medium
- kind: bug
- rule: overlay mcp-servers.md (result caps); BRIEF item 1
- evidence: `crates/kcc-mcp/src/support/shape.rs:191-203`
  ```rust
  if encoded.len() <= cap { return Ok(encoded); }
  let truncated = json!({ "truncated": true, "next_cursor": "1", "request_id": request_id });
  ```
  The failure path shapes the error reply through the same function (`:132-134`). The default cap is 32 KiB (`kcc-app/src/settings.rs:202`).
- impact: A confirmed 64-item `kcc_rci_batch` whose disarm fails returns `BatchFailSafeArmed` with every response included. If that is over 32 KiB, the agent gets `is_error` with no `error` code, no `management_applied_fail_safe_armed` message and no per-item outcomes. A successful large write loses `unsaved`, `persists_immediately`, `audit_pending` and the notice. `"next_cursor":"1"` is meaningless for tools without a cursor (`rci_read`, `backup_diff`), and on paged tools it advances by one item.
- fix: Always keep `error`, `message`, `field`, `unsaved`, `persists_immediately` and `audit_pending`, and truncate only the bulky array. Emit a real next offset only for tools that take `cursor`.
- confidence: high

### E-05 `redact_clients_in_mcp` misses client names, free text and progress notifications
- severity: medium
- kind: security
- rule: project rule (i) "MCP honours `redact_clients`"
- evidence: `crates/kcc-mcp/src/support/shape.rs:271-278`
  ```rust
  ["mac", "hostname", "host_name", "ip", "address"]
      .iter().any(|needle| lowered.contains(needle))
  ...
  key_match || looks_like_mac(value)
  ```
  The client model's registered name field is `name` (`kcc-domain/src/clients.rs:38`). `domains/write/jobs.rs:70-74` sends `JobProgress::OutputLine(line)` straight to `progress.notify`, outside `shape()`. Arping lines carry `mac` and `address` (`kcc-domain/src/diagnostics.rs:94-98`).
- impact: With redaction on, `kcc_clients_read` still returns names such as "Anna's iPhone". System log lines (`kcc_diagnostics_read`) and CLI text bodies still contain raw MACs and IPs. An `arping` call with a progress token streams client MACs unredacted.
- fix: Add `name` under client objects. Scrub MAC and IP patterns inside strings. Pass progress messages through the same pseudonymizer.
- confidence: high

### E-06 The global migrations mutex is held across router commit and rollback
- severity: medium
- kind: anti-pattern
- rule: core §5 "DON'T: Hold locks across .await" (design scope)
- evidence: `crates/kcc-mcp/src/migration_tools/finish.rs:66,83-94,103`
  ```rust
  let mut entries = server.migrations.lock().await;
  ...
  applier.commit().await
  ...
  applier.rollback().await
  ...
  drop(entries);
  ```
- impact: While one router's commit or rollback runs (save, disarm, or a reboot-wait rollback on an extender), every other `kcc_migration_*`/`kcc_preset_apply` call for every router and identity waits on this lock. `reviewed()` (`apply.rs:94`), `report` (`finish.rs:114`) and `record` (`state.rs:178`) all take it.
- fix: Wrap each `Migration` in `Arc<tokio::sync::Mutex<…>>`. Take the map lock only to clone the entry handle, then lock the entry for the I/O.
- confidence: high

### E-07 Every interface write failure becomes `conflict`, losing `verification_failed` and its field
- severity: medium
- kind: bug
- rule: project rule (c); the documented error contract (`registry/docs.rs:44-47`)
- evidence: `crates/kcc-mcp/src/domains/write/interfaces.rs:143-150`
  ```rust
  interfaces::apply(changes, ctx, &name, &operation)
      .await
      .map_err(|error| {
          tracing::warn!(error = ?error, "MCP interface change failed");
          McpFailure::Conflict
      })
  ```
- impact: A `description` or `security_level` change the router accepts but does not apply returns `conflict` with no `field`, and so do forbidden, unreachable and rejected outcomes. The test hides it: `tests/support/interface_refusals.rs:71-73` only checks `reply.error().is_some()`.
- fix: Expose a mapping accessor on `InterfaceChangeError` (Domain/Workflow) and route it through `map_domain`/`map_workflow`.
- confidence: high

### E-08 Several successful MCP actions are not audited, although the Web and CLI audit the same actions
- severity: medium
- kind: security
- rule: project change and audit model (README "Safety model"); BRIEF item 2
- evidence: `crates/kcc-mcp/src/config_tools/backups.rs:82-87`
  ```rust
  let info = server.workflow.backups().create(router.as_str(), "mcp", &text)
      .map_err(|error| map_backup(&error))?;
  Ok(json!({ "name": info.name, ... }))
  ```
  The other unaudited paths are `generic/fleet.rs:216-220` (`job_cancel`), `preset_tools/capture.rs:190-207` and `preset_tools/manage.rs:70-76` (preset capture and delete), and `domains/write/jobs.rs:131-143` (diagnostic job start). The other front ends audit: CLI `kcc/src/cli/persist.rs:241-247` (`"cli.backup_create"`), Web `config_page/create.rs:71`, `advanced/jobs.rs:207` (`"web.explorer_job_cancel"`) and `presets_page/compose.rs:133-136` (`"web.preset_capture"`). `support/audit.rs` covers failures only.
- impact: An agent can create backups, cancel another user's migration job, and overwrite or delete presets (see E-02) with no trace in `audit.jsonl`.
- fix: Append a success `AuditEvent` on these paths, as the Web/CLI equivalents do.
- confidence: high

### E-09 Logged failure causes cannot be tied to the `request_id` returned to the client
- severity: medium
- kind: guideline
- rule: overlay mcp-servers.md "Errors on the wire": "cause is logged server-side with enough context to correlate the two, for example a request id"
- evidence: `crates/kcc-mcp/src/support/shape.rs:61-65`
  ```rust
  let request_id = format!("mcp-{}", NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed));
  match result.and_then(|value| shape(server, value, Some(&request_id))) {
      ...
      tracing::warn!(request_id, code = error.code(), "MCP tool request failed");
  ```
  The causes are logged earlier with no id, tool or router: `support/errors.rs:49,70`. rmcp runs the handler under the loop span with no per-request span (`rmcp-3.9.0/src/service.rs:1606-1630`).
- impact: With concurrent calls, the operator cannot match the logged cause to the `request_id` the client saw.
- fix: Mint the id in `route()` / the `#[tool]` wrappers before the work and open a `tracing::info_span!("mcp_tool", request_id, tool)` around it.
- confidence: high

### E-10 Crate-root `#![expect]` blankets 8 clippy lints plus private-item docs
- severity: medium
- kind: guideline
- rule: AGENTS.md "No `#[allow]` … `#[expect]` on the narrowest item"; BRIEF item 4
- evidence: `crates/kcc-mcp/src/lib.rs:6-16`
  ```rust
  #![expect(
      clippy::absolute_paths, clippy::arithmetic_side_effects, clippy::missing_errors_doc,
      clippy::missing_inline_in_public_items, clippy::multiple_inherent_impl,
      clippy::needless_pass_by_value, clippy::shadow_reuse, clippy::too_many_arguments,
      reason = "RMCP adapters contain schema-only private types ..."
  )]
  ```
  `:17-23` does the same for `missing_docs_in_private_items`. No other crate root does this (grep).
- impact: Any new unchecked arithmetic anywhere in the crate passes silently. For example, `generic/fleet.rs:155` `(offset + limit).to_string()` uses a user-controlled offset.
- fix: Move each expectation to the specific item that triggers it, and use `checked_add`/`saturating_add` at fleet.rs:155.
- confidence: high

### E-11 About 70 async fns have no cancel-safety annotation, including mutating handlers
- severity: medium
- kind: guideline
- rule: core §5 "DO: Annotate every async fn with cancel safety" (`RUST_GUIDELINES.md:1188-1237`)
- evidence: The unannotated fns include `domains/write/wifi.rs:114`, `clients.rs:210,224`, `interfaces.rs:105,189`, `services.rs:185`, `dns.rs:175`, `housekeeping.rs:138`, `jobs.rs:101,147`, `config_tools/state.rs:39` (`config_save`), `config_tools/backups.rs:65`, `migration_tools/apply.rs:119,168`, `migration_tools/finish.rs:62`, `preset_tools/apply.rs:39`, `preset_tools/capture.rs:132`, `preset_tools/manage.rs:62` and `support/access.rs:78,91,102`. 71 in total, counted with awk over `src/`.
- impact: These write the router or state and carry no stated contract. BACKLOG names only 10 such fns in other crates; `xtask cancel-safety` checks `pub` items only.
- fix: Add `// NOT cancel-safe:` / `// cancel-safe:` comments and extend the xtask to `pub(crate)` and private items.
- confidence: high

### E-12 The `fields` projection argument is accepted and validated but never applied
- severity: low
- kind: dead-code
- rule: core §8 API design; overlay "tool inputs" (schema honesty)
- evidence: `crates/kcc-mcp/src/support/shape.rs:174-183`
  ```rust
  let fields = value.get("fields").and_then(Value::as_array).map(|items| { ... });
  if let Some(selected) = fields { project(&mut value, &selected); }
  ```
  It reads `fields` from the **output** value. The inputs `ListInput.fields`, `CatalogSearchInput.fields` and `RciReadInput.fields` (`generic/fleet.rs:39-41,58-60`, `generic/rci.rs:57-59`) are validated and dropped, and no tool puts `"fields"` into its result (grep).
- impact: Agents asking for projections get full payloads, which then hit truncation (E-04). A router answer with a top-level `fields` key would be pruned unpredictably.
- fix: Remove `fields` from the schemas and from `shape`, or pass the parsed input into `shape` and project the result's item arrays.
- confidence: high

### E-13 The pseudonymizer over-matches on the substring "ip", and its map grows without bound
- severity: low
- kind: bug
- rule: none (correctness, unbounded growth)
- evidence: `crates/kcc-mcp/src/support/shape.rs:258-264,274-276`
  ```rust
  Value::String(text) if client_identifier(parent_key, text) => {
      let next = pseudonyms.len().saturating_add(1);
  ...
  ["mac", "hostname", "host_name", "ip", "address"]
  ```
  `pseudonyms` is one process-wide map (`lib.rs:244`, `generic/router.rs:85`).
- impact: `"description"` contains "ip", so interface, system and policy descriptions and every JSON Schema `description` in `kcc_catalog_describe` and catalog resources become `client-N`. NAT session pages add thousands of permanent map entries.
- fix: Match whole key tokens (`key == "ip"` or split on `-`/`_`), and bound or session-scope the map.
- confidence: high

### E-14 Tool metadata and helper logic are duplicated and can drift
- severity: low
- kind: duplication
- rule: BRIEF item 4 (copy-paste duplication)
- evidence:
  - Generic tool name, description and hints are written twice. `generic/router.rs:247-255` repeats `description = "Apply a catalog-validated raw RCI mutation without saving; ..."` with the annotations, and `registry/definitions.rs:137-141` repeats the same text. The wire annotations come from one copy; the docs and RBAC come from the other.
  - The ns3 `mask`/`redacted` code is duplicated three times: `config_tools/backups.rs:157-173`, `kcc-web/src/config_page/text.rs:64-81` and `kcc/src/cli/redact.rs:45-66`.
  - `tier_name` (`migration_tools/plan.rs:128-134`) duplicates `generic/fleet.rs:118-122`.
  - The progress-message mapping in `domains/write/jobs.rs:70-73` duplicates `migration_tools/apply.rs:212-216`.
  - `registry.get(..).profile.login` appears three times: `services.rs:208-213,217-222` and `vpn_servers.rs:138-143`.
- impact: Editing one copy changes the wire annotations without changing the docs, or changes the backup-diff redaction without changing the CLI download.
- fix: Generate `#[tool]` metadata from `generic()` (or register generic tools through `route()`), and share the ns3 mask from `kcc-config`.
- confidence: high

### E-15 Stringly-typed dispatch with wildcard fallbacks binds unknown names to real handlers
- severity: low
- kind: anti-pattern
- rule: core §3 "Use exhaustive match / enums instead of strings"
- evidence: `crates/kcc-mcp/src/config_tools/routes.rs:62,91-97`
  ```rust
  let entry = match description.name {
      "kcc_config_state" => route(...),
      ...
      _ => route(description, schema_for_type::<DiffInput>(), |...| backups::diff(..)),
  ```
  The same pattern appears in `migration_tools/routes.rs:84`, `preset_tools/routes.rs:77`, `system.rs:69`, `read.rs:158`, `jobs.rs:121,173` and `vpn.rs:155`.
- impact: A new description added to `descriptions()` is silently served by `backups::diff` (or the last op handler), with its own name and permission.
- fix: Use enums for tools and ops (serde `rename_all`), and match them exhaustively.
- confidence: high

### E-16 Debug formatting is used as a wire value, and a test pins it
- severity: low
- kind: anti-pattern
- rule: core §13 "DON'T: Assert on Debug output as a stable format"
- evidence: `crates/kcc-mcp/src/handler.rs:148` `"kind": format!("{:?}", command.kind).to_ascii_lowercase()`. The same pattern is at `support/errors.rs:135`, `generic/fleet.rs:128` and `migration_tools/plan.rs:117`. `tests/resources.rs:89` asserts `Some("setting")`.
- impact: Renaming a variant or changing a derive in kcc-catalog or kcc-rci silently changes the MCP wire.
- fix: Use explicit `as_str()` or serde names.
- confidence: high

### E-17 Recovery mapping decides meaning by comparing an i18n message key
- severity: low
- kind: anti-pattern
- rule: BRIEF item 4 (string matching on error names)
- evidence: `crates/kcc-mcp/src/support/errors.rs:22` `None if error.message_key() == Some(keys::MANAGEMENT_NOT_APPLIED) => {`
- impact: Rewording or splitting the message key changes the wire code and the audit classification.
- fix: Have `recovery::Failure` expose a typed fate such as `NotApplied`.
- confidence: high

### E-18 Input schemas call `confirm` "unused", but it is required for some writes
- severity: low
- kind: docs
- rule: core §3 (misleading names and comments)
- evidence: `crates/kcc-mcp/src/domains/write/filtering.rs:96-98` `/// Unused confirmation flag accepted for a uniform interface.` appears on 8 inputs: clients.rs:50,78,109, routing.rs:48,78, filtering.rs:66,96 and dns.rs:34. `common.rs:117` `confirm_risk(server, operation.risk, confirm)?` uses the planned (runtime-classified) risk, and `tests/support/runtime_bracket.rs:167-172` shows firewall writes need it. `FirewallInput.index`/`description` (`filtering.rs:119-124`) are documented but always refused (`:207-209`).
- impact: An agent following the schema gets `confirm_required` on a firewall binding to the management interface.
- fix: Document `confirm` as "required when the change touches management", and drop `index`/`description`.
- confidence: high

### E-19 `resources/read` maps router failures to `internal`, skips the audit, and starts pollers for unregistered names
- severity: low
- kind: bug
- rule: overlay "Errors on the wire" (consistent codes)
- evidence: `crates/kcc-mcp/src/handler.rs:105-118`
  ```rust
  authorize(&identity.role, Permission::Read, host)
      .map_err(|_error| failure_error(McpFailure::Forbidden))?;
  let mut receiver = self.poller.subscribe(host).await;
  ...
  .map_err(|error| internal_error("resources/read", &error))?;
  ```
- impact: An unreachable or unknown router returns `internal`, while the tools return `router_unreachable`. Scope refusals here are never audited, unlike the tool path. A `"*"`-scoped caller can make the server spawn one poll task per arbitrary valid name (`kcc-app/src/poller.rs:224-230`).
- fix: Check registry membership first, map poll errors to `RouterUnreachable`, and audit `Forbidden`.
- confidence: high

### E-20 `catalog_search` with `limit: 0` returns a `next_cursor` equal to the current cursor
- severity: low
- kind: bug
- rule: none
- evidence: `crates/kcc-mcp/src/generic/fleet.rs:144,155`
  ```rust
  let limit = usize::from(input.limit.unwrap_or(20).min(100));
  "next_cursor": (results.len() == limit).then(|| (offset + limit).to_string())
  ```
- impact: An agent following `next_cursor` loops forever on empty pages.
- fix: Clamp the limit to `1..=100`, as the migration tools already do (`finish.rs:112`).
- confidence: high

### E-21 `kcc_diagnostics_write` is registered as a read-only Read tool
- severity: low
- kind: security
- rule: overlay mcp-servers (annotations); project read-only mode
- evidence: `crates/kcc-mcp/src/domains/table.rs:140` `let read_only = metas.iter().all(|&(_permission, risk)| risk == Risk::Read);`. All diagnostic ops are `Risk::Read, Permission::Read` (`kcc-domain/src/diagnostics.rs:268-277`), and `enabled()` (`registry/definitions.rs:178`) keeps read-only tools.
- impact: Under `[mcp] read_only = true`, a viewer can still make the router run iperf3, ping or traceroute to arbitrary hosts, which is real traffic generation. Starting these jobs is not audited (E-08).
- fix: Classify diagnostics as at least `Write`/non-read-only, or document the choice as an owner decision.
- confidence: medium (it may be intended)

### E-22 The unvalidated CLI escape is not recorded as a deviation from project rule (b)
- severity: info
- kind: guideline
- rule: project rule (b) "Every … CLI line … is validated against kcc-catalog"
- evidence: `crates/kcc-mcp/src/generic/rci.rs:433-439` (`if validated.unvalidated { authorize_routers(... ManageRouters ...) }`). The line is sent as `{"command": line}` with Risk `Management` (`kcc-catalog/src/request.rs:49-50`).
- impact: An admin agent can send any CLI line with an unknown prefix. It is classified Management, not Destructive, so it needs no `Destructive` permission.
- fix: List it as an open deviation in the project overlay, or classify unvalidated lines as Destructive.
- confidence: high

### E-23 Test quality: tautologies, tests that pin known-broken behavior, and review labels
- severity: low
- kind: test-quality
- rule: core §13; BRIEF item 5
- evidence:
  - `crates/kcc-mcp/src/tests/random.rs:37-61`: the `matches!` lists every `McpFailure` variant except `BatchFailSafeArmed`. The "typed" assertion is therefore a tautology, and it would falsely fail on a legitimate batch error.
  - `src/tests/gates.rs:196` asserts `next_cursor.is_some()`, pinning E-04.
  - `tests/support/curated_bracket.rs:209-210` expects `verification_failed` "because the fake keeps Bridge0", pinning a fake bug.
  - `tests/support/interface_refusals.rs:72` accepts any error, which hides E-07.
  - `src/tests/gates.rs:69-74` only checks `<= 25`/`<= 70` counts.
  - `gates.rs:91-115` never covers the `name` key (E-05).
  - `tests/live_mcp.rs:36-39` writes into `.omo/evidence/task-51-…` and `live_mcp/session.rs:142` uses the label `kcc-live-51`.
- impact: These tests cannot catch the bugs above, and some actively lock them in.
- fix: Assert specific codes per input class, fix the fake rather than pinning it, and drop task labels from test code.
- confidence: high

### E-24 Some write paths drop the audit receipt, so `audit_pending` is never reported
- severity: low
- kind: anti-pattern
- rule: none (inconsistent contract with `shape::noting`)
- evidence: `crates/kcc-mcp/src/domains/write/vpn.rs:182-192`
  ```rust
  apply(server, &opened, (&operation, input.confirm, async |changes| { ... })).await?;
  return Ok(json!({ "applied": true, "unsaved": true }));
  ```
  The same happens at `vpn_servers.rs:119-134`, `clients.rs:303-315,324-335` (segments) and `system.rs:87-97,103-122`.
- impact: Under a held audit lock, these writes claim a completed audit, while `kcc_rci_execute` correctly returns `audit_pending: true`.
- fix: Return `common::applied(result.unsaved, &result.audit)` on every path.
- confidence: high

## Coverage
- Read in full, src: `lib.rs`, `handler.rs`, `prompts.rs`, `registry{,/definitions,/docs}.rs`, `support{,/access,/audit,/errors,/raw_change,/route,/shape,/validate}.rs`, `generic{,/fleet,/persists,/rci,/router}.rs`, `domains{,/inventory,/read,/routes,/table,/write}.rs`, `domains/write/{clients,common,common/tests,dispatch,dns,filtering,housekeeping,interfaces,jobs,routing,services,system,vpn,vpn_servers,wifi}.rs`, `config_tools{,/backups,/routes,/state}.rs`, `migration_tools{,/apply,/finish,/plan,/routes,/select,/state}.rs`, `preset_tools{,/apply,/capture,/manage,/plan,/routes,/state}.rs`, `tests{,/fixture,/gates,/persists,/random,/strategies}.rs`.
- Read in full, tests: `domain_tools.rs`, `live_mcp.rs`, `live_mcp/session.rs`, `migration_finish.rs`, `migration_lease.rs`, `migration_tools.rs`, `operator_apply.rs`, `preset_tools.rs`, `resources.rs`, and every `tests/support/**` file (lab, resources, raw_*, bracket*, curated_bracket, nested_risk, runtime_bracket, interface_refusals, audit_pending, batch_outcomes{,/mixed,/namespaces}, raw_parity{,/gate_matrix}).
- Also read in full: `Cargo.toml`, `examples/tool-docs.rs`.
- Skimmed (cross-reference only): `kcc-web/src/page_kit/secret.rs`, `kcc-web/src/advanced/{viewer,preview}.rs`, `kcc-web/src/config_page/{create,text}.rs`, `kcc-web/src/presets_page/compose.rs`, `kcc/src/cli/{persist,redact}.rs`, `kcc-migrate/src/presets/store.rs`, `kcc-migrate/src/apply.rs:69-190`, `kcc-app/src/{jobs,poller,persist}.rs` excerpts, `kcc-catalog/src/{runtime,request}.rs` excerpts, `kcc-domain/src/{diagnostics,clients,components,interfaces/guard}.rs` excerpts, `rmcp-3.9.0/src/service.rs:1595-1632`, `rmcp-server-kit-3.21.1/src/{rbac.rs:150-190,585-600; config.rs:655-690}`.
- Not read: the rest of the rmcp and kit sources; the other crates outside these excerpts.

## Clean
- Every router-targeting tool authorizes the operation permission and router scope before any router request. The tests confirm zero requests on refusal.
- Raw tools: preliminary risk is the maximum across all catalogs, then re-checked against the target catalog. Management maps to the server switch and `confirm`. Path segments must match the catalog path.
- Curated writes: `open()` authorizes the registered op meta, and `apply()` re-authorizes the planned op's `SafetyNet::required` set. Management runs inside `bracket::guarded`.
- Toolset and read-only gating removes routes from dispatch, not only from listing. Kit `tool_list_filtering` defaults to `true`, so HTTP `tools/list` is filtered.
- The migration rollback finish requires `Destructive`, the server switch and `confirm`. Commit without `Save` is refused before anything is sent.
- `SecretString` inputs keep secrets out of `Debug`. Write tools never echo secret values.
- Failure audit records drop invalid router ids, and audit params carry only codes.
- `unused_async_trait_impl` has its own `#[expect]` scoped to the `ServerHandler` impl.
- The test harness uses no fixed sleeps. Progress waits are event-driven with a bounded timeout.