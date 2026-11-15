All 24 lane E findings have a verdict: 14 confirmed, 9 adjusted, 1 refuted (E-21). I opened every cited `path:line` myself at HEAD `349b7fb`, plus the rmcp and kit sources each finding depends on. This was read-only: no edits and no `cargo` runs.

### E-01 ADJUSTED
- checked: `crates/kcc-mcp/src/support/shape.rs:210-238`, `support/errors.rs:115-125`, `generic/rci.rs:186-210`, `support/validate.rs:61-77`, `registry/definitions.rs:115-121`, `config_tools/backups.rs:107-173`, `crates/kcc-config/src/secrets.rs:62-95`, `crates/kcc-web/src/page_kit/secret.rs:14-46`, `kcc-web/src/advanced/execute.rs:58-110`, `advanced/deliver.rs:98-106,325-338,366-373`, `advanced/viewer.rs:73-118`, `catalog/5.1/show.json:7811-7871`, `catalog/5.1/interface.json:7010,21595,22353`, `catalog/5.1/snmp.json:6`, `crates/kcc-app/src/settings.rs:195-205`, `README.md:213-215`, project overlay rule (d), `docs/BACKLOG.md:18`.
- reasoning:
  - The code gap is real. `kcc_rci_read` is a `core` tool that needs only `Permission::Read`. It accepts `show running-config`, which the catalog lists as a `Show` command with no arguments. The tool returns the router body after only `redact_secrets`.
  - That denylist uses substrings. It misses `key`, `private-key`, `obfs-key`, `community` and `pin`, all of which the Web `is_secret` catches. It also never looks inside string values, so config lines in a text body or a `message` array pass through unchanged.
  - The backup diff for the same Read principal goes through `kcc_config::secrets::redact` plus the ns3 mask. README:213-215 and rule (d) promise redacted MCP results, and only `RevealSecrets` may reveal secrets. So a Read principal can get ns3 blobs and plaintext secret lines, which the backup diff hides from the same principal.
  - The finding's comparison is wrong in one place. The Web explorer does not mask this read either. A Read user runs `show running-config` through `read_root`, and Web `mask` changes only member values whose names match. `Rendered::text` returns text bodies unmasked. So "the same read in the Web explorer is masked" holds only for JSON members named like secrets.
- severity: high (a Read or viewer key, including the stdio fallback `viewer` role, gets secrets that need `RevealSecrets`; the real answer shape is INFERRED, see BACKLOG:18).
- correction: The MCP leak stands. The Web explorer has the same `show running-config` gap, logged below as NEW-1. Masking JSON members by name differs between the two front ends. The text and line leak is common to both. The fix should be one shared classifier, plus config-text redaction (or a `RevealSecrets` gate) for `show running-config` and related reads in both front ends.

### E-02 CONFIRMED
- checked: `crates/kcc-mcp/src/preset_tools/capture.rs:84-100,131-210`, `crates/kcc-migrate/src/presets/store.rs:113-130,203-262,302-342`, `kcc-web/src/presets_page/compose.rs:127-147`, `crates/kcc/src/cli/preset/manage.rs:196-216`.
- reasoning:
  - MCP checks `Migrate` only on the new source router. It then derives the id as `slug(name)`.
  - `PresetStore::capture` runs `validate_id` and `authorize_source(role, new source)`, then `save`, which writes a temp file and does `fs::rename` over `<id>.json`. It never reads the existing record or checks that record's `source_router`.
  - `delete` and `get_for_apply` do check the existing record's scope. So a `lab-*` Migrate identity can replace a preset sourced from `prod-1`. Prod-scoped users then lose access, because `authorize_source` on the new record fails for them. The old preset content is gone (data loss).
  - The Web avoids this with `fresh_id`. The CLI has the same overwrite: it passes `name` as the id.
- severity: high
- correction: n/a. The root cause is in `PresetStore::capture`, so the store-level fix covers the CLI too.

### E-03 ADJUSTED
- checked: `crates/kcc-mcp/src/migration_tools/state.rs:19-72,163-196`, `migration_tools/finish.rs:61-104`, `migration_tools/apply.rs:150-162`, `crates/kcc-migrate/src/apply.rs:66-90`, `crates/kcc-app/src/persist.rs:260-282`, `crates/kcc-web/src/wizard/service.rs:47-83`, `kcc-web/src/wizard/live.rs:144-150`, `crates/kcc/src/server.rs:194`.
- reasoning:
  - Confirmed in the code:
    - The `Applier` keeps the router lease until commit, rollback or process exit.
    - The map entries have no TTL and are never removed.
    - `routers_for` refuses any identity other than the owner, so an admin cannot finish another identity's migration.
    - The map is process-wide, because `handler.clone()` shares the `Arc`.
    - Unapplied plans accumulate.
  - Two corrections. Holding the lease indefinitely is the shared `Applier` design ("dropping leaves router recovery armed"), and the Web wizard keeps it the same way: `Wizards::session` evicts only sessions with no live apply. The parts specific to MCP are owner-only finishing and never evicting unapplied plans.
- severity: medium
- correction: Restate it as: MCP has no recovery path for an abandoned apply (owner-only finish, no TTL), and its plan map grows without bound. A lease TTL tied to the armed timer belongs in the shared design, because the Web has the same retention.

### E-04 CONFIRMED
- checked: `crates/kcc-mcp/src/support/shape.rs:56-136,163-208`, `generic/persists.rs:67-84`, `generic/rci.rs:394`, `kcc-app/src/settings.rs:202`, `src/tests/gates.rs:184-199`.
- reasoning:
  - Above the cap, `shape` replaces the whole value with `{"truncated":true,"next_cursor":"1","request_id":...}`.
  - The failure reply goes through the same `shape`, so `error`, `message`, `field` and the completion of a `BatchFailSafeArmed` are all lost. The client gets `is_error` with no code.
  - The default cap is 32 KiB. A batch completion carries every response, so this is reachable.
  - `"1"` is meaningless as a cursor for tools that take no cursor.
- severity: medium

### E-05 CONFIRMED
- checked: `crates/kcc-mcp/src/support/shape.rs:240-288`, `kcc-domain/src/clients.rs:27-60`, `kcc-mcp/src/domains/write/jobs.rs:59-80`, `kcc-domain/src/diagnostics.rs:85-100,210-225,282-298`, `kcc-app/src/settings.rs:310-314`.
- reasoning:
  - `PrivacyConfig` says the setting pseudonymizes "host names", but `Client.name` ("Registered host name") does not match any key needle and passes through.
  - Arping progress lines are JSON strings containing `mac` and `address`. They are sent through `progress.notify` without going through `shape`.
  - Strings that embed a MAC are not matched, because `looks_like_mac` needs the whole value to be the MAC.
- severity: medium

### E-06 ADJUSTED
- checked: `crates/kcc-mcp/src/migration_tools/finish.rs:61-104`, `migration_tools/state.rs:170-196`, `migration_tools/apply.rs:94,153`, `preset_tools/apply.rs:86`, `RUST_GUIDELINES.md:1147-1182`.
- reasoning:
  - The cited rule does not apply. §5 is about `std::sync::Mutex` and says explicitly "use tokio::sync::Mutex if you must hold across await". This lock is a `tokio::sync::Mutex`.
  - What remains is a design point. One global map lock is held across commit and rollback I/O, which can include a reboot wait. During that time it blocks plan recording, apply recording and report calls for every router.
- severity: low
- correction: This is not a guideline violation. It is a contention issue on an uncommon path. A per-entry lock is the fix.

### E-07 CONFIRMED
- checked: `crates/kcc-mcp/src/domains/write/interfaces.rs:104-155`, `kcc-domain/src/interfaces/guard.rs:16-72`, `kcc-mcp/src/registry/docs.rs:44-47`, `tests/support/interface_refusals.rs:60-73`.
- reasoning:
  - Every `InterfaceChangeError` becomes `Conflict`. This includes `WorkflowError::VerificationFailed { field }`, permission refusals and router errors.
  - The type exposes only `is_fail_safe_unarmed`, so MCP cannot map the error any better without a change in the domain crate.
  - This breaks rule (c) and the documented `verification_failed` + `field` contract.
- severity: medium

### E-08 CONFIRMED
- checked: `crates/kcc-mcp/src/config_tools/backups.rs:64-88`, `generic/fleet.rs:199-221`, `preset_tools/capture.rs:131-210`, `preset_tools/manage.rs:61-77`, `domains/write/jobs.rs:100-144`, `support/audit.rs:1-40`, `support/route.rs:73-115`, `kcc-web/src/config_page/create.rs:70-74`, `kcc-web/src/advanced/jobs.rs:197-210`, `kcc-web/src/system_pages/diagnostics.rs:6-8`, `kcc/src/cli/preset/manage.rs:213-221`.
- reasoning: The route wrapper audits failures only. None of the cited success paths writes an audit entry. The Web and CLI audit the equivalent actions (backup create, job cancel, preset capture, diagnostic start).
- severity: medium

### E-09 ADJUSTED
- checked: `crates/kcc-mcp/src/support/shape.rs:52-65`, `support/errors.rs:46-75`, `rmcp-3.9.0/src/service.rs:1595-1632`, `rmcp-server-kit-3.21.1/src/auth.rs` (request_id appears in auth logs only, no per-call span), `overlays/domains/mcp-servers.md:12-14`.
- reasoning:
  - The id is created after the work has run. Causes are logged earlier without it. rmcp instruments the handler with the loop span only.
  - The overlay rule is quoted correctly: the cause must be logged "with enough context to correlate". So this is a genuine violation.
  - The cost is limited to concurrent calls: the cause line and the code line are adjacent in the same task. That is a minor operability cost.
- severity: low
- correction: n/a (severity only)

### E-10 ADJUSTED
- checked: `crates/kcc-mcp/src/lib.rs:1-24`, `crates/kcc-domain/src/lib.rs:2-12`, `kcc-catalog/src/lib.rs:3-6`, `kcc-rci/src/lib.rs:4-14`, `generic/fleet.rs:136-157`, `support/validate.rs:103-108`, `RUST_GUIDELINES.md:19,1650`.
- reasoning:
  - The blanket crate-root `#![expect]` covering 8 lints, plus `missing_docs_in_private_items`, does go against "#[expect] on the narrowest item".
  - Two corrections. `kcc-domain` also has a crate-root `#![expect(clippy::missing_errors_doc)]`, so "no other crate root does this" is false. The `offset + limit` example cannot overflow: `results.len() == limit > 0` requires `offset` below the catalog size, and when `limit == 0` it adds 0.
  - The real cost is that `arithmetic_side_effects` is silenced for the whole crate. No overflow has been demonstrated.
- severity: low
- correction: Remove the example and the "no other crate" claim. What remains is a lint-scope violation with no demonstrated bug.

### E-11 ADJUSTED
- checked: My own scan of `crates/kcc-mcp/src/**` found about 71 production async fns without an annotation (81 including tests), e.g. `domains/write/wifi.rs:114`, `migration_tools/finish.rs:62`, `config_tools/backups.rs:65`, `preset_tools/capture.rs:132`, `support/access.rs:78,91,102`. Also checked `RUST_GUIDELINES.md:1188-1237`, `docs/BACKLOG.md:43,77`.
- reasoning: The count and the rule are accurate. The same class of gap is already tracked in BACKLOG:77 for other crates. BACKLOG:43 records that rmcp runs each call in a detached task that kcc never cancels, so the practical risk now is documentation drift.
- severity: low
- correction: These are new instances of a known BACKLOG class. Add them to that item, or annotate them.

### E-12 CONFIRMED
- checked: `crates/kcc-mcp/src/support/shape.rs:174-183,280-286`, `generic/fleet.rs:84,141`, `generic/rci.rs:57-59,192`, grep for `"fields"`.
- reasoning:
  - `fields` is read from the output value, but no tool emits `"fields"`. The input `fields` values are validated and then dropped, so the schema promises a projection that never happens.
  - The "router key pruned" sub-claim is weak, because `rci_read` wraps the router answer under `value`.
- severity: low

### E-13 CONFIRMED
- checked: `crates/kcc-mcp/src/support/shape.rs:240-278`, `lib.rs:244`, `generic/router.rs:85`, `kcc/src/server.rs:194`.
- reasoning:
  - `"description"` contains `"ip"`, so every description string becomes `client-N` when redaction is on. This includes the schema descriptions from catalog describe.
  - There is one map, shared through `Arc` across every session clone, and nothing ever evicts entries.
- severity: low

### E-14 CONFIRMED
- checked: `crates/kcc-mcp/src/generic/router.rs:32-60,247-262`, `registry/definitions.rs:136-141`, `config_tools/backups.rs:157-173`, `kcc-web/src/config_page/text.rs:63-80`, `kcc/src/cli/redact.rs:45-66`, `migration_tools/plan.rs:127-134`, `generic/fleet.rs:118-122`, `domains/write/services.rs:207-221`, `domains/write/vpn_servers.rs:136-142`.
- reasoning: Every duplicate exists as cited. The wire annotations of the generic tools come from `#[tool]`, while the RBAC specs and docs come from `definitions`. No test compares the two.
- severity: low

### E-15 CONFIRMED
- checked: `crates/kcc-mcp/src/config_tools/routes.rs:17,58-100`, `RUST_GUIDELINES.md:547`.
- reasoning: Tool-name dispatch ends in a `_` arm that serves `backups::diff`, so an added description would be bound to the wrong handler. The op-level wildcards are guarded by `check_op`, so only the tool-name dispatch matters here.
- severity: low

### E-16 CONFIRMED
- checked: `crates/kcc-mcp/src/handler.rs:144-150`, `support/errors.rs:128-141`, `generic/fleet.rs:128`, `migration_tools/plan.rs:117`, `tests/resources.rs:88-89`, `RUST_GUIDELINES.md:2239,3538-3566`.
- reasoning: `{:?}` output is used as a wire value, and a test pins it. The guideline says "Debug is not an output format" (`use_debug` rationale, §13).
- severity: low

### E-17 CONFIRMED
- checked: `crates/kcc-mcp/src/support/errors.rs:18-29`, `kcc-domain/src/configuration/recovery.rs:56-100`.
- reasoning:
  - `Failure` keeps `sent` private, so MCP infers "not applied" from `message_key()`.
  - Rewording the message text does not break this, because both sides use the same constant. Splitting or reassigning the key does break it.
- severity: low

### E-18 CONFIRMED
- checked: the 8 doc lines found by grep (`clients.rs:50,78,109`, `routing.rs:48,78`, `filtering.rs:66,96`, `dns.rs:34`), `domains/write/common.rs:65-71,105-118`, `filtering.rs:110-130,186-209`.
- reasoning: `confirm` is passed to `confirm_risk` and is required for Management risk. The `index` and `description` fields are documented but always refused.
- severity: low

### E-19 ADJUSTED
- checked: `crates/kcc-mcp/src/handler.rs:93-135`, `kcc-app/src/poller.rs:216-232,306-348`.
- reasoning:
  - Confirmed: a poll error becomes `internal` rather than `router_unreachable`, and a resource-path `Forbidden` is not audited.
  - Correction: the poller started for an unknown name idles out after `intervals.idle` and removes its channel. That sub-claim is therefore bounded.
- severity: low
- correction: Remove the unbounded-task implication.

### E-20 CONFIRMED
- checked: `crates/kcc-mcp/src/generic/fleet.rs:136-157`.
- reasoning: With `limit: 0`, `results.len() == 0 == limit`, so `next_cursor` comes back equal to the current offset. An agent following it loops forever.
- severity: low

### E-21 REFUTED
- checked: `crates/kcc-mcp/src/domains/table.rs:130-150`, `kcc-domain/src/diagnostics.rs:266-279`, `kcc-web/src/system_pages/diagnostics.rs:1-8`.
- reasoning:
  - This is a documented design choice, not a defect. The domain declares the diagnostics `Risk::Read` and `Permission::Read`.
  - The Web states the same policy: "The domain describes the diagnostics as reads: whoever may read the router may run them." MCP's read-only flag follows that shared classification.
  - The missing audit entry is already covered by E-08.

### E-22 CONFIRMED
- checked: `crates/kcc-mcp/src/generic/rci.rs:414-475`, `kcc-catalog/src/request.rs:40-55`, `kcc-catalog/src/runtime.rs:298`, `kcc-web/src/advanced/cli.rs:248`, `docs/MCP_TOOLS.md:176`, project overlay rule (b) and the deviation list.
- reasoning:
  - Lines the catalog cannot map are sent unvalidated for RawRci+ManageRouters callers, classified Management. This contradicts rule (b) as written.
  - It is documented only in the MCP tool docs, not as an overlay deviation. The Web CLI console has the same escape.
- severity: info

### E-23 ADJUSTED
- checked: `crates/kcc-mcp/src/tests/random.rs:32-63`, `src/tests/gates.rs:64-74,184-199`, `tests/support/curated_bracket.rs:203-212`, `tests/support/interface_refusals.rs:60-73`, `tests/live_mcp.rs:34-38`, `tests/live_mcp/session.rs:142`, `AGENTS.md` (Evidence section), `docs/BACKLOG.md:17`.
- reasoning:
  - These sub-claims hold:
    - The `matches!` in `random.rs` is close to a tautology: it accepts anything except `BatchFailSafeArmed`.
    - `gates.rs:196` pins the meaningless cursor from E-04.
    - `interface_refusals` accepts any error, which hides E-07.
  - These sub-claims do not hold:
    - The `.omo/evidence/task-<N>-…` path is mandated by AGENTS.md "Evidence".
    - Whether a real router deletes `Bridge0` is an open hardware question in BACKLOG:17, so the fake's read-back is not a known bug.
    - The `<= 25`/`<= 70` checks are deliberate registry caps.
- severity: low
- correction: Keep the `random.rs`, `gates.rs:196` and `interface_refusals` items. Drop the evidence-path, Bridge0 and caps items.

### E-24 ADJUSTED
- checked: `crates/kcc-mcp/src/domains/write/vpn.rs:178-193`, `domains/write/vpn_servers.rs:112-134`, `domains/write/system.rs:84-122`, `kcc-domain/src/vpn_clients/secrets.rs:128-133`, `kcc-domain/src/system.rs:201-207`.
- reasoning:
  - The system paths do drop a `TerminalCliChangeResult` from `apply_registered(...)` in MCP.
  - The VPN-secret paths cannot follow the proposed fix: `client_secrets::apply` returns `CoreResult<(), WorkflowError>`, so the receipt is consumed inside kcc-domain, and `common::applied(result.unsaved, &result.audit)` is not available in MCP.
- severity: low
- correction: Fix the system paths in MCP. The VPN-secret paths first need the domain functions to return their change result.

## Summary
- CONFIRMED: 14 (E-02, E-04, E-05, E-07, E-08, E-12, E-13, E-14, E-15, E-16, E-17, E-18, E-20, E-22)
- ADJUSTED: 9 (E-01, E-03, E-06, E-09, E-10, E-11, E-19, E-23, E-24)
- REFUTED: 1 (E-21)
- DUPLICATE: 0

**NEW-1 (high, to validate separately).** A Read user in the Web explorer can read `show running-config` with secrets intact, the same leak as E-01:
- Evidence: `kcc-web/src/advanced/execute.rs:68-74,100` (a Read-risk command needs only `command_permissions(Risk::Read)`), then `deliver.rs:98-106` (`read_root`), then `viewer.rs:73-118`. There, `mask` replaces only members whose names look like secrets, and `Rendered::text` is never masked. Lines inside a `message` array or a text body stay as they are.
- Contrast: the Web's own `explorer/stored` view (`advanced/preview.rs:137-175`) runs `kcc_config::secrets::redact` on the same data.
- The real answer shape is INFERRED (BACKLOG:18).

**NEW-2 (scope note for E-02).** The CLI `kcc preset capture` also uses the display name as the preset id (`crates/kcc/src/cli/preset/manage.rs:205-206`). It therefore has the same out-of-scope overwrite through `PresetStore::capture`.