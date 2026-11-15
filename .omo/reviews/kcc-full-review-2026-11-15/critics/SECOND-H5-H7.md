### H5 CONFIRMED
- checked: `crates/kcc-migrate/src/apply/preflight.rs:91,104-125,132-175`, `apply/reconnect.rs:17-83`, `apply/execute.rs:28-139`, `apply/finish.rs:134-171`, `planner.rs:83-130,177-211`, `planner/diff.rs:11-25`, `rules.rs:562-599,693-711`, `rules/rules.toml:128-140`, `crates/kcc-app/src/workflow.rs:913-927`, `crates/kcc-rci/src/engine.rs:204-217`, `crates/kcc/src/cli/migrate_plan.rs:170-191`, `crates/kcc-web/src/migrate_wizard/apply_request.rs:116-136`, `crates/kcc/tests/live_migration/rehearsal.rs:155-170`, `crates/kcc-migrate/tests/support/apply_secrets.rs:91-120`, `crates/kcc-config/tests/fixtures/superuser-startup-config.txt:26-30,55-58`
- reasoning:
  - **How the order is built.** `execution_phases` walks the classified items in source order. Each emitted line that the target does not already contain is pushed to `management` when `is_management_line` matches. That means `user <name> password plain …`, `ip http port|ssl …`, or `interface <current mgmt iface> ip address|security-level …`. The management phase is never re-sorted, and `execute::management` runs it as is.
  - **Where the password lines come from.** When the realm differs (cross-model), the rules mark each `user X password md5|nt` as needs-input, and `password_item` rewrites it to `user X password plain <pw>`.
  - **What the reconnect uses.** After every applied management line, `complete_line` calls `changes.reconnect(url, applier.credential.clone())`. The URL is `reconnect_url`, or the current URL for `user ` lines. The credential is fixed once in `prepare` as `Some(login, management_password)`. The CLI and Web set `management_password` whenever the operator supplies a password for the profile's login. `retarget` uses it instead of the current credential, and `read_last_change` authenticates with it.
  - **Plan that breaks (verified from code).** A cross-model migration onto a target whose LAN differs from the source's, for example source Bridge0 192.168.10.1 and target default 192.168.1.1, with "overwrite" chosen.
    1. Management order: `interface Bridge0 ip address 192.168.10.1 …` (interface blocks precede `user` blocks; see the fixture).
    2. Then `user admin password plain P`, and again `user admin password plain P` (the md5 and nt lines become the same line).
    3. After line 1, the reconnect goes to `reconnect_url` as `admin/P`. The router still has the old password, so it fails for 120 s.
    4. `recover` then waits out the timer and returns `RolledBackByRouter`.
  - **Variant.** A non-`admin` kcc login whose `user` block comes after another user's fails the same way. That ordering is INFERRED.
  - **Mitigations.** There is no lockout: the timer or reboot restores the router, and the registry is transitioned only on a successful reconnect. The only workaround is to enter the target's *current* password as the "new" one. The live rehearsal does exactly that (`rehearsal.rs:164-168`), which hides the bug. The only fake-router test has a single `user` line.
- severity: high. A main flow (cross-model hardware replacement with a different LAN subnet) fails every time, after about 120 s plus the safety window.

### H6 ADJUSTED
- checked: `crates/kcc-migrate/src/presets/store.rs:114-131,172-230,237-262,312-342,356-378`, `crates/kcc-mcp/src/preset_tools/capture.rs:60-99,132-195`, `preset_tools/manage.rs:32-76`, `preset_tools/state.rs:124-137`, `preset_tools/plan.rs:224-248`, `crates/kcc/src/cli/preset/manage.rs:25-28,197-215`, `cli/preset/source.rs:31-46,59-65`, `cli/principal.rs:95-109`, `crates/kcc-web/src/presets_page/compose.rs:127-148`, `kcc-web/src/wizard/ids.rs:16-19`
- reasoning:
  - **What runs on the existing preset.** On both paths: none. `PresetStore::capture` runs only `validate_id` and `authorize_source(role, new source)`, then `save` renames over `<id>.json`. That `authorize_source` call is `Migrate` plus scope on the *new* source router, or `Migrate` alone when the source is `None`. `save` never reads the old record's `source_router`, although `delete`, `get` and `load_for_apply` all do.
  - **MCP checks.** MCP checks `Migrate` on the new source router (`authorize_routers`) and uses `slug(name)` as the id.
  - **CLI checks.** The CLI checks `Read+Migrate` on the source router through `Principal::authorize` and narrows the role to that router. A `file:` source needs only `Migrate` and stores `source_router = None`. The id is the raw name.
  - **What an attacker gains (MCP; the realistic vector).**
    - A `lab-*`-scoped Migrate key can destroy any CLI- or MCP-named preset of another scope. Web presets use random 64-bit ids and cannot be hit.
    - The target ids are guessable. There is also an existence oracle: `kcc_preset_list {id}` and `kcc_preset_delete` answer `Forbidden` for an existing out-of-scope id and `InvalidArguments` for a missing one (`map_preset`).
    - The replacement is stamped with the attacker's `source_router`. A prod-only admin therefore loses the preset rather than applying it: `load_for_apply` refuses them.
    - Lab-authored lines reach prod only when an admin whose scope covers *both* routers later applies the same-named preset, even though its source router and creator have changed. That makes it a victim-assisted cross-scope push, not a direct one.
  - **CLI vector.** The CLI vector is real in code (and with `file:` the replacement becomes scope-less, so any Migrate role can apply it). But the CLI user loads the master key from disk (`manage.rs:25-28`) and can already decrypt or write all state, so the CLI is not a security boundary here.
  - No secret is disclosed.
- severity: medium
- correction: The finding should read: "MCP `kcc_preset_capture` lets any Migrate identity overwrite (delete and replace) an out-of-scope preset whose id is name-derived (created by CLI or MCP). An existence oracle makes the target id discoverable. Prod-only users lose the preset. A both-scope admin may later apply attacker-sourced lines." The CLI path is the same bug but carries little risk, because the CLI user already holds the master key. Fix: in `capture`/`save`, open with `create_new`, or read the existing record and require `authorize_source` on its `source_router` (the same check `delete` makes). Optionally make the MCP slug unique.

### H7 CONFIRMED
- checked: `crates/kcc/src/cli/api_keys.rs:26-97`, `cli/accounts.rs:89-102,140-158`, `crates/kcc/src/server.rs:122-150,532-597`, `rmcp-server-kit-3.21.1/src/auth.rs:1757-1762,2555-2625`, `crates/kcc-mcp/src/support/access.rs:30-63`, `crates/kcc-web/src/authz.rs:159-201`, `crates/kcc-web/src/admin.rs:122,132` (grep), `README.md:226-238`, `docs/CONFIG.md:27-30`, `docs/SECURITY.md:101-107,266-270`, `docs/USER_GUIDE.md:245-258`
- reasoning:
  - **How the kit authenticates keys.** The kit checks every bearer token against `state.api_keys.load_full()`, an in-memory `ArcSwap` (`auth.rs:2603`). kcc fills it once at startup (`server.rs:136`) and replaces it only through `install_keys`, which runs on a Web create or revoke or on SIGHUP `reload()` (`server.rs:583-597`).
  - **No per-request state check.** Nothing on the MCP path re-reads `api_keys.json`. `record_key_use` discards the `persist()` result (`Ok(Ok(_known))`), so a deleted key that is still in use goes unnoticed.
  - **What the CLI does.** `kcc apikey revoke` only edits the state file, then prints "deleted" with exit 0 and no note. `user disable` and `passwd` reset only write the account store.
  - **Web sessions.** `authentication_middleware` takes the in-memory session and re-resolves only the role definition. It never checks `disabled` or the password, and SIGHUP `reload()` does not touch sessions. A CLI-disabled or CLI-reset account's sessions therefore last until idle (30 min, refreshed by every request) or absolute (12 h) expiry, and even a SIGHUP does not end them.
  - **Docs.** No document says that revoke, disable or reset from the CLI needs a SIGHUP.
    - The README Limitations section names only `apikey create`.
    - CONFIG.md:27 says SIGHUP "appl[ies] API keys", which an operator could infer covers revocation.
    - SECURITY.md:106-107 says "a password or role change ends the account's other sessions", with no CLI exception. That is false for the CLI.
    - USER_GUIDE covers only the Web admin page.
- severity: high. A revoked leaked key stays valid indefinitely on a long-running server, and a disabled account keeps access until its session expires. The operator is told it succeeded.

## Summary
- CONFIRMED: 2 (H5, H7)
- ADJUSTED: 1 (H6, high → medium; the MCP vector is real, the CLI vector is low-value, and the cross-scope push needs a both-scope admin to apply)
- REFUTED: 0. DUPLICATE: 0.

NEW issues to validate separately:
- **NEW-a (low/medium, H6-adjacent): preset existence oracle.** `PresetStore::get` and `delete` call `read_record` before `authorize_source` (`store.rs:172-176,207-211`). MCP then maps `NotFound` to `InvalidArguments` and `Forbidden` to `Forbidden` (`kcc-mcp/src/preset_tools/state.rs:126-130`). An out-of-scope caller can therefore confirm whether any preset id exists.
- **NEW-b (low, test gap masking H5):** `crates/kcc/tests/live_migration/rehearsal.rs:164-168` supplies the target's *current* password as the login's "new" password. The only fake-router management-password test plans a single `user` line (`kcc-migrate/tests/support/apply_secrets.rs:93-120`). No test can catch the H5 ordering bug.