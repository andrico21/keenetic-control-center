I read this as a request to validate every lane-F finding against the code without changing anything, and I've stopped now that all 31 have a verdict.

### F-01 CONFIRMED
- checked: `crates/kcc/src/cli/api_keys.rs:26-98`, `cli/accounts.rs:31-176`, `crates/kcc/src/server.rs:136,537-598`, `crates/kcc-web/src/admin.rs:122,160`, `admin_keys.rs:229,305`, `admin_users.rs:390,495,560`, `kcc-web/src/authz.rs:159-201`, `kcc-web/src/session.rs:242-411`, `kcc-mcp/src/support/access.rs:49-63`, `kcc-app/src/api_key_use.rs`, `rmcp-server-kit-3.21.1/src/auth.rs:1757-1887,2603`, `docs/CONFIG.md:27-30`, `docs/SECURITY.md:101-107`, README "Limitations".
- reasoning: The kit keeps the keys in an in-memory `ArcSwap`. They are installed once at `server.rs:136` and swapped only by `TransportReload::install_keys`, which runs on a Web key create or revoke (it re-reads `api_keys.json`) or on a SIGHUP (`reload()` at `server.rs:583-598`). Nothing checks a key against state on each request. `record_key_use` even gets `persist() == false` for a deleted key and ignores it (`Ok(Ok(_known))`). A Web session is an in-memory record. `authentication_middleware` re-reads only the role's live definition, never `disabled`. `reload()` does not touch sessions, so after a CLI `user disable` or an admin `passwd` reset the sessions last until their idle or absolute timeout, even across a SIGHUP. That contradicts SECURITY.md:106-107 ("a password or role change ends the account's other sessions"). The README limitation mentions only `apikey create`. The Web paths do the extra steps the CLI skips; the reviewer's `:495` is the delete path, while disable is the `signs_out` branch at `:560`.
- severity: high

### F-02 CONFIRMED
- checked: `cli/router_secrets.rs:98-139,199-203`, `cli/router_edit.rs:69-151`, `cli/routers.rs:151-153`, `kcc-app/src/registry.rs:102-134,547-590`, `kcc-app/src/credentials.rs:160-168,321-327`.
- reasoning: `parse_url` is plain `Url::parse`, so `http://h/ui` passes `plan()`. `seal()` overwrites the deterministic sealed path, and then `registry.update` → `profile.validate()` refuses "url must be an http(s) origin". The stored profile keeps its old URL but now resolves the new sealed password, and the old one is gone. The doc comment "a refused change writes nothing" is false. `edit` also skips `outbound::check`. The connection-time check still enforces the policy, but SECURITY.md says it is "checked before a router profile is stored", which `update` does not do.
- severity: medium

### F-03 CONFIRMED
- checked: `crates/kcc/src/server.rs:138,457-471`, `kcc-web/src/session.rs:145-194`, `kcc-app/src/settings.rs:886-911`, `docs/SECURITY.md:85-88,103-104`.
- reasoning: The cookie mode depends only on listener TLS. Validation accepts a non-loopback plain listener when `public_url` is https and `trusted_proxies` is set, and then the cookie is `kcc_session` without `Secure`. SECURITY.md says "on TLS listeners `Secure`", so it is literally consistent, but the `LoopbackHttp` doc ("the listener is loopback-only") is false in this mode. Browsers will send the cookie to `http://<same host>`, so an active LAN attacker can provoke a cleartext request and take the session. HSTS at the proxy would mitigate it; kcc does not ensure that.
- severity: medium

### F-04 ADJUSTED
- checked: `cli/fleet.rs:62-145`, `cli/rci.rs:38-60`, `cli/persist.rs:261-295`, `cli/context.rs:275-315`, `cli/args.rs:26-28`, `cli/principal.rs:34-110`, `kcc-config/src/ns3.rs:30-70`, `catalog/5.1/show.json`, `kcc-web/src/advanced/deliver.rs:331-337`.
- reasoning: The code does print `show running-config` unmasked with only `Read`, and NS3 is key-less reversible scrambling (`ns3::decode`), so the output holds real secrets. That contradicts the README rule that revealing a secret needs `RevealSecrets`, which the CLI itself enforces for `backup get --output`. But the CLI is not a security boundary for whoever runs it. `Ctx::services` loads the master key, so the caller can open every sealed router credential, and `--config` lets the caller pick a `kcc.toml` with any `[cli] role`. Also, `rci get` requires `RawRci` plus `Read`, not just `Read`.
- severity: low
- correction: This is a contract inconsistency on the CLI, not a privilege escalation. The real exposure is in MCP (see the first NEW item in the Summary).

### F-05 CONFIRMED
- checked: `crates/kcc/src/server.rs:218-248`, `crates/kcc/src/main.rs`, `server_shutdown.rs`, `rmcp-server-kit-3.21.1/src/transport.rs:5916-5937,4551-4576`, `docs/BACKLOG.md:32,43`.
- reasoning: `serve_stdio` awaits only `service.waiting()`. The kit's ctrl_c/SIGTERM handling exists only on the HTTP path (`:4551`), and kcc installs no handler anywhere except SIGHUP inside the HTTP reload callback. With the default disposition, SIGTERM or SIGINT kills `kcc mcp stdio` at once. That skips `wait_for_brackets`, the job drain and `flush_audit`. The MCP stdio shutdown sequence (close stdin, then SIGTERM after a client-chosen timeout) can hit this during the 10 s bracket grace, and Ctrl-C hits it directly. BACKLOG:32/43's "stdio waits for brackets" holds only on stdin EOF. The router timer still rolls back, which is the safe direction, so the loss is the change plus its queued audit entries. The cited §5 "Audit Drop impls" rule is a loose fit.
- severity: medium

### F-06 ADJUSTED
- checked: `cli/api_keys.rs:26-46`, `cli/accounts.rs:31-61,235-248`, `kcc-web/src/admin_keys.rs:195-235,320-346`, `cli/principal.rs`, `cli/context.rs:275-276`, `docs/CONFIG.md:133-138`.
- reasoning: The CLI really does skip `dominates` and `manages`. Escalation is not real, though: the CLI user can read the master key, write `api_keys.json` and `roles.json`, and choose its own `--config` with `[cli] role = "admin"`. What remains is a cross-surface consistency gap against README "Permissions".
- severity: low
- correction: This is a consistency issue, not a security escalation.

### F-07 ADJUSTED
- checked: `cli/persist.rs:174-195`, `cli/redact.rs`, `kcc-config/src/config_text.rs:217-222,445-459`, `kcc-web/src/config_page/text.rs`, `kcc-mcp/src/config_tools/backups.rs:140-178`, `cli/args_fleet.rs:139`.
- reasoning: Comparing redacted lines does hide a changed PSK, password or key: both sides read `... <redacted>`, so the diff prints nothing. The Web compares full-text digests instead. The help text "Count the lines" is wrong; the command prints lines. The repeated-line claim is wrong, though: `flatten` prefixes every leaf with its ancestor tokens (`interface X up` and `interface Y up` differ), so only exact duplicates within one block, or reordering, are missed.
- severity: medium
- correction: Drop the claim about `up`/`exit`/`shutdown` in other blocks. The defect is invisible secret changes, plus set semantics for reordering and exact duplicates.

### F-08 ADJUSTED
- checked: `cli/redact.rs:11-64`, `kcc-web/src/config_page/text.rs:15-97`, `kcc-mcp/src/config_tools/backups.rs:156-178`.
- reasoning: The three `redacted` + `mask` copies, and the CLI copy of `redacted_copy` with a literal `"kcc-redacted"`, are real and currently identical in behaviour. The "already drifted" claim is wrong: F-07 is a drift in the diff algorithms, not in redaction.
- severity: low
- correction: Duplication with no observed drift.

### F-09 ADJUSTED
- checked: `cli/persist.rs:143-148,226-229,261-264`, `cli/accounts.rs:31-34,127-129`, `cli/context.rs:275-315`, `crates/kcc/src/server.rs:337-419,451,491`.
- reasoning: Every cited double `ctx.services()` and every master-key load is there. Each `services()` call spawns an `AuditLog` writer, runs `migrate_all` (a no-op the second time) and prints the external-password notes again. The outer `Services` in `backup create`/`get` is used only for `router_id`; its workflow never begins a change set, so there is no lease conflict. The concrete cost is duplicate stderr notes and wasted work, plus two near-copies of the composition root.
- severity: low

### F-10 CONFIRMED
- checked: `cli/persist.rs:96,237`, `migrate_plan.rs:161,176`, `preset/source.rs:53,139`, `dom_routes.rs:103`, `dom_vpn.rs:130`, `tls.rs:55,117,154`, `migrate_apply.rs:77`, `preset/run.rs:107`, `entry.rs:106`, `principal.rs:42`, `server.rs:128-131,315,428-431,464,511`, overlay `keenetic-control-center.md:53-54`.
- reasoning: Every cited literal is a hand-written English sentence passed through `Failure::text` or `ServerError`, and it reaches the user. Rule (f) says "Every user-visible string comes from `kcc-i18n`".
- severity: medium

### F-11 ADJUSTED
- checked: `cli/dom_lan.rs:94-121`, `cli/args_dom_lan.rs:44-72`, `kcc-domain/src/dhcp.rs:86-117`.
- reasoning: `--gateway` defaults to `begin`, so with the Keenetic default pool (begin .33, router .1) a client address is advertised as the gateway. The LAN loses its route on renewal, and the read-back passes. `plan_pool` emits `dns-server` only when `--dns` is given and `bind` only when `--interface` is given, so DNS servers and the binding are not cleared. Lease (86400) and enable state are reset to defaults.
- severity: medium
- correction: Drop "clears the DNS servers". The harmful default is the gateway, and the replace resets only lease and state.

### F-12 ADJUSTED
- checked: `cli/migrate_apply.rs:47-82`, `migrate_apply/migrate_apply_finish.rs:17-31`, `cli/migrate.rs:70-77,150-186`, `preset/run.rs:60-133`, `preset/commands.rs:52-54`, `preset/finish.rs:39-101`, `persist.rs:88-115`, `preset/manage.rs:240-260`, `cli/secret.rs:65-102`.
- reasoning: The inconsistency is real: `apply --finish rollback` needs only `--yes` (Management confirm), while `finish rollback` needs `--confirm-destructive <id>`. `Destructive` permission is still required up front (`authorize_apply` with `finishing_with_rollback`). The rollback also only has to be requested explicitly with `--finish rollback`, so "a scripted `--yes` also authorizes a rollback" overstates it. `preset delete` takes the id as an argument, which is itself typed.
- severity: low

### F-13 ADJUSTED
- checked: `cli/persist.rs:150,175,197-199,266,274-276`, `routers.rs:42-44,72,96`, `router_secrets.rs:35-37,105-107`, `preset/manage.rs:57-68`, `accounts.rs:32,186`, `api_keys.rs:27,108`, `context.rs:177-192,378-392`, `docs/SECURITY.md:292`.
- reasoning: These refusals return through `principal().authorize()?` or `require()?` with no `attempt()`. That contradicts SECURITY.md:292 ("Every change, handler-level refusal, login and secret reveal appends an entry"). Since the CLI role is not a boundary against its own OS user (see F-04 and F-06), the forensic cost is small.
- severity: low

### F-14 ADJUSTED
- checked: `cli/preset/source.rs:39-141`, `cli/migrate_plan.rs:120-163`, `kcc-migrate/src/source.rs:66-98`.
- reasoning: The preset path does copy the configuration into a plain `Vec<u8>`, and there are two `--from` grammars (bare id accepted versus `router:` required). But both paths parse into `SourceConfig { ast: Ast, .. }`, which holds the whole configuration, secrets included, as plain `String`s for the life of the plan. The extra short-lived `Vec` adds almost nothing. The `split_once`/`rsplit_once` mismatch only matters for names containing `/`.
- severity: low

### F-15 CONFIRMED
- checked: `cli/persist.rs:111-134`, `cli/migrate.rs:184-186`, `cli/change.rs:266-288,177-252`.
- reasoning: `applied(step == Close::Rollback)` sets `"unsaved": true` exactly on rollback, `labelled` keeps it, and `run_completed` passes the document through, so the JSON reports unsaved changes after the router restored its saved configuration.
- severity: low

### F-16 ADJUSTED
- checked: `cli/dom_vpn.rs:91-108`, `dom_vpn_server.rs:47-60`, `kcc-domain/src/vpn_clients/secrets.rs:83-170`, `kcc-domain/src/wan.rs:168-192`, `cli/domains.rs:228-252`.
- reasoning: The domain planners themselves return a fixed `Risk::Write` and `Permission::Write`, with no management detection (`vpn_clients::secrets::plan` and `wan::plan_password`). So `Gate::of(&plan)` would give the identical gate, and the "no fail-safe timer" consequence is not caused by the CLI. A credential CLI line leaves the configuration unsaved, so `applied(true)` matches what `result.unsaved` would report. Only the code shape differs.
- severity: info

### F-17 CONFIRMED
- checked: `cli/router_secrets.rs:34-60,146-164`, `cli/secret.rs:29-42`.
- reasoning: With `--read-login` and no `--read-password-file`, the read-only secret falls back to `KCC_PASSWORD`, the same value as the primary secret, with no prompt. Line 46 guards only the opposite combination.
- severity: low

### F-18 ADJUSTED
- checked: `crates/kcc/src/server.rs:58-75,642-645`, `cli/entry.rs:121-129`, a grep for `unsupported_command`, `RUST_GUIDELINES.md:1567-1580`.
- reasoning: `unsupported_command` has no caller, and its doc ("used by the binary dispatcher") is false. `ServerError(String)` drops `source()` and always maps to exit 1. The cited §7 rule ("Overreliance on `String` in APIs") is about `&str`/`impl Into<String>` parameters, not error types.
- severity: low
- correction: Same facts, but cite error-type guidance instead of §7's String-parameter rule.

### F-19 ADJUSTED
- checked: `crates/kcc/src/privileges.rs:87-107,198-289`, `crates/kcc/src/main.rs:15-19`.
- reasoning: `Ok(Report)` is dropped, and the "returned for logging" doc is false. An unprivileged user cannot clear the bounding set, so `bounding_cleared = false` and verification skips it, silently. Permitted, effective, inheritable and ambient are verified at zero and `no_new_privs` is set, so the full bounding set cannot be used to gain anything.
- severity: info

### F-20 ADJUSTED
- checked: `cli/entry.rs:33-93`, `cli/domains.rs:47-91`, `dom_net.rs:200-210`, `dom_wire.rs:28-40,188-200`.
- reasoning: The arms exist, but both matches are exhaustive with no wildcard, so a new variant forces a compile error. The hazard needs someone to deliberately reroute a variant.
- severity: info

### F-21 ADJUSTED
- checked: `cli/args_dom_family.rs:1-20`, `args_domains.rs:85-95`, the 13 "first commands, or the writes added here" comments, `CONTRIBUTING.md:47`.
- reasoning: The history-shaped names and comments are real. The split itself is partly motivated by CONTRIBUTING's ~250-line file ceiling, so "no behavioral reason" understates why it exists. This is a naming and style issue.
- severity: info

### F-22 CONFIRMED
- checked: `cli/files.rs:25-56`, its callers (`migrate.rs:105`, `migrate_apply.rs:85` with `fresh=false`).
- reasoning: The temporary file is a fixed `<path>.kcc-tmp`, opened with `create(true).truncate(true)` and no `O_EXCL`/`O_NOFOLLOW`, and mode 0600 applies only on creation. A pre-planted file keeps its permissions and is renamed into place. Linux `protected_symlinks` and `protected_regular` mitigate this in `/tmp`.
- severity: low

### F-23 CONFIRMED
- checked: `crates/kcc/src/server.rs:122-216,537-560`, `rmcp-server-kit transport.rs:3554,3583`.
- reasoning: SIGHUP is installed only inside the reload callback, which runs after `Services::open`, `JobRunner::open` and the log start that contacts routers. Until then SIGHUP's default action kills the process. `serve_result?` returns before `logs.shutdown()`, and `_updates` lives until the function returns, so it runs through the drain.
- severity: low

### F-24 ADJUSTED
- checked: `cli/context.rs:200-266`, `kcc-domain/src/configuration.rs:206-217`.
- reasoning: The comments do restate the code. `apply_permissions` can only return Read, Migrate, Write, Save or Destructive, and all five are in the table, so nothing is dropped today; drift is hypothetical.
- severity: info

### F-25 CONFIRMED
- checked: `cli/context.rs:425-430,446-456`, `server_migrations.rs:25-34`, `api_keys.rs:134-138`, `preset/source.rs:61-63`, `kcc-app/src/accounts.rs:41-51`.
- reasoning: The time code is copied five times despite `SystemClock`. `cli-{timestamp}` request ids collide across invocations within the same second.
- severity: low

### F-26 ADJUSTED
- checked: `cli/dom_core.rs:110-120`, `dom_wire.rs:60-70,201-205`, `kcc-domain/src/logging.rs:68-70`, `kcc-domain/src/diagnostics.rs:161`.
- reasoning: `logging::read_log` just calls `diagnostics::read_log`, so it is one code path with two CLI spellings. `wan password` and `vpn secret ppp` are separate planners, but both are `Risk::Write`. Removing a spelling breaks CLI compatibility.
- severity: info

### F-27 CONFIRMED
- checked: `crates/kcc/src/main.rs:20-26`, `cli/output.rs:1-6`.
- reasoning: Clap parse errors print as clap text before `--json` is known. That breaks the documented `{"error":{...}}` contract on stderr.
- severity: low

### F-28 ADJUSTED
- checked: `cli/secret.rs:113-126`, `cli/principal.rs:82-88`, `docs/BACKLOG.md:51`.
- reasoning: The root cause is correct: `ask()` hard-codes `("router","-")` without a terminal, and `require()` uses `denied("-")`. The symptom is already the backlog item `cli-confirm-missing` (BACKLOG:51), so it is not a new finding. It only adds the root cause and wider scope.
- severity: info

### F-29 ADJUSTED
- checked: `tests/cli_domain_writes/admin.rs:9-21`, `cli/output.rs:59-71`, `tests/cli/basics.rs:11`, `tests/cli/outbound.rs:55-66`, `tests/cli/health.rs:98-104`, `tests/cli/firewall_binding.rs:20-28`, `tests/serve.rs:432-445`.
- reasoning: `emit` pretty-prints (`"applied": true`), so `!contains("\"applied\":true")` cannot fail; that assertion is vacuous. The "R-MCP2 incident" label is real. `"[outbound] allowed_networks"` and serve.rs's `allowed_networks` pin a configuration key name, a machine identifier, so they are not prose pins. `"verification"` (a negative check) and `"SHA-256"` are weak text pins.
- severity: low
- correction: Drop `outbound.rs:62` and `serve.rs:440` from the prose-pin list.

### F-30 CONFIRMED
- checked: `tests/serve.rs:242-252`, `tests/cli/health.rs:31`, `serve_origin.rs:216`, `metrics_serve.rs:106`, `serve_bracket.rs:158-160,204-205`, `serve_bracket/process.rs:176-178`, `tests/source_guards.rs:29-41`, `main.rs:11-14`.
- reasoning: A port is bound, dropped and reused, which races. `write_master_key` is copied. `exit_within(3s) == None` is a fixed-window negative check. The source guard greps `main.rs`, which is why `#[expect(clippy::absolute_paths)]` is there. None of these are in BACKLOG's "Tests" list.
- severity: low

### F-31 CONFIRMED
- checked: `tests/live_smoke.rs:1-100`, AGENTS.md "Live" tier.
- reasoning: It checks the serial allowlist only, with no `test_device`/`KCC_LIVE_TARGET_CONFIG` check, even though its `#[ignore]` reason says "needs ... a test_device router". It is read-only.
- severity: info

## Summary
- **Counts:** 14 CONFIRMED (F-01, 02, 03, 05, 10, 15, 17, 22, 23, 25, 27, 30, 31, plus F-19 is not among them), 17 ADJUSTED, 0 REFUTED, 0 DUPLICATE. Precisely: CONFIRMED = F-01, F-02, F-03, F-05, F-10, F-15, F-17, F-22, F-23, F-25, F-27, F-30, F-31 (13). ADJUSTED = F-04, F-06, F-07, F-08, F-09, F-11, F-12, F-13, F-14, F-16, F-18, F-19, F-20, F-21, F-24, F-26, F-28, F-29 (18).
- **Final severities:** high 1 (F-01). Medium 6 (F-02, F-03, F-05, F-07, F-10, F-11). Low 16. Info 8 (F-16, F-19, F-20, F-21, F-24, F-26, F-28, F-31).
- **Context for several downgrades:** the CLI principal reads the master key (`context.rs:276`) and accepts any `--config`, so `[cli] role` is a guardrail, not a security boundary. That is why F-04, F-06 and F-13 drop to low.
- **NEW (MCP lane, likely high): `kcc_rci_read` hands out decodable router secrets to a `Read` role.** The tool requires only `Permission::Read` (`kcc-mcp/src/registry/definitions.rs:116-121`, `generic/rci.rs:190-210`). Nothing excludes `show running-config` (`support/validate.rs:61-77`). `rci_body_value` wraps a text answer as `{"text": ...}` (`support/errors.rs:116-125`), and `shape::redact_secrets` (`support/shape.rs:207-236`) redacts only by JSON key name, so the configuration text passes unmasked. NS3 is key-less reversible scrambling (`kcc-config/src/ns3.rs:42-70`). A `viewer` API key held by an AI assistant can therefore recover Wi-Fi PSKs and PPPoE/VPN passwords. That contradicts SECURITY.md's "treat [assistants] as untrusted users of their key's role" and the README's "MCP results carry redacted values".
- **NEW (low):** The README says kcc "refuses to run as root, under sudo", but `privileges.rs:249-260` refuses only root UIDs. Nothing checks `SUDO_*`, so `sudo -u <other> kcc ...` runs, and with `--config` it could choose any `[cli] role`.