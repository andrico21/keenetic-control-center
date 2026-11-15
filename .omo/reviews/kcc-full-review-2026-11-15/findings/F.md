## Lane F review: `crates/kcc` (CLI, process and composition root)

The review was read-only, at HEAD `349b7fb`. Every source file under `crates/kcc/src/**` was read in full. Of the tests, I read the harness and the files listed under Coverage, and searched the rest for specific patterns.

### F-01 Revoking a key or disabling a user from the CLI does not reach a running `kcc serve`
- severity: high
- kind: security
- rule: project rule (d) intent / overlay mcp-servers.md (revocation of credentials); none of the vendored rules names it directly
- evidence:
  - `crates/kcc/src/cli/api_keys.rs:71-76`
    ```rust
    ApiKeyCommand::Revoke { name } => {
        let removed = ctx.state().update(|document: &mut ApiKeysDocument| {
            let before = document.keys.len();
            document.keys.retain(|key| key.name != name);
    ```
  - `crates/kcc/src/cli/accounts.rs:89-90` disables the account in the state file only: `accounts.administer(&username, &AccountChange::Disabled(!enable))?`. The admin reset at `:145-151` does the same.
  - `crates/kcc/src/server.rs:136`: the keys are loaded once at startup, `AuthConfig::with_keys(api_key_entries(&services.state)...)`.
  - The Web does the extra step the CLI skips: `kcc-web/src/admin_keys.rs:304` calls `let warning = admin.reload_keys().await;`, and `kcc-web/src/admin_users.rs:495` calls `state.sessions().invalidate_user(&target.username).await`.
  - `kcc-web/src/authz.rs:168-180` takes the session from memory and never re-reads the account's `disabled` flag.
- impact: An operator runs `kcc apikey revoke leaked-agent` or `kcc user disable mallory` and gets "deleted"/"disabled" with exit 0. The running server keeps accepting the key until a SIGHUP or restart. Mallory's live Web sessions stay valid until their idle or absolute timeout, and a SIGHUP does not end them either. The README limitation mentions only `apikey create`.
- fix: Make the SIGHUP reload also drop sessions of disabled or reset accounts. Have the CLI print a localized "takes effect after SIGHUP or restart" note after revoke, disable and reset. Longer term, have the server re-check the key and the account against state on each request.
- confidence: high (INFERRED: that the kit keeps keys only in memory; this follows from `server.rs:136` and the explicit reload paths)

### F-02 `router edit` seals the new credential before the profile is validated
- severity: medium
- kind: bug
- rule: RUST_GUIDELINES.md §3 "Force construction through validated constructors"
- evidence:
  - `crates/kcc/src/cli/router_secrets.rs:119-122`
    ```rust
    let (mut profile, removed, changed) = plan.into_parts();
    point(store, &mut profile, &secrets)?;
    seal(store, &id, &secrets)?;
    services.registry().update(&role, profile).await?;
    ```
  - `router_edit.rs:71-72`: `profile.url = parse_url(&text)?;` accepts any URL. `kcc-app/src/registry.rs:560` (`profile.validate()?`) rejects a path other than `/` only inside `update`.
  - `sealed_path` is deterministic (`credentials.rs:321-327`), so the seal overwrites the live record.
- impact: `kcc router edit home --url http://192.168.1.10/ui --new-password --password-file new.pw` exits 4 ("url must be an http(s) origin"). The unchanged `home` profile now signs in with `new.pw`'s password, and the old sealed password is gone; the README invites users to delete their input files. The doc comment "a refused change writes nothing" (`router_secrets.rs:102`) is false. Unlike `add` (`:49`), `edit` also skips `outbound::check` for a new URL.
- fix: Call `profile.validate()` (plus `outbound::check` when the endpoint moves) before `seal`. Alternatively, seal to a temporary record and rename it only after `update` succeeds.
- confidence: high

### F-03 Session cookie loses `Secure` and `__Host-` in the HTTPS-proxy deployment
- severity: medium
- kind: security
- rule: project rule (e) "Web UI hardening"; overlay http-services.md
- evidence:
  - `crates/kcc/src/server.rs:138`: `let tls = config.server.tls_cert_path.is_some() && config.server.tls_key_path.is_some();`
  - `server.rs:467-471`
    ```rust
    let cookie_security = if tls {
        CookieSecurity::Tls
    } else {
        CookieSecurity::LoopbackHttp
    };
    ```
  - `kcc-app/src/settings.rs:900-901` allows a non-loopback plain listener when `public_https && !trusted_proxies.is_empty()`.
  - `kcc-web/src/session.rs:151-172`: `LoopbackHttp` documents "the listener is loopback-only" and emits no `; Secure`.
- impact: In the documented setup (https `public_url` behind a trusted TLS proxy), browsers see HTTPS but get a `kcc_session` cookie without `Secure`. Any plain-HTTP request to that host, such as a proxy's http→https redirect or a forced request from a LAN attacker, sends the session cookie in cleartext.
- fix: Pick `CookieSecurity::Tls` when `tls || public_url.scheme() == "https"`, and pass the same flag to `security_headers`.
- confidence: medium-high (the cookie path was not exercised; no test covers the proxy cookie)

### F-04 `kcc show running-config` hands out secrets with only `Read`
- severity: medium
- kind: security
- rule: project rule (d) "Secrets … never reach … tool results"; README "revealing a secret needs the RevealSecrets permission"
- evidence:
  - `crates/kcc/src/cli/fleet.rs:62-82`: `ctx.target(&services, &[Permission::Read])` validates `show {words}` and calls `print_body(ctx, body)`.
  - `fleet.rs:127-136` prints the text or JSON unchanged.
  - `rci.rs:41-59` (`rci get`) does the same.
  - Compare `persist.rs:276`, where the full backup needs `Permission::Read, Permission::RevealSecrets`. `kcc-web/src/advanced/deliver.rs:330-336` masks answers unless `RevealSecrets`, and `catalog/5.1/show.json` contains `"show running-config"`.
- impact: A CLI principal limited to `Read` (for example a scoped `[cli] role`) gets the full running configuration, with whatever registered secrets it carries. The same principal is refused `backup get --output`.
- fix: Pass `show running-config` and `show startup-config` text through `redact::redacted_copy`, and mask JSON answers the way the Web viewer does, unless the role grants `RevealSecrets`.
- confidence: medium (INFERRED: which secrets appear in the live text). Cross-lane, INFERRED: `kcc-mcp/src/generic/rci.rs:190-210` returns `rci_body_value(body)` unmasked with `Permission::Read`.

### F-05 `kcc mcp stdio` has no signal handling, so a signal skips the bracket wait, job drain and audit flush
- severity: medium
- kind: bug
- rule: RUST_GUIDELINES.md §5 "Audit Drop impls of async resources"; BACKLOG "Known gaps" (CLI SIGINT) claims stdio waits
- evidence:
  - `crates/kcc/src/server.rs:234-235`
    ```rust
    let served = serve_stdio(handler).await.map_err(error);
    crate::server_shutdown::wait_for_brackets(services.workflow.brackets()).await;
    ```
  - `rmcp-server-kit-3.21.1/src/transport.rs:5916-5937`: `serve_stdio` only awaits `service.waiting()` and installs no signal handler.
- impact: An MCP client that stops its child with SIGTERM (or a Ctrl-C) during a management change kills the process at once. The disarm is never sent, so the router's timer rolls back an applied change later. Queued audit entries are lost and jobs are not drained. BACKLOG line 43 ("kcc mcp stdio do[es] wait for open brackets") holds only when stdin reaches EOF.
- fix: Wrap `serve_stdio` in a `select!` with `tokio::signal::ctrl_c()` and a SIGTERM stream, then fall through to the existing wait, drain and flush.
- confidence: high

### F-06 CLI `apikey create` and `user add` skip the role-dominance check the Web enforces
- severity: medium
- kind: security
- rule: project rule "same permission checks on every surface" (README "Permissions"); duplication
- evidence:
  - `crates/kcc/src/cli/api_keys.rs:31-33`
    ```rust
    ApiKeyCommand::Create { name, role } => {
        known_role(ctx, &role)?;
        let created = create_api_key(ctx.state(), name.clone(), role.clone(), now())?;
    ```
  - `accounts.rs:42-48`: `user add` likewise checks only that the role exists.
  - The Web checks `if !dominates(user.role(), &role)` (`kcc-web/src/admin_keys.rs:212`) and, for revoke, `manages(...)` (`:333-346`).
- impact: With a custom `[cli] role` holding `ManageUsers` but not `Destructive` or `RevealSecrets`, or one scoped to some routers, `kcc apikey create x --role admin` mints an unscoped admin key and `kcc user add` an admin account. Revoke also lacks the Web's `manages` check. The default CLI role is `admin`, so only custom configurations are exposed.
- fix: Move `dominates` into `kcc_app::api_keys::create_api_key` and `AccountStore::create` (taking the actor's role), or call it from the CLI before both.
- confidence: high

### F-07 `backup diff` compares sets of redacted lines, so it misses real changes, and its help text says "Count"
- severity: medium
- kind: bug
- rule: none (correctness)
- evidence:
  - `crates/kcc/src/cli/persist.rs:176-186`
    ```rust
    let before = redacted_lines(services.backups().get(&router, &older)?.expose_secret())?;
    let after = redacted_lines(services.backups().get(&router, &newer)?.expose_secret())?;
    let removed = before.iter().filter(|line| !after.contains(line))...
    let added = after.iter().filter(|line| !before.contains(line))...
    ```
  - `args_fleet.rs:139`: `/// Count the lines that differ between two backups.`
  - The Web compares SHA-256 digests of the full text (`kcc-web/src/config_page/text.rs:36-43`).
- impact: A changed password, PSK or WireGuard key becomes `<redacted>` on both sides and is invisible. A repeated line (`up`, `exit`, `shutdown`) added to one block while it exists elsewhere is also invisible. `kcc backup diff` prints nothing (exit 0) for backups that differ. The help promises a count; the command prints lines.
- fix: Diff the full-text digests in order (as the Web does), print `shown[i]`, and fix the help text.
- confidence: high

### F-08 The redaction pipeline exists three times
- severity: medium
- kind: duplication
- rule: AI anti-pattern (copy-paste that drifts)
- evidence:
  - `crates/kcc/src/cli/redact.rs:47-63` (`redacted` + `mask`)
  - `kcc-web/src/config_page/text.rs:63-83` (`redacted` + `mask`, identical)
  - `kcc-mcp/src/config_tools/backups.rs:156-178` (same, with a literal `"<redacted>"`)
  - The CLI's `redacted_copy` (`redact.rs:19-28`) re-implements `config_page::text::redacted_copy`, including the `"kcc-redacted"` mark, which the Web keeps as `REDACTED_MARK`.
- impact: A security-relevant transform maintained in three places. The copies have already drifted in how diffs use them (F-07).
- fix: Move `redacted`, `mask` and `redacted_copy` (with the mark constant) into `kcc_config::secrets` and call that from all three.
- confidence: high

### F-09 Two composition roots, and some CLI commands build them twice
- severity: medium
- kind: duplication
- rule: RUST_GUIDELINES.md §7 / AI anti-pattern; focus item "one ChangeWorkflow per process"
- evidence:
  - `crates/kcc/src/cli/persist.rs:144`, then `:148` `backup_create(ctx, &reason)`, which runs `ctx.services()` again at `:227`. `backup_get` does the same at `:262`.
  - `accounts.rs:33`, then `passwd` runs `ctx.services()` again at `:128`.
  - `context.rs:275-315` repeats `server.rs:337-419` (credential migration, registry, audit, backups, workflow).
  - `server.rs:349,375,451,491` loads the master key four times, mixing `duplicate()` and `MasterKey::load`.
- impact: `kcc backup create`, `kcc backup get` and `kcc user passwd` spawn two `AuditLog` writers and two `ChangeWorkflow`s, run credential migration twice, and print the external-password-file note twice on stderr. The two roots can drift; the CLI already reports differently than the server (stderr notes versus tracing).
- fix: Pass `&Services` into `backup_create`, `backup_get` and `passwd`. Extract one `kcc_app` builder used by both `Services::open` and `Ctx::services`, and load the key once with `duplicate()`.
- confidence: high

### F-10 User-visible English strings outside `kcc-i18n`
- severity: medium
- kind: guideline
- rule: project rule (f) "Every user-visible string comes from kcc-i18n"
- evidence (each appears under a localized headline):
  - `persist.rs:96` `"--seconds must be 300..=3600"`
  - `persist.rs:237` `"startup configuration is not UTF-8"`
  - `migrate_plan.rs:161` and `:176`
  - `preset/source.rs:53` and `:139`
  - `dom_routes.rs:103`
  - `dom_vpn.rs:130`
  - `principal.rs:42` `"[cli] role {:?} does not exist"`
  - `tls.rs:55`, `:117`, `:154`
  - `migrate_apply.rs:77`
  - `preset/run.rs:107`
  - `entry.rs:106`
  - every `ServerError(format!(...))` in `server.rs` (`:129`, `:315`, `:428`, `:464`, `:511`)
- impact: `--lang ru`, `de`, `kk` and the other locales get English detail lines. `Detail::Text` is documented as typed-error text, but these are hand-written sentences.
- fix: Add keys and use `Failure::message`.
- confidence: high

### F-11 `dhcp pool` defaults the default router to the first leased address and wipes options on replace
- severity: medium
- kind: bug
- rule: none (wrong router command from defaults)
- evidence:
  - `crates/kcc/src/cli/dom_lan.rs:106-110`
    ```rust
    let mut pool = PoolConfig::new(name, begin, end)
        .with_default_router(gateway.unwrap_or(begin))
        .with_dns_servers(dns)
        .with_lease_seconds(lease_seconds)
    ```
  - `args_dom_lan.rs:46` "Create or replace … options not given take their defaults"; `:59` "(default: the first address)"
  - The Web form requires both gateway and interface (`kcc-web/src/clients_pages/dhcp_forms.rs:136-144`).
- impact: `kcc dhcp pool _WEBADMIN --begin 192.168.1.33 --end 192.168.1.120` advertises 192.168.1.33 (a client) as the gateway and clears the DNS servers. The LAN loses internet on lease renewal. Read-back passes because the router applied exactly that.
- fix: Make `--gateway` required (as the Web does), or default it to the pool interface's own address. Refuse to replace an existing pool without the options the user omitted.
- confidence: high

### F-12 Inconsistent confirmation gates for the same action
- severity: medium
- kind: bug
- rule: focus item "confirmation gates on every write"
- evidence:
  - `migrate_apply.rs:49`: `secret::confirm(..., Risk::Management, &target, false)` also covers `--finish rollback`.
  - `preset/run.rs:75` (Management confirm), then `:123-125` `Finish::Rollback => { ctx.authorize_recovery(...)?; applier.rollback()`.
  - By contrast, `migrate.rs:170-171` `migrate finish rollback`, `preset/finish.rs:91` and `persist.rs:92-93` `config failsafe rollback` all use `Gate::new(Risk::Destructive, ...)`, which requires `--confirm-destructive`.
  - `preset/manage.rs:241-250` deletes a preset with no confirmation, while the Web asks for the typed name (`presets_page/delete.rs:51-67`).
- impact: The same rollback, which reboots the router into its saved configuration, needs only `--yes` on `apply`/`copy` but `--confirm-destructive <id>` on `finish`. A scripted `--yes` therefore also authorizes a rollback.
- fix: When `finish == Rollback`, also run `confirm(Risk::Destructive, ...)`. Give `preset delete` a confirmation.
- confidence: high

### F-13 Permission refusals on local-state commands are not audited
- severity: medium
- kind: security
- rule: README "every … refusal audited"; consistency with `Ctx::target_named`
- evidence:
  - `persist.rs:276-277`
    ```rust
    drop(ctx.principal()
        .authorize(&[Permission::Read, Permission::RevealSecrets], &[&router])?,
    ```
  - The same pattern without an audit appears at `persist.rs:150,175,199,266`, `routers.rs:42-44,72`, `router_secrets.rs:35-37,105-107`, `preset/manage.rs:57-68`, `accounts.rs:32,186`, `api_keys.rs:27,108`.
  - The audited path for comparison: `context.rs:385-392` (`self.attempt(services, "cli.refused", Some(&id), Attempt::Forbidden)`).
- impact: A refused attempt to export a full backup with secrets, delete a backup, or add, edit or remove a router leaves no audit entry. Router commands and the Web do audit refusals. `preset show --reveal` audits, but with a different shape (`ctx.audit(..., "forbidden")`).
- fix: Route every refusal through one `Ctx::authorize_audited(services, perms, routers)` helper.
- confidence: high

### F-14 Two parsers for `--from`, and preset sources copy the startup configuration into a plain `Vec<u8>`
- severity: medium
- kind: guideline
- rule: project rule (d) secrets in secrecy/zeroize types; duplication
- evidence:
  - `preset/source.rs:120-130`
    ```rust
    .get(id, name)?.expose_secret().as_bytes().to_vec())
    ...
    let bytes = client.download_config(ConfigKind::Startup).await?;
    Ok(bytes.expose_secret().to_vec())
    ```
  - `migrate_plan.rs:127-163` keeps `SecretBytes` and requires `router:<id>`. `source.rs:97-100` accepts a bare id.
  - `source.rs:94` takes the router id from `split_once('/')`, but `:119` takes the name from `rsplit_once('/')`.
- impact: Full startup configurations (password hashes, PSKs, private keys) sit in non-zeroizing heap memory for every `preset capture`, `preset apply` and `copy`. Users must learn two grammars for the same option.
- fix: One `--from` parser and reader returning `SecretBytes`, shared by migrate and preset.
- confidence: high

### F-15 Rollback results report `"unsaved": true`
- severity: low
- kind: bug
- rule: none (JSON output correctness)
- evidence: `persist.rs:130` `Ok(applied(step == Close::Rollback))`; `migrate.rs:185` does the same. `applied(unsaved)` builds `json!({ "applied": true, "unsaved": unsaved })` (`change.rs:286-288`).
- impact: `kcc --json config failsafe rollback` and `migrate finish rollback` claim unsaved changes exist after the router restored its saved configuration. Scripts that save on `unsaved` will act wrongly.
- fix: Use `applied(false)` for rollback, or take the flag from the closing result.
- confidence: medium

### F-16 VPN secret writes use a fixed gate and a hard-coded `unsaved`
- severity: low
- kind: bug
- rule: consistency with the domain planner (compare the BACKLOG item for Web `dns_checks.rs:82`)
- evidence: `dom_vpn.rs:101-105`
  ```rust
  let gate = Gate::new(Risk::Write, Permission::Write, false);
  session.change(gate, async move |changes, router| {
      client_secrets::apply(changes, router, &target, value).await?;
      Ok(applied(true))
  ```
  `dom_vpn_server.rs:54-58` is the same.
- impact: No management detection, so there is no fail-safe timer when the tunnel carries kcc's own traffic, and `unsaved` is always true. `vpn secret ppp X` and `wan password X` reach the same router setting through two domain paths.
- fix: Have `client_secrets` and `server_secrets` return a `ChangeOp` (risk from the planner) and use `Gate::of` plus `result.unsaved`.
- confidence: medium

### F-17 Credential misbinding through the single `KCC_PASSWORD` fallback
- severity: low
- kind: bug
- rule: none
- evidence: `router_secrets.rs:56-59` reads the primary credential and then the `ReadPassword` one through `secret(...)`. Both fall back to `read_secret`, which returns `KCC_PASSWORD` when no file is given (`secret.rs:33-35`).
- impact: `KCC_PASSWORD=adminpw kcc router add home --url … --read-login ro` silently seals the admin password as the read-only password, with no prompt. Polling then fails to authenticate.
- fix: Use `KCC_PASSWORD` for only one secret per invocation, or refuse when two secrets need it.
- confidence: high

### F-18 `ServerError` is a stringly-typed error, and one constructor is dead with a false doc
- severity: low
- kind: dead-code
- rule: RUST_GUIDELINES.md §7 "Overreliance on String in APIs"; §2
- evidence: `server.rs:66` `pub struct ServerError(String);`; `server.rs:643-645` `ServerError(source.to_string())`; `server.rs:69-74` `unsupported_command()` ("used by the binary dispatcher"), which nothing calls.
- impact: `source()` chains are lost and `kcc serve` failures cannot be classified (always exit 1). The doc comment states something untrue.
- fix: Delete `unsupported_command`. Make `ServerError` an enum wrapping `#[source]` errors.
- confidence: high

### F-19 The privilege `Report` is discarded, so a kept bounding set is never reported
- severity: low
- kind: dead-code
- rule: comment that lies (AI anti-pattern)
- evidence: `privileges.rs:87` "returned for logging after tracing starts"; `main.rs:16` `if let Err(error) = kcc::privileges::enforce()`, where the `Ok(Report)` is dropped. `privileges.rs:208-210` sets `bounding_cleared = false` on failure.
- impact: On a host without `CAP_SETPCAP`, the bounding set stays full and nothing says so. The README states "drops every capability".
- fix: Keep the report and log it after tracing starts, or delete `Report`.
- confidence: high

### F-20 Dispatchers have arms that return success for "unreachable" variants
- severity: low
- kind: anti-pattern
- rule: AI anti-pattern "wildcard arms hiding variants"
- evidence: `entry.rs:77` `Command::Serve | Command::Mcp(_) => Ok(()),`; `domains.rs:76-90` (15 variants mapped to `=> Ok(())`); `dom_net.rs:206`; `dom_wire.rs:34,195`.
- impact: Moving a variant without updating the second match makes the command exit 0 having done nothing.
- fix: Destructure into disjoint sub-enums, or make those arms `unreachable` through a typed split.
- confidence: high

### F-21 `Family<B, W>` encodes development history
- severity: low
- kind: anti-pattern
- rule: AI anti-pattern (speculative abstraction; comments that describe history)
- evidence: `args_dom_family.rs:6-19` ("The domain's reads and first writes" / "The domain's remaining writes"); `dom_admin.rs:29` "the first commands, or the writes added here" (repeated about 12 times); nested `Family<VpnCommand, Family<VpnWriteCommand, VpnSecretCommand>>` (`args_domains.rs:91`).
- impact: Every domain is split across two or three modules and dispatch functions for no behavioral reason.
- fix: Flatten each domain into one subcommand enum.
- confidence: high

### F-22 `write_private` reuses a predictable temporary file and follows symlinks
- severity: low
- kind: security
- rule: RUST_GUIDELINES.md §10 "Validate … at system boundaries"
- evidence: `files.rs:32-39`
  ```rust
  let temporary = path.with_extension("kcc-tmp");
  ...
  let _: &mut OpenOptions = options.create(true).truncate(true);
  ```
- impact: `migrate plan --out /tmp/p.json` and `migrate report --out` open `/tmp/p.kcc-tmp` without `O_EXCL`, so a pre-planted file or symlink is truncated or written through (Linux `protected_symlinks` mitigates this). `a.json` and `a.html` share one temporary file.
- fix: Create the temporary file with `create_new(true)` and a random suffix in the same directory.
- confidence: medium

### F-23 Startup and shutdown edges in `run_serve`
- severity: low
- kind: bug
- rule: RUST_GUIDELINES.md §5 "Audit Drop impls of async resources"
- evidence:
  - The SIGHUP handler is installed only inside the kit's reload callback (`server.rs:544-558`), after `Services::open`, which contacts routers.
  - `server.rs:211-214` returns at `serve_result?;` before `logs.shutdown().await`.
  - `_updates` (`:155`) keeps polling routers through the 40 s drain.
- impact: A `systemctl reload` during startup kills `kcc serve`, because SIGHUP's default action is termination. When the transport fails, the log sinks are not flushed.
- fix: Install the SIGHUP stream at the top of `run_serve`, shut the logs down before `serve_result?`, and abort `_updates` once shutdown starts.
- confidence: medium

### F-24 `authorize_apply` restates code in comments and repeats a permission-label table
- severity: low
- kind: anti-pattern
- rule: AI anti-pattern "comments that restate code"
- evidence: `context.rs:216-235` ("// Check if all required permissions are granted …", "// Compute the subset …") and a five-entry `Permission → WEB_ADMIN_PERMISSION_*` table inline.
- impact: Noise, plus a mapping that will drift when a permission is added (a missing one is silently dropped by `filter_map`).
- fix: Delete the comments and use one shared permission-label function from `kcc-i18n` or `kcc-web`.
- confidence: high

### F-25 Unix-time helper copied five times; audit request ids are not unique
- severity: low
- kind: duplication
- rule: AI anti-pattern (copy-paste)
- evidence: `context.rs:426,447`, `server_migrations.rs:25-27`, `api_keys.rs:134-138` and `preset/source.rs:61-63` each repeat `SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, ...)`, while `kcc_app::accounts::Clock` exists. Request ids are built as `format!("cli-{timestamp}")` (`context.rs:430,456`).
- impact: Duplicated code, and audit entries from the same second share a request id.
- fix: Use `SystemClock::unix_seconds()` and a random or sequenced request id.
- confidence: high

### F-26 Duplicated CLI commands
- severity: low
- kind: duplication
- rule: none
- evidence: `kcc diagnostics log` (`dom_core.rs:117-119`, `diagnostics::read_log`) and `kcc log read` (`dom_wire.rs:67-68`, `logging::read_log`). `wan password` and `vpn secret ppp` (see F-16).
- impact: Two help entries and two code paths for one operation.
- fix: Keep one of each.
- confidence: high

### F-27 `--json` contract is broken for argument errors
- severity: low
- kind: bug
- rule: output contract in `output.rs:3-6`
- evidence: `main.rs:20-25` calls `drop(error.print()); return ExitCode::from(...)`.
- impact: `kcc --json info --bogus` prints clap's text, not `{"error":{...}}`.
- fix: When `--json` is present in argv, wrap clap errors in the JSON envelope.
- confidence: high

### F-28 Root cause of the `-` router in confirmation messages (KNOWN-BACKLOG)
- severity: low
- kind: bug
- rule: BACKLOG `cli-confirm-missing`
- evidence: `secret.rs:118-126` `ask()` returns `&[("router", "-")]` whenever stdin is not a terminal. Also `dom_jobs.rs:242-243`, `principal.rs:86` and `preset/manage.rs:33`.
- impact: Every non-interactive confirmation refusal prints `-`, not just `migrate apply`.
- fix: Pass the router into `ask`.
- confidence: high

### F-29 Test quality: a vacuous assertion, prose pins and a review label
- severity: low
- kind: test-quality
- rule: RUST_GUIDELINES.md §13; overlay rule "never pin prose"
- evidence:
  - `tests/cli_domain_writes/admin.rs:15` `assert!(!run.stdout.contains("\"applied\":true"))` can never fail, because `emit` pretty-prints (`"applied": true`).
  - English prose pins: `tests/cli/outbound.rs:62` (`"[outbound] allowed_networks"`), `permission_gates/apply.rs:228` (`"Missing permissions: ."`), `cli/health.rs:103` (`"SHA-256"`), `firewall_binding.rs:24` (`"verification"`), `serve.rs:440`.
  - Review label: `cli/basics.rs:11` "The R-MCP2 incident payload".
- impact: These tests pass whatever the code does, or break on wording-only changes.
- fix: Parse the JSON and compare fields, assert localized `tr(...)` strings, and drop the label.
- confidence: high

### F-30 Test quality: port race, copied helpers, time windows, source greps
- severity: low
- kind: test-quality
- rule: overlay test discipline (nondeterminism)
- evidence:
  - `serve.rs:242-247` binds, drops and reuses a port. The same is repeated in `serve_origin.rs:211`, `metrics_serve.rs:100`, `cli/health.rs:31`, `serve_refresh/support.rs:153` and `serve_bracket/process.rs:91`, and `write_master_key` is copied three times.
  - `serve_bracket.rs:158,204` `exit_within(Duration::from_secs(3))` asserts "still running" over a fixed window.
  - `source_guards.rs:29-41` greps `main.rs` text, which forces `#[expect(clippy::absolute_paths)]` on `main` (`main.rs:11-14`).
- impact: Parallel runs can collide on ports, and the 3 s window passes trivially on a slow machine.
- fix: Pass `listen_port = 0` and read the bound port from the log, put shared helpers in a `tests/support` module, and wait on the drain log line instead of the window.
- confidence: medium

### F-31 `live_smoke` checks only the serial allowlist, not `test_device`
- severity: info
- kind: guideline
- rule: project rule (g)
- evidence: `tests/live_smoke.rs:61-92` connects using `KCC_LIVE_URL` and `verify_serial`, with no `test_device` profile check. The write suites do check it (`live_domains/gate.rs:96`, `live_migration/guard.rs:74`).
- impact: The read-only smoke test can run against any allowlisted router. Writes are correctly gated.
- fix: Require the `KCC_LIVE_TARGET_CONFIG` profile check here too, or document the exemption in the overlay.
- confidence: high

## Coverage
- **Read in full (`src/`):**
  - `main.rs`, `lib.rs`, `cli.rs`, `privileges.rs`, `server.rs`, `server_shutdown.rs`, `server_tasks.rs`, `server_origins.rs`, `server_outbound.rs`, `server_tls_key.rs`, `server_migrations.rs`
  - every file under `cli/`: `entry`, `args`, `args_admin`, `args_router`, `args_fleet`, `args_migrate`, `args_dom_family`, `args_dom_jobs`, `args_dom_admin`, `args_dom_lan`, `args_dom_link`, `args_dom_vpn_server`, `args_domains`, `args_domains_wire`, `context`, `change`, `closing`, `exit`, `exit_from`, `output`, `principal`, `secret`, `files`, `persist`, `dom_*` (all 13), `domains`, `fleet`, `rci`, `outbound`, `redact`, `issues`, `tls`, `accounts`, `api_keys`, `routers`, `router_secrets`, `router_edit`, `migrate`, `migrate_plan`, `migrate_apply`, `migrate_apply/migrate_apply_finish`, `preset.rs` and `preset/*`
- **Skimmed (`src/`):** `args_dom_dns.rs`, `args_domains_net.rs` and `args_dom_vpn.rs` (doc comments and argument constraints).
- **Tests read in full:** `cli/support.rs`, `cli/basics.rs`, `source_guards.rs`, `docs.rs`, `docs/markdown.rs` (first 60 lines), `docs/firmware.rs`, `serve.rs` (helpers and the warning test), `serve_bracket.rs:140-217`, `serve_bracket/disconnect.rs:140-208`, `cli_domain_writes/admin.rs:1-30`, `cli/firewall_binding.rs:1-40`.
- **Tests searched:** all of `cli/`, `cli_domain_writes/`, `serve*`, `metrics_serve*` and `docs/` for sleeps, prose pins, port reservation and labels.
- **Live tests:** the `live_*.rs` gates only, for `test_device` and the serial allowlist.
- **Not read:** the remaining test bodies (`cli/closing*`, `migrate*`, `permission_gates/*`, `preset_*`, `serve_refresh/*`, `metrics_serve/*`, `cli_presets/*`, `cli_accounts_reset.rs`, `cli_finish_recovery.rs`) and the bodies of the live suites.

## Clean
- Linux privilege floor: it runs before the runtime exists, clears the sets in a safe order, re-reads `/proc` to verify, and refuses if more than one thread exists or `NoNewPrivs` is unset.
- Exit-code mapping is centralized in `exit.rs`/`exit_from.rs`, matches the documented codes, and `Failure` carries no secrets.
- `confirm()`: `--yes` never stands in for a destructive confirmation; a wrong `--confirm-destructive` id is refused; missing confirmations are audited through `Ctx::confirmed`.
- `change::run_completed` authorizes before it confirms, takes the lease, runs the bracket via `guarded`, and audits failed attempts with `fail_safe_armed`.
- Raw RCI: every path is validated against the catalog before sending, the body is capped at 256 KiB and batches at 50, and DELETE is forced to at least Destructive.
- Outbound policy refusals are explained before anything is stored (`router add`, `test`, targets).
- WireGuard import reads through `open_secret_file` with a size bound into `Zeroizing`; secret files readable by others are refused.
- `admin init` prints the password once through a zeroized buffer; `apikey list` never prints hashes.
- The `healthcheck` TLS client pins the configured leaf certificate and installs no redirect or proxy.
- `kcc serve` shutdown order: transport, then a 10 s bracket grace, then a 30 s job drain, then a bounded audit flush; a dead audit writer triggers a graceful stop; the server state lock prevents a second `serve`.
- Migration and preset applies reserve the lease before the job record exists and audit a busy router.
- The live write suites gate on a `test_device = true` profile and the serial allowlist before any write.