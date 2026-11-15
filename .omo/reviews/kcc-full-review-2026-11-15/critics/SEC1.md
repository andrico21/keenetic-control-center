### SEC1-01 CONFIRMED
- checked: `crates/kcc-mcp/src/registry/definitions.rs:116-121`, `crates/kcc-mcp/src/generic/rci.rs:1-230`, `crates/kcc-mcp/src/generic/router.rs:228-245`, `crates/kcc-mcp/src/support/errors.rs:114-124`, `crates/kcc-mcp/src/support/shape.rs:160-236`, `crates/kcc-catalog/src/runtime.rs:120-169`, `catalog/5.1/show.json:7812-7860`, `crates/kcc-rci/src/engine.rs:301-413,510-533`, `crates/kcc-rci/src/lib.rs:590-620`, `crates/kcc-web/src/authz.rs:150-300`, `crates/kcc-web/src/page_kit/gate.rs:17-31`, `crates/kcc-web/src/advanced/execute.rs:40-110`, `crates/kcc-web/src/advanced/deliver.rs:198-340`, `crates/kcc-web/src/advanced/viewer.rs:60-125`, `crates/kcc-web/src/page_kit/secret.rs:1-45`, `crates/kcc-domain/src/firewall/read.rs:50-66`, `crates/kcc-web/src/config_page/store.rs:233-245`, `crates/kcc-config/src/secrets.rs:140-150`, `docs/PRIVACY.md:63-65`, `docs/BACKLOG.md:18`, `README.md:163`.
- reasoning: `show running-config` is in the catalog with `kind: Show`. It is not on the destructive or management lists, so `risk()` gives `Risk::Read`. MCP `rci_read` checks only `authorize_host(Permission::Read, …)`, and the Web explorer route and handler need only `command_permissions(Risk::Read) = [Read]`. `RciResponse::from_value` keeps the whole JSON value. MCP `redact_secrets` and Web `mask` both match on key names only, and text bodies are shown verbatim, so configuration lines under any non-secret key such as `message` pass through unchanged. Web `reveal` (RevealSecrets) only controls name-based masking, so it gives no protection here. Every other path to the same text redacts it or needs RevealSecrets: firewall read redacts the AST, explorer preview uses `redact`/`ns3_redacted`, and the full backup download needs RevealSecrets. The configuration does hold plain-text secrets as well as ns3 blobs (the `secrets.rs` test fixture has `web-api password delta`).
- severity: high. The exact reply shape is unproven on hardware (BACKLOG:18 lists only the shape, not this exposure). Whatever the shape, nothing on these paths redacts configuration text.

### SEC1-02 CONFIRMED
- checked: `crates/kcc-web/src/auth.rs:47-55,170-240,357-380,490-510`, `crates/kcc-app/src/accounts.rs:370-420`, `crates/kcc-app/src/audit.rs:20-60,140-160`, `crates/kcc-app/src/audit/writer.rs` (grep for size bounds), `crates/kcc-web/src/lib.rs:220,562`, `crates/kcc/src/server.rs:135-150`, `rmcp-server-kit-3.21.1/src/config.rs:554-565`, `transport.rs:2339-2375`, `crates/kcc/src/server_shutdown.rs:35-58`, `crates/kcc-web/src/admin_audit.rs:110-116,285-365`.
- reasoning: `LoginForm.username` is an unbounded `String`. An unknown user goes through dummy Argon2 to `Authentication::Invalid`, then `login_failure`, then `audit(…, &username, …)`, and finally `Actor::new(ActorKind::Web, username.to_owned())`, which is `const` and copies the name unchanged. Nothing between the 1 MiB body limit and the audit writer bounds the size. The lockout counter applies only to existing accounts, so it never stops this. Rotation does not delete live data, retention is age-based (365 days), and when the writer closes, `serve_until_shutdown` stops the server. The admin audit view and export load and verify the whole log.
- severity: high. Throughput is lower than 600 MiB/min/IP because every attempt runs dummy Argon2 under the users-file lock. It is still several MiB per second per attacker, enough to fill a disk within hours.

### SEC1-03 ADJUSTED
- checked: `crates/kcc/src/server.rs:138,148,455-480`, `crates/kcc-app/src/settings.rs:878-910`, `crates/kcc-web/src/session.rs:157-195`, `crates/kcc-web/src/csp.rs:30-48`, `docs/SECURITY.md:86-88`, `docs/CONFIG.md:60-63`, `deploy/podman/kcc.toml.example`.
- reasoning: The code matches the finding. `tls` is derived only from `tls_cert_path`/`tls_key_path`, and `CookieSecurity::LoopbackHttp` is used whenever it is false. `web_allowed_origins` explicitly allows a non-loopback Web UI with `public_url` https plus `trusted_proxies` and no listener TLS, and that mode is documented. In that mode the cookie is `kcc_session=…; HttpOnly; SameSite=Strict`, with no `Secure` and no `__Host-` prefix. No other code path chooses `CookieSecurity::Tls`.
- severity: medium
- correction: Exploiting this needs an active or observing network attacker and a browser making a plain-HTTP request to that host. It also applies only to the HTTPS-proxy mode, not to the shipped Podman example, which uses listener TLS. The control is weakened, not fully defeated, so medium rather than high. The fix stands: derive `CookieSecurity` and the CSP from `tls || public_url.scheme == "https"`, computed once in `Config`.

### SEC1-04 CONFIRMED
- checked: `crates/kcc-mcp/src/support/shape.rs:160-236`, `crates/kcc-web/src/page_kit/secret.rs:13-80`, `catalog/5.1/interface.json:21648-21672,22406-22420`, `catalog/5.1/crypto.json:2184-2200`, `catalog/5.1/snmp.json:58-82`, `docs/PRIVACY.md:63-65`.
- reasoning: The MCP list matches by substring on `private_key` with an underscore, while the catalog arguments are `private-key`, `obfs-key`, `preshare-key` (which contains neither `preshared` nor `psk`) and `community`. None of these is redacted by MCP. The Web catches all four through `-key` and the exact `community`, so the two classifiers have drifted, and PRIVACY.md promises "private key … always replaced". `shape()` is the only redaction applied to `kcc_rci_read` results, including GETs of setting nodes.
- severity: medium. It is inferred that real read replies carry these key names.

### SEC1-05 CONFIRMED
- checked: `crates/kcc/src/cli/accounts.rs:80-150`, `crates/kcc-web/src/authz.rs:159-200`, `crates/kcc-web/src/session.rs:313-410`, `crates/kcc/src/server.rs:581-597`, `docs/SECURITY.md:101-107`.
- reasoning: The middleware checks only that the session exists and that its role name still resolves. It never checks whether the account still exists, is enabled, or has changed its password. `invalidate_user` is called only from `admin_users.rs`. The SIGHUP `reload` reloads roles and keys but not sessions or accounts, and the CLI runs as a separate process with no channel to `kcc serve`. SECURITY.md:106-107 says "a password or role change ends the account's other sessions", and that does not hold for CLI changes.
- severity: medium

### SEC1-06 CONFIRMED
- checked: `crates/kcc-web/src/system_pages/logs.rs:140-175`, `crates/kcc-web/src/overview.rs:214-227`, `crates/kcc-web/src/dashboard.rs:195-240`, `crates/kcc-web/src/sse.rs` (all), `crates/kcc-web/src/session.rs:313-410`.
- reasoning: Authorization runs once, when the stream opens. `guarded` only forwards events while it holds the permit. The `invalidate*` functions only remove HashMap entries and signal nothing to open streams, and the stream limiter is not tied to session validity. Streams have no lifetime cap.
- severity: medium

### SEC1-07 CONFIRMED
- checked: `crates/kcc-web/src/auth.rs:134-168,357-380`, `crates/kcc-web/src/session.rs:270-272,410-490`, `crates/kcc/src/server.rs:147`.
- reasoning: A GET with no cookie, and every failed POST without a live session, calls `create_anonymous()`, which is an unconditional insert. Sessions are evicted only by the idle sweeper, which runs every `min(idle, absolute)/2`, i.e. 15 minutes by default. The only bound is the kit's per-IP limit of 600/min. One IPv4 client stays around 18k sessions (a few MB), but a LAN client using many IPv6 addresses is effectively unbounded.
- severity: medium (borderline low for a single address)

### SEC1-08 ADJUSTED
- checked: `crates/kcc-web/src/authz.rs:247-262`, `crates/kcc-web/src/admin_audit.rs:100-120,285-310`, `crates/kcc-app/src/permissions.rs:30-80`, `crates/kcc-app/src/registry.rs:953-966`, `docs/SECURITY.md:117-123,277-313`.
- reasoning: The code does what the finding says: `/ui/admin/audit*` maps to ViewAudit with no router, and `Filter::matches` never consults `router_scope`. But SECURITY.md defines scope as a check "before any router request". Reading the audit log is not a router request, and like ManageUsers it lives in the global admin area. Neither code nor docs say ViewAudit is router-scoped, so this is an undocumented design gap rather than a broken control. Secret values are already excluded from audit params.
- severity: low
- correction: Treat this as a decision. Either filter entries by `scope_matches(role.router_scope, entry.router)` in `page` and `export`, or document ViewAudit as fleet-wide.

### SEC1-09 ADJUSTED
- checked: `crates/kcc-web/src/routers.rs:95-135,195-275`, `crates/kcc-web/src/router_form/plan.rs:150-219`, `crates/kcc-app/src/registry.rs:554-592`, `docs/SECURITY.md:89-90`.
- reasoning: The bug is real. `seal` writes to `store.sealed_path(id, kind)`, a fixed path per router and credential kind, before `registry().update`, and nothing rolls it back on failure (`create` does roll back). `update` can still fail after the handler's checks: a state I/O error, `NotFound` after a concurrent delete, `ConfigDefined` after a concurrent SIGHUP, or `profile.validate()`. Because the client cache is cleared only on success, a later sign-in uses the new secret against the old URL.
- severity: medium
- correction: The ndw2/ndw4 sign-in is challenge-response (SECURITY.md:89-90), so in password mode the new password is not disclosed to the old router. The consequence is failed sign-ins and possible lockout on the old router. Only the token mode might send the secret, and I did not verify that.

### SEC1-10 ADJUSTED
- checked: `crates/kcc-web/templates/partials/kit_result.html`, `crates/kcc-web/src/page_kit/respond.rs:110-170`, `crates/kcc-web/src/page_kit/request.rs:111-119`, `crates/kcc-web/src/routing_page/reply.rs:82-101`, `grep '|safe'` over the templates (29 uses in 26 files), `docs/rust-guidelines/overlays/projects/keenetic-control-center.md:50-52,62+`.
- reasoning: Rule (e) says "askama auto-escaping only, no bypass", and there are 29 `|safe` uses carried in plain `Option<String>` fields. No deviation entry covers this. Every producer I traced (`Changed::new`, `with_report`) passes `request::rendered(&impl Template)` output, which askama has already escaped. No XSS is shown; the cost is latent and only type-level.
- severity: low
- correction: The fix stands: a `Markup` newtype that only `rendered()` can construct. Severity is low because no producer of unescaped text exists today.

### SEC1-11 CONFIRMED
- checked: `crates/kcc-app/src/accounts.rs:370-420`, `crates/kcc-app/src/persist.rs:200-240`.
- reasoning: An unknown user runs dummy Argon2, but `disabled` and an active `Locked` return before any Argon2. That timing gap lets an attacker tell disabled or locked accounts apart from unknown ones. `StateStore::update` holds the file lock across the closure, so Argon2 runs under the lock, and it rewrites `users.json` on every login attempt, including attempts for unknown users. That serializes all logins and account changes.
- severity: low

### SEC1-12 CONFIRMED
- checked: `crates/kcc-web/src/auth.rs:271-323,434-456`, `crates/kcc-web/src/session.rs:330-362`.
- reasoning: A normal password change calls `invalidate_other_user_sessions(&username, current.id())` and keeps the same id. Only the forced-change path calls `rotate_privilege`.
- severity: low

### SEC1-13 CONFIRMED
- checked: `crates/kcc-web/assets/js/app.js:25-32,322,364,388,412-460`.
- reasoning: The comments `todo 44/36/37/39/70/121` are review-process labels. Three separate `htmx:beforeSwap` listeners each set `shouldSwap=true; isError=false` for 422, for 413 with `HX-Retarget`, and for 403 with `HX-Retarget`.
- severity: low

### SEC1-14 CONFIRMED
- checked: `crates/kcc-web/src/authz.rs:225-292`, `crates/kcc-web/src/page_kit/context.rs:175-196`, `crates/kcc-web/src/page_kit/action.rs:85-106`.
- reasoning: `router_scope` takes the raw segment, while handlers use the decoded `Path`. `context::target` rejects anything failing `is_profile_id` and re-checks scope through `lookup`, so a percent-encoded id can only be refused. There is no bypass today.
- severity: info

## Summary
- **CONFIRMED (10):** SEC1-01, SEC1-02, SEC1-04, SEC1-05, SEC1-06, SEC1-07, SEC1-11, SEC1-12, SEC1-13, SEC1-14
- **ADJUSTED (4):** SEC1-03 (high to medium), SEC1-08 (medium to low; a design decision), SEC1-09 (medium kept; the impact claim is corrected), SEC1-10 (medium to low)
- **REFUTED:** 0
- **DUPLICATE:** 0
- **NEW issues:** none. One cross-reference: SEC1-11's `users.json` rewrite on every failed login also slows the SEC1-02 flood, and it means every attempt by that flood also writes to disk.