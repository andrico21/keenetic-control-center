## Ask

Ask: read-only security review of the user-facing surfaces (lane SEC1), in the format BRIEF.md sets. Wanted: findings ordered by severity, then Coverage and Clean.

For you: I found 3 high, 7 medium, 3 low and 1 info finding. I edited nothing and ran no cargo commands.
- **Secrets to a viewer:** the default `viewer` role can read the router's full running configuration, secrets included, through MCP `kcc_rci_read` and the Web explorer.
- **Login floods the audit log:** anyone who can reach the login page can grow the audit log by up to 1 MiB per request.
- **Cookie without `Secure`:** in the documented HTTPS-proxy setup, the session cookie is sent without `Secure`.

Every route-table entry I traced reaches its permission and router scope, either in the middleware or again in the handler.

---

### SEC1-01 A Read role gets the full running configuration, secrets included, from MCP `kcc_rci_read` and the Web explorer
- severity: high
- kind: security
- rule: project rule (d) "Secrets … never reach … tool results"
- evidence:
  - `crates/kcc-mcp/src/registry/definitions.rs:116-121`: `"kcc_rci_read", … "core", Permission::Read`. "core" is the default toolset (`kcc-app/src/settings.rs:203`).
  - `crates/kcc-catalog/src/runtime.rs:145`: `CommandKind::Show => Risk::Read`. `catalog/5.1/show.json:7812` has `"path": "show running-config"`.
  - `crates/kcc-mcp/src/generic/rci.rs:194-209`: `server.authorize_host(Permission::Read, …)` … `client.show(&path, &input.value)` … `Ok(rci_body_value(body))`
  - `crates/kcc-mcp/src/support/errors.rs:116-122`: `RciBody::Json(response) => json!({"value": response.value, …})`, `RciBody::Text(text) => json!({ "text": text, … })`
  - `crates/kcc-mcp/src/support/shape.rs:207-226`: redaction matches key names only, so lines under `"text"` or `"message"` pass through unchanged.
  - Web: `crates/kcc-web/src/page_kit/gate.rs:20` gives `Risk::Read => vec![Permission::Read]`. `advanced/viewer.rs:93-97` masks secret-named keys only, and `viewer.rs:111-118` shows text verbatim.
  - The project treats this text as secret elsewhere:
    - `kcc-rci/src/engine.rs:518-532` returns running-config as `SecretBytes`.
    - `kcc-domain/src/firewall/read.rs:55-65` redacts it "before anything else reads it".
    - The backup download needs `RevealSecrets` for the unredacted copy (`config_page/store.rs:242-245`).
- impact: Take an API key created exactly as the README shows (`kcc apikey create claude --role viewer`), or a prompt-injected agent using it. It calls `kcc_rci_read {"catalog_path":"show running-config","path":["show","running-config"]}` and receives every `ns3` blob and any plain-text secret the configuration holds (e.g. `community`, `obfs-key`). The data then goes to the model provider. A Web viewer gets the same through the explorer. Both bypass `RevealSecrets`.
- fix: Treat `show running-config` (and any other raw read that returns configuration text) as secret-bearing. Either require `RevealSecrets`, or parse the reply with `kcc_config` and run `secrets::redact` before shaping, on both surfaces.
- confidence: medium (INFERRED: that a real router answers RCI `show running-config` with the configuration lines in a `message`/text body; the fake router does not serve it)

### SEC1-02 Anyone can grow the audit log by 1 MiB per failed login, filling the disk and stopping `kcc serve`
- severity: high
- kind: security
- rule: RUST_GUIDELINES.md §10 "Validate and sanitize all external input at system boundaries", "Length limits" (line 2738)
- evidence:
  - `crates/kcc-web/src/auth.rs:48-54`: `username: String` (no length bound). `auth.rs:229-230` sends invalid logins to `login_failure`, which at `:363` calls `audit(state, &username, "web.login", outcome)`.
  - `auth.rs:503-506`: `Actor::new(ActorKind::Web, username.to_owned())`. `kcc-app/src/audit.rs:155` shows `Actor::new` does not truncate.
  - `crates/kcc-web/src/lib.rs:220`: `BODY_LIMIT: usize = 1024 * 1024`. `kcc/src/server.rs:147` sets `.with_extra_route_rate_limit(600)`, i.e. 600 requests per minute per IP.
  - `kcc-app/src/audit.rs:35`: rotation at 50 MiB, retention 365 days, no total size cap.
- impact: An unauthenticated LAN client first does a GET on `/ui/login` for a cookie and CSRF token, then POSTs logins whose username is about 1 MiB. Each one appends a hash-chained entry of about 1 MiB. Within hours the disk fills; the audit writer then dies and `server_shutdown.rs:45-57` stops the server. Before that, `/ui/admin/audit` loads the whole log into memory on every view (`admin_audit.rs:340-364`).
- fix: Reject or truncate the username at the login boundary (the account name rules are short, e.g. ≤64 bytes) before authentication and audit, and bound `Actor.id` in `AuditEvent`.
- confidence: high

### SEC1-03 Behind the documented HTTPS reverse proxy, the session cookie has no `Secure` flag and no `__Host-` prefix
- severity: high
- kind: security
- rule: project rule (e) "Web UI hardening"; overlay http-services "DO: Set OWASP-recommended HTTP response headers"
- evidence:
  - `crates/kcc/src/server.rs:138` and `:467-471`: `let tls = config.server.tls_cert_path.is_some() && …tls_key_path.is_some();` … `if tls { CookieSecurity::Tls } else { CookieSecurity::LoopbackHttp }`
  - `kcc-app/src/settings.rs:895-901`: a non-loopback Web UI is allowed when `trusted_https_proxy = public_https && !trusted_proxies.is_empty()`.
  - `kcc-web/src/session.rs:170-178`: `LoopbackHttp => ""` → `kcc_session=…; Path=/; HttpOnly; SameSite=Strict`, with no `Secure`.
  - `csp::policy(false)` also drops `upgrade-insecure-requests`.
- impact: Take the supported setup: `public_url = "https://kcc.lan"` with `trusted_proxies`, and kcc listening on plain HTTP behind the proxy. A LAN attacker who can make the browser load any `http://kcc.lan/...` URL (injected `<img>`, ARP-spoofed HTTP) receives the admin's `kcc_session` in cleartext. Cookies are not bound to a port, so any HTTP service on that host also receives it. Without `__Host-`, a network attacker can also plant a session cookie.
- fix: Choose `CookieSecurity::Tls`, and the TLS CSP, when the listener has TLS *or* `web.public_url` is `https`. Pass that decision from `Config` instead of recomputing `tls` in `server.rs`.
- confidence: high

### SEC1-04 MCP secret redaction misses hyphenated and short secret keys that the Web masks
- severity: medium
- kind: duplication
- rule: project rule (d); BRIEF anti-pattern "copy-paste duplication that drifts"
- evidence:
  - `crates/kcc-mcp/src/support/shape.rs:211-224`: `lowered.contains(needle)` over `"password","passwd","token","secret","api_key","private_key","ns3","psk","preshared"`
  - `crates/kcc-web/src/page_kit/secret.rs:15-29`: the Web list includes `"key"`, `"pin"`, `"community"` and suffix `"-key"`. Its own test at `:68-73` lists `"private-key"` as a secret.
  - The catalog argument names include `"private-key"`, `"community"`, `"obfs-key"` and `"preshare-key"` (`catalog/5.1/interface.json:22418`, `snmp.json`).
- impact: `"private-key"` does not contain `"private_key"` (hyphen versus underscore). A `kcc_rci_read` of a WireGuard or SNMP node that returns `{"private-key": …}` or `{"community": …}` reaches the MCP client unmasked, although `docs/PRIVACY.md` says "MCP tools never reveal secrets".
- fix: Move one classifier (the Web's `is_secret`, with `-`/`_` normalised) into a shared crate, e.g. `kcc-config` or `kcc-catalog`, and use it in both `mask` and `redact_secrets`.
- confidence: medium (INFERRED: the exact JSON key names in RCI read replies)

### SEC1-05 Disabling an account or resetting its password from the CLI does not end its Web sessions
- severity: medium
- kind: security
- rule: none (weakened control)
- evidence:
  - `crates/kcc/src/cli/accounts.rs:89-90`: `accounts.administer(&username, &AccountChange::Disabled(!enable))`; the reset is at `:146` (`accounts.reset_password(…)`).
  - `crates/kcc-web/src/authz.rs:165-180`: the middleware trusts the in-memory session and resolves the role name only. It never checks that the account still exists, is enabled, or keeps the same password.
  - Only Web-side changes call `sessions().invalidate_user` (`admin_users.rs:390,495,560`).
- impact: In incident response, an operator runs `kcc user disable mallory` or resets the password on the host. Mallory's open browser session keeps full access for up to 12 h (`session_absolute`), with the 30 min idle timer refreshed by every request.
- fix: In `authentication_middleware`, re-check the account's `disabled` flag and a password/role generation counter from `AccountStore` (it can be cached briefly), and drop the session on mismatch.
- confidence: high

### SEC1-06 Open event streams keep sending data after logout, account disable or role reduction
- severity: medium
- kind: security
- rule: none (weakened control)
- evidence:
  - `crates/kcc-web/src/system_pages/logs.rs:151-174`: the router is checked once (`context::target`), then `log.follow(domain, seen)` streams with no limit.
  - `crates/kcc-web/src/overview.rs:222-226`: `stream::unfold((events, permit), …)` never re-checks the session.
  - `dashboard.rs:217-222` keeps a role snapshot (`role: user.role().clone()`).
- impact: A user whose role is reduced, who is disabled in the Web UI (`invalidate_user`), or who logs out in another tab keeps receiving router logs, traffic and fleet status on streams already open (up to 4 per session) until the TCP connection closes.
- fix: Have `guarded` end the stream when the session is gone, e.g. a `sessions().peek(id)` check per event or every N seconds, or a cancellation token fired by `invalidate*`. Also cap the stream's total lifetime.
- confidence: high

### SEC1-07 Every login-page GET without a valid cookie creates a new anonymous session, with no cap
- severity: medium
- kind: security
- rule: RUST_GUIDELINES.md §10 (input/DoS bounds); BRIEF "unbounded growth"
- evidence:
  - `crates/kcc-web/src/auth.rs:150-156`: `None => match state.sessions().create_anonymous().await`
  - `session.rs:456-462`: an unconditional `insert` into `HashMap<SessionId, Session>`. Sessions are only swept by the idle timeout (default 30 min).
- impact: An unauthenticated client gets 600 sessions per minute per IP, about 18,000 per IP for each 30-minute idle window. With many source addresses (an IPv6 /64), memory and the time `retain` holds the global `RwLock` grow without bound, slowing every authenticated request.
- fix: Cap anonymous sessions (global and per client IP), give them a short idle timeout (e.g. 5 min), or use a stateless signed pre-auth CSRF token for the login form.
- confidence: high

### SEC1-08 The audit log page and export ignore the viewer's router scope
- severity: medium
- kind: security
- rule: none (router scope not enforced)
- evidence:
  - `crates/kcc-web/src/authz.rs:252`: `value if value.starts_with("/ui/admin/audit") => Permission::ViewAudit` (router scope not extracted).
  - `admin_audit.rs:110-116`: `Filter::matches` filters only by what the user asks for. `export` at `:298` writes every matching entry.
- impact: A custom auditor role scoped to `lab-*` sees and exports audit entries for every router: actions, targets, router URLs and logins from `router.profile_*` params, and client names. This contradicts the per-router scope model used everywhere else.
- fix: Drop entries whose `router` is set and outside `user.role().router_scope` (`scope_matches`), in both `page` and `export`. If global audit visibility is intended, document it as an owner decision.
- confidence: medium (INFERRED: whether ViewAudit is meant to be global)

### SEC1-09 A failed router edit leaves the new credential sealed for the old profile
- severity: medium
- kind: bug
- rule: none
- evidence: `crates/kcc-web/src/routers.rs:236-250`
  ```rust
  if let Err(error) = plan
      .point(store, &mut profile)
      .and_then(|()| plan.seal(store, &id))
  { return errors::internal(&error, shell); }
  match fleet.registry().update(user.role(), profile.clone()).await {
      Ok(()) => {}
      … Err(error) => return errors::internal(&error, shell),
  ```
  `create` rolls back on failure (`:119-126`); `update` does not.
- impact: An admin moves router `a` to a new URL and types the new router's password. If `registry().update` fails (a state write error, or a scope change in between), the sealed `a` password is already overwritten while the profile still points at the old URL. The next poll sends the new router's password to the old router, which also fails sign-in and can trip the router's own lockout.
- fix: Seal to a temporary path and rename after `update` succeeds, or restore the previous sealed record when `update` fails.
- confidence: medium

### SEC1-10 HTML is passed around as plain `String` and rendered with `|safe`, against "askama auto-escaping only, no bypass"
- severity: medium
- kind: guideline
- rule: project rule (e) "askama auto-escaping only, no bypass"
- evidence:
  - `crates/kcc-web/templates/partials/kit_result.html:4,10,13`: `{{ text|safe }}`, `{{ more|safe }}`, `{{ region|safe }}`
  - `crates/kcc-web/src/page_kit/respond.rs:122-126`: `report: Option<String>`, `extra: Option<String>`, `refreshed: Option<String>`
  - Also `routing_page/reply.rs:64` and more than 25 pages (`{{ region|safe }}`, etc.).
- impact: Every producer I checked passes pre-rendered askama output (`request::rendered`), so this is not exploitable today. But the type `String` cannot tell markup from router text: one future `changed(outcome, None, Some(router_text), …)` is stored XSS from a hostile router reply, and the compiler will not catch it.
- fix: Add a `Markup(String)` newtype whose only constructor is `rendered(&impl Template)`. Make these fields `Option<Markup>` so `|safe` applies only to that type.
- confidence: high

### SEC1-11 Login timing reveals disabled or locked accounts; all logins are serialised on the users file
- severity: low
- kind: security
- rule: none
- evidence:
  - `crates/kcc-app/src/accounts.rs:386-401`: an unknown user runs `verify_dummy_password` (slow Argon2), but `if account.disabled { return Ok(Authentication::Disabled); }` and the `Locked` branch return before any Argon2 (fast).
  - The whole check runs inside `self.state.update(…)`.
- impact: An attacker sends `max_failures`+1 bad logins for a guessed name. A fast final reply shows the account exists (and the attempts lock it). Because each attempt does Argon2 inside the `users.json` update (INFERRED: `update` takes the file lock), a login flood also delays every legitimate login and account change.
- fix: Run the dummy verification on the disabled and locked paths too, and do Argon2 outside `state.update`: read, verify, then update the counters.
- confidence: medium

### SEC1-12 A self-service password change keeps the current session id
- severity: low
- kind: security
- rule: none
- evidence: `crates/kcc-web/src/auth.rs:306-313`: `invalidate_other_user_sessions(&username, current.id())`, then the same `current` id is reused. Only the forced first-login path rotates (`finish_required_change`).
- impact: A user who changes their password because they suspect their session cookie was stolen does not evict the attacker who holds that same cookie.
- fix: Call `rotate_privilege` (new id and CSRF token) on every successful password change and set the new cookie.
- confidence: high

### SEC1-13 `app.js` carries review-process labels and three copies of the same swap override
- severity: low
- kind: anti-pattern
- rule: BRIEF "review-process labels in code", "copy-paste duplication"
- evidence: `crates/kcc-web/assets/js/app.js:322,364,388,412,427,443`: `// todo 44:`, `todo 36`, `todo 37`, `todo 39`, `todo 70`, `todo 121`. Separate `htmx:beforeSwap` listeners at `:27-32`, `:418-424` and `:450-456` each set `shouldSwap = true; isError = false` for one status.
- impact: The labels mean nothing to a maintainer. The three status overrides (422, 413 with `HX-Retarget`, 403 with `HX-Retarget`) live in three places, so a change to swap policy must be made three times.
- fix: Remove the labels. Merge into one `beforeSwap` handler with a status table.
- confidence: high

### SEC1-14 Route-table scope checks use the raw path, handlers use the decoded one
- severity: info
- kind: security
- rule: none
- evidence: `crates/kcc-web/src/authz.rs:268-281` takes `router` from `request.uri().path()` without percent-decoding. Handlers use the decoded `Path(router)`, and every one I traced re-checks scope (`page_kit/context.rs:181-195`, `action.rs:91-106`, `workflow.rs:602`).
- impact: Today this can only refuse (`/ui/r/%68ome/...` is denied for a `home`-only scope). It would bypass scope for a glob whose literals contain `%`/hex digits, and only if a handler stopped re-checking.
- fix: Percent-decode the segment before `registry::authorize`, or rely only on the handler check.
- confidence: high

## Coverage
- **Read in full:**
  - kcc-web `src`: `lib.rs`, `auth.rs`, `authz.rs`, `csrf.rs`, `csp.rs`, `session.rs`, `sse.rs`, `assets.rs`, `brackets.rs`
  - kcc-web `src`: `routers.rs`, `router_access.rs`, `router_check.rs`, `router_delete.rs`, `router_form.rs`, `router_form/{address,page,plan}.rs`
  - kcc-web `src`: `admin.rs`, `admin_shared.rs`, `admin_users.rs`, `admin_roles.rs`, `admin_keys.rs`, `admin_audit.rs`, `admin_server.rs`, `admin_{users,roles,keys,audit}/table.rs`
  - kcc-web `src`: `secret_pages.rs`, `secret_pages/{routes,dialog,reply,wifi_psk}.rs`, `page_kit/{action,context,secret}.rs`
  - `crates/kcc-web/assets/js/app.js`
  - `crates/kcc/src/server.rs`, `server_{origins,outbound,tasks,tls_key,migrations,shutdown}.rs`
  - kcc-mcp: `src/lib.rs`, `src/support/{access,audit,errors,shape,raw_change}.rs`
  - kcc-app: `src/{permissions,role_source,api_keys,api_key_use}.rs`
- **Skimmed (relevant parts):**
  - kcc-web: `config_page/{wiring,download,store}.rs`, `migrate_wizard/{routes,source_read}.rs`, `presets_page/{routes,reveal,capture}.rs`, `dns_vpn.rs` (uploads)
  - kcc-web: `dashboard.rs`, `save.rs`, `overview.rs`, `advanced/{viewer,deliver,execute,job_stream,jobs}.rs`, `system_pages/{logs,jobs}.rs`, `table/piece.rs`, `page_kit/{respond,gate,request}.rs`, `errors.rs`
  - kcc-mcp: `generic/{rci,fleet}.rs`, `domains/{read,write/common}.rs`, `migration_tools/finish.rs`, `support/validate.rs`
  - kcc-app: `accounts.rs` (`authenticate`), `registry.rs` (`authorize`/globs), `settings.rs` (`web_allowed_origins`), `workflow.rs` (`begin`/`save`)
  - kcc: `cli/accounts.rs`
  - rmcp-server-kit `auth.rs`/`transport.rs` (`with_keys`, extra-route limiter)
  - Templates: grepped every template for `|safe`, `<script`, `style=`, `on*=`, `href`, `hx-*`; read `kit_result.html`, `error.html`, `kit_table.html`
- **Not read:**
  - `brackets/tests.rs`
  - `secret_pages/{user_password,vpn_credential,vpn_server,wan_password}.rs`
  - Most templates line by line
  - `prefs.rs`, `page.rs`, the remaining kcc-mcp tool modules

## Clean
- **Route table → permission:** `/ui/admin` Read, `/ui/admin/audit*` ViewAudit, other `/ui/admin/*` ManageUsers, `/ui/migrate*` Migrate, `/ui/configuration` Write, `/ui/routers/*` ManageRouters (scope re-checked by `managed`), `/ui/r/{r}/console*` RawRci, `/ui/r/{r}/…/save` Save, everything else Read + scope. Sampled writes (secret dialogs, domain pages, backups, explorer, save) re-check their operation's permission and risk in the handler.
- **Separately merged routers:** `config_page`, `migrate_wizard`, `presets_page` and `dns_vpn` uploads all go through `protect()` (CSRF, then authentication, then route-table authorization).
- **Privilege dominance:** user, role and API-key administration all check `dominates`/`covered`: no acting on yourself, no granting above your own role, unknown role counts as all-powerful, roles still in use cannot be deleted.
- **Session basics:** 256-bit OS-random ids and CSRF tokens; id rotated on login (no fixation); `HttpOnly`, `SameSite=Strict`; idle and absolute expiry; logout invalidates on the server.
- **CSRF:** every non-GET needs the session token (constant-time compare) plus an exact Origin allowlist plus `Sec-Fetch-Site` same-origin; the login form is covered too.
- **CSP:** `default-src 'none'`, script and style from self only, no inline code anywhere, no eval, `frame-ancestors 'none'`; assets carry SRI hashes and immutable cache headers.
- **Open redirects:** none; every `Redirect`/`HX-Redirect` target is a constant or a validated slug.
- **Error responses:** generic localized pages and opaque MCP codes; internals go only to `tracing`.
- **API keys:** stored as Argon2id hash only; plaintext shown once with `no-store`; revocation reloads the transport; `last_used` writes throttled.
- **MCP:** every tool checks identity, permission and scope; the destructive switch plus `confirm` gate destructive and raw management changes; `RouterId` is validated.
- **Startup:** the server refuses a group- or world-readable TLS key file; the state lock stops a second `kcc serve` from starting on the same state directory.