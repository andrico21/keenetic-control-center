# kcc full code review: critic-validated report

- **Repository:** `/home/andrico/keenetic-control-center`, `master` at `349b7fb`.
- **Standard:** `andrico21/rust-guidelines` at `49898c9`, the current upstream HEAD, byte-identical to the vendored copy. Also the `http-services` and `mcp-servers` overlays and the project overlay.
- **Mode:** read-only. No file in the repository was changed.

## How this review was done

1. **Reviewers.** 16 reviewer lanes read the code from scratch, without the plan, the worker's notes or the earlier review:
   - two security lanes: Web/MCP access, and secrets/outbound/files;
   - one lane per crate group;
   - five kcc-web lanes;
   - test quality;
   - build, supply chain and deploy.
2. **Coverage.** About 168k lines of production Rust, 4.1k lines of templates, 3.8k lines of first-party JS/CSS, about 74k lines of tests, plus `xtask/`, CI, the Containerfile and `deploy/`.
3. **First critic.** Every finding (317) went to a fresh critic that re-derived it from the code and tried to refute it. Verdicts:
   - 161 confirmed;
   - 148 adjusted, mostly downgraded or narrowed;
   - 8 refuted.
4. **Second critic.** Every finding still rated high got an independent second critic acting as tie-breaker, and so did every new issue a critic raised while checking (14 items). Results:
   - one high claim refuted (the CLI part of H1);
   - one high lowered to medium (preset capture);
   - one critic-raised issue refuted (N13), another merged as a duplicate (N15);
   - the rest confirmed or narrowed.
5. **My own check.** I re-read the code for every high finding myself:
   - H1: the MCP path;
   - H2: the login → audit path;
   - H3: the firewall render path;
   - H4: rule order and `Copy` skipping `apply_mappings`;
   - H5: the credential fixed for the whole run;
   - H7: the CLI revoke path;
   - plus two mediums: M01 (cookie flags) and M06 (unquoted DHCP/known-host names).
6. **Deduplication.** Overlapping findings from different lanes are merged. The ids show every source.

Only findings that survived validation appear below. Everything is under `~/.cache/kcc-review/`: lane findings in `findings/`, critic verdicts in `critics/`, the full table in `table.tsv` and `db.json`.

## Verdict

The worker shipped a codebase that passes its own strict gates:
- clippy under the full §9 profile;
- 1385 tests;
- deny, audit and vet;
- the xtask gates.

Much of its security engineering is also good. Sealed state, the SSRF policy, CSRF/CSP, the RCI auth state machine, the shared safety bracket and atomic state writes all held up under hostile review (see "Sound areas").

But the review found **6 high-severity defects**, 59 distinct medium issues and about 230 low/info items. The pattern behind most of them is the same as in the first review: **one rule is implemented separately per surface or per planner, and the copies drift**. That is where most real bugs live:
- secret masking exists three times, and each copy has different gaps;
- CLI-line quoting is done in some planners and forgotten in others;
- confirmation is opt-in per handler;
- risk classification is hard-coded in some planners.

The lint profile cannot catch any of these, and the tests often pass because they assume the behavior they should test. For example, they send the confirmation up front, or use secret markers that quoting always escapes.

| Severity | Distinct issues |
|---|---|
| High | 6 |
| Medium | 59 (H6 lowered to medium is M12) |
| Low | 188 rows (Appendix A, incl. 11 critic-raised) |
| Info | 44 rows |
| Refuted | 10 (8 lane findings, 1 sub-claim, 1 critic-raised) |

## High

### H1. A Read-only role can read router secrets (MCP `kcc_rci_read`, Web explorer, Web masker gap)
- **Ids:** SEC1-01, E-01, W4-01, plus the W4 critic's nested-mask variant. Three reviewers found it independently; two first critics, the second critic and I confirmed it.
- **Rule:** project rule (d), "secrets never reach … tool results".
- **H1a, MCP.** `kcc_rci_read` is in the default `core` toolset and needs only `Permission::Read`.
  - Code: `crates/kcc-mcp/src/registry/definitions.rs:116-122`, `generic/rci.rs:186-210`.
  - `show running-config` is a `Show` command, so its risk is Read. The reply goes back unredacted (`support/errors.rs:114-124`).
  - `shape::redact_secrets` matches JSON key names only (`support/shape.rs:207-239`), so `password ns3 …` and `wpa-psk ns3 …` lines inside strings pass through.
  - `ns3` is keyless and reversible (`crates/kcc-config/src/ns3.rs:42-60`).
  - A `viewer` API key held by an AI assistant can therefore recover Wi-Fi PSKs and PPPoE/VPN passwords, which then go to the model provider.
  - Limit: by default only configurations under the 32 KiB MCP result cap come back whole.
- **H1b, Web explorer.** `/ui/r/{r}/explorer/execute` falls through to Read.
  - Code: `crates/kcc-web/src/authz.rs:248-262`, `advanced/execute.rs:39-110`.
  - `read_root` posts the show command, and `advanced/viewer.rs:72-118` shows text bodies verbatim.
  - Every sibling path to the same data redacts it or requires `RevealSecrets`: the firewall reader, the preview's `ns3_redacted`, and the backup download.
- **H1c, Web masker.** `crates/kcc-web/src/page_kit/secret.rs:14-47`: `mask` replaces a secret-named member only when the value is a scalar, and `ns3` is not in `is_secret`.
  - So `{"password":{"ns3":…}}` and `{"wpa-psk":{"ns3":…}}` from `show interface` reach a viewer. This needs no assumption about the router's reply shape.
  - The project's own read-backs rely on exactly that shape (`kcc-domain/src/wan.rs:167-190`).
- **Refuted part (H1d):** the CLI. The CLI principal loads the master key itself, so its role is not a boundary.
- **Fix.**
  - Treat configuration-text reads (`show running-config` and similar) as secret-bearing. Either require `RevealSecrets`, or run them through `kcc_config::secrets::redact` on both surfaces.
  - Make `mask` replace a secret-named member of any type, and add `ns3`.
  - Have MCP and Web share one masker (see M07).

### H2. Anyone without an account can fill the disk through the audit log
- **Ids:** SEC1-02. Confirmed by the first critic and the second critic, and by me.
- **Rule:** §10 "Validate and sanitize all external input at system boundaries".
- **Path.** `LoginForm.username` is an unbounded `String` (`crates/kcc-web/src/auth.rs:47-55`).
  - An unknown user is audited as `Actor::new(ActorKind::Web, username.to_owned())` (`auth.rs:495-510`), with no truncation.
  - The only bound is the 1 MiB body limit (`lib.rs:220`), and the kit allows 600 requests per minute per IP.
  - Audit retention is by age only (`kcc-app/src/audit.rs:25-40`).
- **Impact.** An unauthenticated LAN client posts logins with ~1 MiB usernames. Each failure appends a ~1 MiB hash-chained entry. The disk fills, the audit writer dies, and `kcc serve` stops.
  - Exposure: the default bind is loopback, but the shipped Podman example binds `0.0.0.0`.
- **Fix.** `validate_username` (1..=64 bytes, `crates/kcc-app/src/accounts.rs:667`) already exists but `authenticate` never calls it.
  - Call it first and treat a failure as `Invalid`.
  - Bound `Actor.id` in `AuditEvent`.

### H3. Clearing a firewall rule's description or schedule turns a disabled rule on
- **Ids:** D-01, plus the D critic's NEW-1. Confirmed by both critics and by me.
- **Path.** `RuleProperty::Description(None) | Schedule(None)` builds `{"index":N,"no":true}` (`crates/kcc-domain/src/firewall/change.rs:92-98`).
  - `render_property` finds no description, schedule or order and falls through to `disable` (`firewall/change/render.rs:127-143`).
  - The router receives `no access-list L rule N disable`.
- **The Web reaches it.** An empty description field or the "no schedule" choice becomes `None` (`kcc-web/src/firewall_page/rule_props.rs`, `checks.rs:45-58`).
- **The checks pass.** The workflow check passes because the `disable` line is now absent. When there was nothing to clear, the Web read-back `Expect::Property` passes too.
- **Impact.** A deliberately disabled firewall rule is enabled silently and audited as success. No test covers `Description(None)` or `Schedule(None)`.
- **Fix.** Render from the `RuleProperty` variant: `no access-list L rule N description` / `… schedule`. Add the regression test on a disabled rule.

### H4. Migration and presets copy secret-bearing lines without applying interface, port or radio mappings
- **Ids:** G-01. Confirmed by the first critic and the second critic, and by me.
- **Rule order.** In `crates/kcc-migrate/rules/rules.toml:142-168` the first match wins, and `copy-wireguard-private-key` and `copy-ns3-secret` come before `remap-mapped-reference`.
- **Copy skips mappings.** `rules.rs:522-535` calls `apply_mappings` only for `Disposition::Remap`.
- **Impact.** A secret line keeps the source interface name while its sibling lines are remapped. It also bypasses the scalar-conflict check, so it silently overwrites the target's secret on the source-named interface.
  - Example: map a Wi-Fi access point or a PPPoE/WireGuard interface to a different target name. The SSID or peer settings move, and the PSK/password/private key lands on the wrong (source-named) object.
  - No backlog entry covers this.
- **Related, medium (H4a):** radio mappings never rewrite access-point tokens.
  - The tokenizer does not split `WifiMaster0/AccessPoint0`, and both planners replace exact tokens only.
  - So a proposed `WifiMaster0 → WifiMaster1` moves the radio settings but leaves SSID, schedule and PSK on the source-numbered AP.
- **Fix.**
  - Apply mappings to `Copy` lines too, or put the secret-copy rules after the remap rule while keeping their secret handling.
  - Expand radio mappings to the `WifiMasterN/…` children.
  - Add planner tests with a mapped AP and a mapped WireGuard interface.

### H5. Migration reconnects with the new management password before that password has been sent
- **Ids:** G-03. Confirmed by both critics and by me.
- **The credential is fixed for the whole run.** `crates/kcc-migrate/src/apply/preflight.rs:104-110` sets `Some(login, management_password)` once.
- **Reconnects use it immediately.** `apply/reconnect.rs:37-60` reconnects with it after every management line.
- **Ordering.** Management lines run in source order, and interface blocks precede `user` blocks.
- **Plan that breaks.** A cross-model migration onto a target whose LAN differs from the source's, with "overwrite":
  1. The `interface Bridge0 ip address …` line runs first.
  2. The reconnect authenticates as `admin/<new>` while the router still has the old password.
  3. It fails for 120 s, `recover` waits out the timer, and the result is `RolledBackByRouter`.
- **Impact.** That main flow (hardware replacement) fails every time. The router timer still protects the router, so nothing is locked out.
- **Why tests miss it** (critic note, not separately validated): the live rehearsal supplies the target's current password as the "new" one (`crates/kcc/tests/live_migration/rehearsal.rs:164-168`), and the fake-router test has a single `user` line.
- **Fix.** Keep the old credential until the login's own `user <login> password plain` line has been applied, then switch.

### H7. CLI `apikey revoke`, `user disable` and password reset don't reach a running `kcc serve`
- **Ids:** F-01, plus SEC1-05 and W1-01. Confirmed by both critics and by me.
- **Keys.** The kit authenticates against keys loaded once at startup (`crates/kcc/src/server.rs:136`) and refreshed only by a Web create/revoke or SIGHUP.
  - `kcc apikey revoke` (`crates/kcc/src/cli/api_keys.rs:71-76`) edits the state file and reports success with exit 0.
- **Sessions.** Web sessions never re-check `disabled` or the password (`crates/kcc-web/src/authz.rs:159-201`), and SIGHUP doesn't end them.
- **Docs.** They don't say revocation needs SIGHUP. `docs/SECURITY.md:106-107` says a password change "ends the account's other sessions", which is false for the CLI.
- **Impact.** A revoked leaked key keeps working on a long-running server, and a disabled account keeps its sessions until idle (30 min, refreshed) or absolute (12 h) expiry.
- **Fix.**
  - Re-check key existence and account state per request, or have the CLI signal the server.
  - Make SIGHUP also invalidate sessions of disabled or reset accounts.
  - At minimum, print a "takes effect after SIGHUP" note and fix the docs.

## Medium

H6 (preset capture overwrite) was lowered to medium by the tie-breaker. It appears as M12, with the corrected scope: MCP only (the CLI user already holds the master key), destructive replace of name-derived presets plus an existence oracle.

#### M01. Session cookie lacks `Secure` / `__Host-` when kcc runs behind the documented HTTPS reverse proxy
- **Area:** Security: Web. **Ids:** SEC1-03, F-03. **Critic:** SEC1-03 adjusted (high→medium); F-03 confirmed.
- **Where:** `crates/kcc/src/server.rs:138`, `kcc-app/src/settings.rs:895-901`, `kcc-web/src/session.rs:170-178`, `server.rs:467-471`, `kcc-app/src/settings.rs:900-901`
- **Impact:** Take the supported setup: `public_url = "https://kcc.lan"` with `trusted_proxies`, and kcc listening on plain HTTP behind the proxy. A LAN attacker who can make the browser load any `http://kcc.lan/...` URL (injected `<img>`, ARP-spoofed HTTP) receives the admin's `kcc_session` in cleartext. Cookies are not bound to a port, so any HTTP service on that host also receives it. Without `__Host-`, a network attacker can ...
- **Critic correction:** Exploiting this needs an active or observing network attacker and a browser making a plain-HTTP request to that host. It also applies only to the HTTPS-proxy mode, not to the shipped Podman example, which uses listener TLS. The control is weakened, not fully defeated, so medium rather than high. ...
- **Fix:** Choose `CookieSecurity::Tls`, and the TLS CSP, when the listener has TLS *or* `web.public_url` is `https`. Pass that decision from `Config` instead of recomputing `tls` in `server.rs`.

#### M02. SSE, log, job and traffic streams keep sending data after logout, account disable or role reduction
- **Area:** Security: Web. **Ids:** SEC1-06, W1-02, W5-02. **Critic:** SEC1-06 confirmed; W1-02 confirmed; W5-02 adjusted.
- **Where:** `crates/kcc-web/src/system_pages/logs.rs:151-174`, `crates/kcc-web/src/overview.rs:222-226`, `dashboard.rs:217-222`, `crates/kcc-web/src/overview.rs:135-151,172-174,222-226`, `dashboard.rs:202`
- **Impact:** A user whose role is reduced, who is disabled in the Web UI (`invalidate_user`), or who logs out in another tab keeps receiving router logs, traffic and fleet status on streams already open (up to 4 per session) until the TCP connection closes.
- **Critic correction:** No guideline rule applies; this is a session-revocation gap. The root is the shared `overview::guarded` (`overview.rs:215`), so it also covers `system_pages/logs.rs:174`, `system_pages/jobs.rs:153`, `advanced/job_stream.rs:87` and `net_interface_traffic.rs:67`. The fix belongs in `guarded`.
- **Fix:** Have `guarded` end the stream when the session is gone, e.g. a `sessions().peek(id)` check per event or every N seconds, or a cancellation token fired by `invalidate*`. Also cap the stream's total lifetime.

#### M03. Unauthenticated `GET /ui/login` creates anonymous sessions without a cap
- **Area:** Security: Web. **Ids:** SEC1-07. **Critic:** SEC1-07 confirmed.
- **Where:** `crates/kcc-web/src/auth.rs:150-156`, `session.rs:456-462`
- **Impact:** An unauthenticated client gets 600 sessions per minute per IP, about 18,000 per IP for each 30-minute idle window. With many source addresses (an IPv6 /64), memory and the time `retain` holds the global `RwLock` grow without bound, slowing every authenticated request.
- **Fix:** Cap anonymous sessions (global and per client IP), give them a short idle timeout (e.g. 5 min), or use a stateless signed pre-auth CSRF token for the login form.

#### M04. Router edit seals the new credentials before the profile update and never rolls them back (Web and CLI)
- **Area:** Security: credentials. **Ids:** SEC1-09, W1-05, F-02. **Critic:** SEC1-09 adjusted; W1-05 adjusted; F-02 confirmed.
- **Where:** `crates/kcc-web/src/routers.rs:236-250`, `plan.rs:182`, `routers.rs:119-127`, `crates/kcc/src/cli/router_secrets.rs:119-122`, `router_edit.rs:71-72`
- **Impact:** An admin moves router `a` to a new URL and types the new router's password. If `registry().update` fails (a state write error, or a scope change in between), the sealed `a` password is already overwritten while the profile still points at the old URL. The next poll sends the new router's password to the old router, which also fails sign-in and can trip the router's own lockout.
- **Critic correction:** The ndw2/ndw4 sign-in is challenge-response (SECURITY.md:89-90), so in password mode the new password is not disclosed to the old router. The consequence is failed sign-ins and possible lockout on the old router. Only the token mode might send the secret, and I did not verify that. The mismatch shows immediately only for the read-only polling login. For the primary credential it shows after the cached client is evicted, which is still silent and still needs a fix. Snapshotting and restoring the previous sealed bytes is the safe fix. Sealing after the update would briefly ...
- **Fix:** Seal to a temporary path and rename after `update` succeeds, or restore the previous sealed record when `update` fails.

#### M05. Router and log-sink HTTP clients honour HTTP(S)_PROXY/ALL_PROXY, bypassing the resolved-address pinning
- **Area:** Security: outbound. **Ids:** SEC2-01. **Critic:** SEC2-01 confirmed.
- **Where:** `crates/kcc-rci/src/outbound.rs:220-224`, `session.rs:264-269`, `kcc-telemetry/src/logs/sink.rs:76`, `elastic_sink.rs:76`
- **Impact:** When kcc runs with `HTTP_PROXY` set (common on corporate hosts and in containers), every router request goes to the proxy instead of the pinned address. - That includes the ndw2 login hash, session cookie, `/ci/startup-config.txt` with ns3 secrets, and writes. - The `allowed_networks` and metadata checks are run against an address that is never connected to. - The proxy resolves the name itself, so the DNS pin is ...
- **Fix:** Add `.no_proxy()` in `OutboundPolicy::pinned_builder` and in both sink builders. If proxies must be supported, make that an explicit per-sink setting.

#### M06. Free text goes into router CLI lines unquoted (DHCP pool/host, `known host`, several firewall/policy names): extra arguments can be injected
- **Area:** Security: router commands. **Ids:** SEC2-02, C-01, D-02. **Critic:** SEC2-02 confirmed; C-01 adjusted (high→medium); D-02 adjusted.
- **Where:** `crates/kcc-domain/src/clients/command.rs:133`, `crates/kcc-domain/src/dhcp/command.rs:64-65`, `kcc-catalog/src/validate.rs:301`, `kcc-app/src/workflow_cli/command.rs:42-48`, `crates/kcc-domain/src/dhcp.rs:155-158`
- **Impact:** - A name with a space (common, for example "Anna phone") produces extra router arguments, so the command fails or is misparsed. - A prompt-injected MCP agent can choose the tokens after a fixed prefix. For example `name="Home range 10.0.0.2 10.0.0.3"` becomes a different `ip dhcp pool Home …` subcommand, while the audit log and risk classification record the validated `ip dhcp pool` name. - The MCP `access` op on an ...
- **Critic correction:** Reachable only through MCP (and through the CLI by its own operator). It adds arguments inside the pool/host/known-host commands, not separate commands. Two more MCP holes have the same root cause: `plan_client` passes `input.value` as the registration name with no check at all (`clients.rs:156`), ... Limit the sinks to MCP and CLI input: ACL name, DNS names and descriptions, VPN context names and peer keys, crypto-map names, and policy description. Remove firewall schedule and interface from the list, and replace the FQDN-description example with the one above. - **Possible extra impact ...
- **Fix:** Pass these values through `cli_token::quoted` (names and free text) or `cli_token::validate` (keys, ids), as `interfaces.rs`, `mesh.rs` and `wan/render.rs` already do. Consider making `CliCommand::new` re-run `validate_cli` on the rendered line.

#### M07. MCP secret denylist misses hyphenated and short secret keys the Web masks
- **Area:** Security: secrets. **Ids:** SEC1-04. **Critic:** SEC1-04 confirmed.
- **Where:** `crates/kcc-mcp/src/support/shape.rs:211-224`, `crates/kcc-web/src/page_kit/secret.rs:15-29`
- **Impact:** `"private-key"` does not contain `"private_key"` (hyphen versus underscore). A `kcc_rci_read` of a WireGuard or SNMP node that returns `{"private-key": …}` or `{"community": …}` reaches the MCP client unmasked, although `docs/PRIVACY.md` says "MCP tools never reveal secrets".
- **Fix:** Move one classifier (the Web's `is_secret`, with `-`/`_` normalised) into a shared crate, e.g. `kcc-config` or `kcc-catalog`, and use it in both `mask` and `redact_secrets`.

#### M08. `redact_clients` pseudonymization misses client names, free text and progress notifications
- **Area:** Security: privacy. **Ids:** E-05. **Critic:** E-05 confirmed.
- **Where:** `crates/kcc-mcp/src/support/shape.rs:271-278`, `kcc-domain/src/clients.rs:38`, `domains/write/jobs.rs:70-74`, `kcc-domain/src/diagnostics.rs:94-98`
- **Impact:** With redaction on, `kcc_clients_read` still returns names such as "Anna's iPhone". System log lines (`kcc_diagnostics_read`) and CLI text bodies still contain raw MACs and IPs. An `arping` call with a progress token streams client MACs unredacted.
- **Fix:** Add `name` under client objects. Scrub MAC and IP patterns inside strings. Pass progress messages through the same pseudonymizer.

#### M09. Generic interface reads pass `show interface` credential blobs (ns3) through `extra`
- **Area:** Security: secrets. **Ids:** C-04. **Critic:** C-04 adjusted.
- **Where:** `crates/kcc-domain/src/interfaces/models.rs:35-37`, `wan/models.rs:76-77,83-91`, `wifi/models.rs:43-44`, `wan.rs:180-182`
- **Impact:** `kcc interfaces list --json` prints PPPoE passwords and Wi-Fi PSKs in a decodable form, without the `RevealSecrets` permission. MCP is protected only by the key-name redaction in `kcc-mcp/src/support/shape.rs:207-236`.
- **Critic correction:** The real issue is a rule-(d) secret in CLI output (`--json` or a terminal paste), conditional on the firmware returning the blob. It is not a privilege escalation. The fix stands: drop `authentication` at the read boundary.
- **Fix:** Drop `authentication` from `Interface` at the read boundary, as WAN and Wi-Fi already do.

#### M10. `secrets::redact` misses router-written ns3 secrets and blanks the wrong word for `crypto ike key`
- **Area:** Security: secrets. **Ids:** A-01. **Critic:** A-01 confirmed.
- **Where:** `crates/kcc-config/src/secrets.rs:65-93,101-107,110-130`, `crates/kcc-domain/tests/vpn_credentials.rs:81-87`, `crates/kcc-testkit/src/cli_engine/secrets.rs:36-44`
- **Impact:** - In the second arm group the computed index lands on the literal `ns3` word. `replace_expanded_word` only matches the payload slot, so the ns3 blob stays readable. - `crypto ike key office ns3 B any` gets index 3, so the key name `office` is replaced and the PSK blob is left. - `crypto ipsec profile … preshared-key|xauth-password` is not in the registry at all. - ns3 can be reversed with the public algorithm in ...
- **Fix:** Run every arm through `secret_after_kind`. Index `crypto ike key` past the name. Add `crypto ipsec profile _ preshared-key|xauth-password`. Mask all `Token::Ns3` payloads inside `redact` itself and delete the six consumer copies. Rebuild the test fixture from the `ns3` lines the testkit actually ...

#### M11. WireGuard parse error can keep a raw key line in a Debug/Display error
- **Area:** Security: secrets. **Ids:** D-16. **Critic:** D-16 adjusted.
- **Where:** `crates/kcc-domain/src/vpn_clients/wireguard/parser.rs:68-74`, `wireguard.rs:102`
- **Impact:** A pasted config with `PrivateKey: <key>` (colon typo), or a bare key line, produces `Malformed{field: "<key>"}`. Any `{error:?}` or `tracing` `?error` then prints the key. Today's surfaces use Display or ignore `field`, so this is latent.
- **Critic correction:** Store only the line number in `UnknownField`, `Malformed` and `Duplicate` (anything that can hold raw line text), or never derive `field` from unparsed text. This is a project rule (d) violation in Display error text.
- **Fix:** Store only the line number for `Malformed`.

#### M12. MCP `kcc_preset_capture` overwrites an out-of-scope preset (name-derived id), with an existence oracle
- **Area:** Security: authorization. **Ids:** E-02, G-02. **Critic:** E-02 confirmed high by its first critic, G-02 adjusted to medium by its first critic; the second critic (tie-breaker) set **medium**: MCP vector real (any Migrate identity can replace a name-derived preset of another scope; `get`/`delete` give an existence oracle), CLI vector low because the CLI user already holds the master key, no secret disclosed.
- **Where:** `crates/kcc-mcp/src/preset_tools/capture.rs:152-156,190-193`, `crates/kcc-migrate/src/presets/store.rs:120-129`, `kcc-web/src/presets_page/compose.rs:127`, `crates/kcc-mcp/src/preset_tools/capture.rs:155`
- **Impact:** A `lab-*` identity with `Migrate` captures `{"source":"lab-src","name":"Office",...}` and silently replaces the `office` preset that an admin captured from `prod-1`. A later `kcc_preset_apply office` on prod then pushes lab settings to prod, and prod-scoped users lose the preset. This is a write to an out-of-scope object that `delete` would refuse.
- **Critic correction:** n/a. The root cause is in `PresetStore::capture`, so the store-level fix covers the CLI too. Vector: an MCP identity with `Migrate` on any router can overwrite and destroy a preset of another scope by naming its capture so the slug matches. Fix as proposed: `create_new`, or `authorize_source` on the existing record.
- **Fix:** Have `PresetStore::capture` refuse an existing id (or require the old record's source scope plus an explicit replace flag). In MCP, either give the slug a random suffix or return `conflict` when the id exists.

#### M13. Preset/migration changes to kcc's own login password bypass the management safeguards
- **Area:** Router safety. **Ids:** G-04. **Critic:** G-04 adjusted (high→medium).
- **Where:** `crates/kcc-migrate/src/presets/apply/convert.rs:61-65`, `presets/plan/classify.rs:48-51`, `rules/groups.toml:104`, `preflight.rs:148`
- **Impact:** a preset with `router-users` (or a migration with overwrite) changes the password of the account kcc uses. There is no `PasswordRequired` check, no reconnect and no credential update, and the result can be reported verified and committed. After the save, kcc can no longer log in to that router until someone runs `router edit`. In Mirror mode, the target's `user <login> …` lines that are absent from the preset are ...
- **Critic correction:** The demonstrated consequence is that a `router-users` preset (or a migration that overwrites a same-realm hash) touching kcc's own login always fails and is rolled back by the timer. There is no password check and no clear refusal. Lockout after save is only possible if the firmware keeps sessions ...
- **Fix:** run `is_management_line` (extended to `md5|nt` for the login user) in `convert::migration_plan` and in the planner's prune and copy paths, and require `management_password` there as `validate_credentials` does.

#### M14. Firewall pages require `Destructive` for management changes, unlike every other page (contradicts D-Q1)
- **Area:** Authorization. **Ids:** W3-02. **Critic:** W3-02 confirmed.
- **Where:** `firewall_page/run.rs:154-158`, `kcc-domain/src/configuration.rs:223-228`, `tests/routing_pages/firewall_bind.rs:59-70`, `tests/network_pages/wifi.rs:104-114`
- **Impact:** An operator may take an access point down, or move it into a new segment, under the timer. The same operator gets 403 when applying an access list to `Bridge0`. That is one policy decided in two places, and they disagree.
- **Fix:** Delete the hand-written check and let `Action::run_planned` → `Action::plan` (`SafetyNet::required`) decide. If firewall really needs `Destructive`, express that in the firewall descriptor's risk.

#### M15. Router-account protection fails open when kcc's login is empty or the profile lookup fails
- **Area:** Router safety. **Ids:** W4-03. **Critic:** W4-03 adjusted.
- **Where:** `system_pages/shared.rs:152-157`, `user_delete.rs:104-106,119`, `user_forms.rs:103-105`, `kcc-domain/src/router_users.rs:182-184`
- **Impact:** For a token-auth router, `login == ""`. For any router, a registry read error makes it `""` too. Either way the "account kcc signs in with" guard never matches. A `ManageUsers` holder can then delete, or set a new password on, the router account kcc uses. kcc loses access after the bracket. A fail-safe timer may roll back only if the session dies before the disarm (INFERRED).
- **Critic correction:** For token profiles with an empty login, protection fails open on both Web and CLI. On Web, a registry read error also makes it fail open. Fix it at the source: refuse when the login is empty or unknown, and make `profile_login` return a `Result` that refuses on error.
- **Fix:** Make `profile_login` return `Result<String, _>`. Refuse the change (fail closed) when the lookup fails or the login is empty. For token profiles, record and compare the token's account.

#### M16. Management changes run without the fail-safe confirmation dialog on several Web handlers
- **Area:** Router safety. **Ids:** W2-01, W3-01. **Critic:** W2-01 confirmed; W3-01 adjusted.
- **Where:** `page_kit/submit/flow.rs:51-57`, `submit.rs:317-321`, `net_wifi_settings.rs:231-241`, `kcc-domain/src/wifi.rs:166-172`, `page_kit/submit/flow.rs:51-56`
- **Impact:** One click on "Disable" for the access point kcc reaches the router through runs a management change under the fail-safe timer, with no warning dialog. The same happens on any page that forgets the opt-in. The typed-name rule for destructive changes is enforced only where each page remembers to ask for it.
- **Critic correction:** 1. Default route is not management-classified: `wan::plan_default_route` uses a fixed `Risk::Write` (`wan.rs:240-257`). Remove it from the list. 2. WAN delete does ask, with a typed name (`form.confirmed()`). It lacks only the fail-safe explanation, so it is a wording gap, not a missing ...
- **Fix:** In `carry`, always run `action.confirm(planned.risk, …)` once the planned effective risk is Management or above. Make `Resubmit` a required argument of `Submission::new`, or derive it from the request URI. Keep `Ask::First` as an extra early check, not a replacement.

#### M17. Management changes run without the fail-safe bracket: WAN planners hard-code `Risk::Write`; management detection falls back to Write after a blocking DNS lookup
- **Area:** Router safety. **Ids:** C-06, C-05. **Critic:** C-06 confirmed; C-05 confirmed.
- **Where:** `crates/kcc-domain/src/wan.rs:228-237`, `crates/kcc-domain/src/interfaces/management.rs:206-209`
- **Impact:** When kcc manages a router over its PPPoE WAN address, `no interface PPPoE0 ipcp default-route`, a bad MTU or wrong PPPoE credentials cut kcc off with no recovery timer. The unsaved change stays until someone power-cycles the router.
- **Fix:** Classify these the same way as `plan_priority` (`plan_named_generated`), or take a `ManagementVerdict`.

#### M18. Read-only polling login opens a new router session (and ndw4 Argon2) every round and never logs out
- **Area:** Resources. **Ids:** SEC2-03, B-06. **Critic:** SEC2-03 confirmed; B-06 confirmed.
- **Where:** `crates/kcc-app/src/registry.rs:646-655`, `poller.rs:358`, `poller.rs:29`, `poller/extended.rs:78`, `crates/kcc-app/src/registry.rs:646-653`
- **Impact:** - Each poll performs a full login: 1-2 fresh router sessions every 15 s per router, never closed. - On ndw4 firmware each login runs an Argon2 derivation with router-chosen cost under the single global permit (`ndw4_keys.rs:18`), which delays every other router's login. - This floods the router's login log. INFERRED: it may exhaust the router's session table and block the admin's own UI logins.
- **Fix:** Cache the read-only client per id like `client()` does (invalidate on reload/update), and use it in both `poll_client` and `poll_info`.

#### M19. Every audit append re-reads, re-parses and re-hashes the whole retained log under the cross-process lock
- **Area:** Audit. **Ids:** B-01, SEC2-05. **Critic:** B-01 adjusted (high→medium); SEC2-05 confirmed.
- **Where:** `crates/kcc-app/src/audit.rs:582-597`, `audit.rs:750-783`, `writer.rs:46-57`, `audit.rs:444-449`, `crates/kcc-app/src/audit.rs:587-588`
- **Impact:** Rotation is 50 MiB and retention is 365 days (`audit.rs:35,39`), so the retained log only grows. Each audited action (login, MCP call, change) costs CPU and a transient allocation proportional to the whole retained log, and blocks every other kcc process sharing the state directory for that time. As the log grows, receipts pass `AUDIT_WAIT` and changes are reported as `audit_pending`. Once 128 entries are queued, ...
- **Critic correction:** The O(retained log) append under the cross-process lock is real and contradicts `SECURITY.md:315`. The latency and memory figures are unproven. The fix stays as proposed: read the tail of the newest file under the lock and keep full verification for `verify_chain` and startup.
- **Fix:** Under the lock, read only the tail of the newest file (seek back to the last newline) to get `seq` and `hash`. Keep full verification for `verify_chain` and startup. Detect rotation by another process with file identity and size checks.

#### M20. One torn or partial audit line stops `kcc serve` from starting and kills the writer
- **Area:** Audit. **Ids:** B-03, SEC2-04. **Critic:** B-03 confirmed; SEC2-04 confirmed.
- **Where:** `crates/kcc-app/src/audit.rs:621-624`, `audit.rs:761-762`, `audit.rs:444-445`, `crates/kcc/src/server.rs:365-369`, `crates/kcc-app/src/audit.rs:587-588`
- **Impact:** A power loss or a partial `write_all` on ENOSPC leaves half a JSON line. The writer stops (any non-lock error is fatal), and every later `kcc serve` start and every audited CLI command fails until someone edits `audit.jsonl` by hand. A partial write is crash damage, not tampering, yet it is treated the same way.
- **Fix:** On open, if the last line has no trailing `\n`, truncate the file back to the last newline and log it (an incomplete line has no hash to protect). Treat only complete lines that fail verification as tampering.

#### M21. "Bounded" audit waits block without limit once the 128-slot queue is full, including inside a safety bracket
- **Area:** Audit. **Ids:** B-04. **Critic:** B-04 confirmed.
- **Where:** `crates/kcc-app/src/audit.rs:452`, `workflow_receipts.rs:48`, `crates/kcc-domain/src/configuration/bracket.rs:113-127`, `crates/kcc-web/src/auth.rs:486-490`
- **Impact:** The writer keeps retrying while another process holds the append lock (`writer.rs:85-104`), for example a stalled process or a slow append from B-01. Once 128 entries are queued, every `submit` waits indefinitely: - a bracket's `apply` never reaches its disarm, and shutdown waits on the open bracket; - Web sign-ins hang despite their 5 s bound. The module docs promise the opposite.
- **Fix:** Put the reserve under the caller's limit, e.g. `timeout(limit, sender.reserve())`. For deferred receipts, use an unbounded queue or `try_reserve` and return a `Pending` that reports "not queued".

#### M22. Every login attempt runs Argon2 and rewrites `users.json` with fsync under the exclusive cross-process lock
- **Area:** Resources. **Ids:** B-05. **Critic:** B-05 adjusted.
- **Where:** `crates/kcc-app/src/accounts.rs:386-406`, `persist.rs:206-224`
- **Impact:** An unauthenticated client sending login attempts with random usernames forces, per attempt, one Argon2id run (19 MiB, t=2) plus one durable rewrite, all serialized behind one cross-process lock. Real logins, password changes, account administration and `has_admin` writers queue behind them, and the Web `spawn_blocking` pool fills with threads parked on `flock`.
- **Critic correction:** Remove `has_admin` from the impact. Fix: skip the write when nothing changed, and move Argon2 out of the file lock but behind a small semaphore.
- **Fix:** Read the document without the lock, run Argon2 outside it, then take `update` only when the failure counters or lockout actually change. Give `update` a "no change, skip write" result.

#### M23. Conflict check needs both checksum and agent to differ, so a change by another RCI client goes unnoticed
- **Area:** Change workflow. **Ids:** B-02. **Critic:** B-02 adjusted.
- **Where:** `crates/kcc-app/src/workflow.rs:692-700`, `crates/kcc-testkit/src/config_state.rs:42`, `workflow.rs:1429`, `tests/workflow.rs:91-108`
- **Impact:** Any other HTTP RCI client produces the same agent as kcc: another kcc install, a script, or (INFERRED) the router's own web UI, which also talks RCI. If such a client changes the router between kcc's read and its write, the checksum differs but the agent matches, so no `Conflict` is raised and kcc writes over a configuration it never read. The same gap applies between writes inside a change set.
- **Critic correction:** This is a plan-mandated rule that does not deliver the README/ARCHITECTURE promise ("refuses if someone else changed the router"). In `check_conflict`, the agent clause protects nothing from kcc's own writes, so use checksum only, as `ensure_unchanged` already does. Separately, the "since the ...
- **Fix:** Compare `checksum` alone against kcc's own last observed state, which already tracks kcc's own writes. If kcc's own changes from other sets must be allowed, compare `(agent, user)` against kcc's login rather than agent alone.

#### M24. Several successful MCP actions are not audited although Web and CLI audit them
- **Area:** Audit. **Ids:** E-08. **Critic:** E-08 confirmed.
- **Where:** `crates/kcc-mcp/src/config_tools/backups.rs:82-87`, `generic/fleet.rs:216-220`, `preset_tools/capture.rs:190-207`, `preset_tools/manage.rs:70-76`
- **Impact:** An agent can create backups, cancel another user's migration job, and overwrite or delete presets (see E-02) with no trace in `audit.jsonl`.
- **Fix:** Append a success `AuditEvent` on these paths, as the Web/CLI equivalents do.

#### M25. RCI cookie refresh stores any `Set-Cookie` into the session, including on 401 and from requests sent with an older cookie
- **Area:** RCI client. **Ids:** A-02. **Critic:** A-02 confirmed.
- **Where:** see ids
- **Impact:** 1. If a 401 carries `Set-Cookie: <name>=<new pending id>`, as the router's `/auth` challenge does, that unauthenticated cookie is installed. `reauthenticate_after` then sees a "different" cookie and skips login. The replay gets 401 and the caller sees `Http{401}`. Every later request repeats this until the local `Max-Age` (300 s) expires. 2. Request R1 is sent with cookie A. Meanwhile R2 re-authenticates to cookie ...
- **Fix:** Refresh only on non-401 responses, and only while the current cookie `same_cookie(&snapshot)`. Never turn a refresh-parse failure into an error on a response that was already applied.

#### M26. `RciClient::show` drops the query on the POST fallback and caches the path as POST-only
- **Area:** RCI client. **Ids:** A-03. **Critic:** A-03 confirmed.
- **Where:** `crates/kcc-rci/src/engine.rs:399-412`
- **Impact:** Callers pass queries: `kcc-app/src/poller.rs:444` uses `show(&show/interface/stat, &[("name", id)])`, and `kcc-mcp/src/generic/rci.rs:204` uses the agent's `input.value`. If GET answers 404 once, the POST is sent with `{}` and no `name`, so the unfiltered answer is returned as if it were the filtered one. The path is then cached POST-only for the client's lifetime, so every later query on it is ignored too. The ...
- **Fix:** POST the serialized query as the body: build the POST body from `query` (`serde_json::to_value(query)`) instead of `{}`, or refuse the fallback when the query is not empty.

#### M27. `batch` never checks the reply length and drops completed chunks on a later error
- **Area:** RCI client. **Ids:** A-04. **Critic:** A-04 adjusted.
- **Where:** `crates/kcc-rci/src/engine.rs:429-449`, `crates/kcc-app/src/workflow_batch.rs:52-70`
- **Impact:** - If the router returns fewer elements than the chunk had, the missing items count as neither succeeded nor failed, and the change is reported as fully applied. - Extra elements shift which item each result belongs to, across chunks. - A transport error on chunk 2 returns `Err` for the whole call, so the caller cannot tell that chunk 1 was already applied. - `stop_on_error` cuts off the results of items the router ...
- **Critic correction:** Drop the `stop_on_error` impact. The concrete consequence is an applied but unaudited multi-chunk batch on a later-chunk failure, plus silent miscounting if the reply is short.
- **Fix:** Return `Decode` (or a typed partial error that carries the results so far) when `values.len() != chunk.len()`. On a mid-batch failure, return the completed results together with the error.

#### M28. Bracket disarm runs the full write preflight, so a local refusal blocks cleanup and is reported as "may be armed"
- **Area:** Safety bracket. **Ids:** C-02. **Critic:** C-02 confirmed.
- **Where:** `crates/kcc-domain/src/configuration.rs:271-273`, `kcc-app/src/workflow.rs`, `recovery.rs:113-116`
- **Impact:** - Another agent edits the router after the change set starts. The arm is refused locally with Conflict, and so is the disarm. Nothing was sent, but the user is told a rollback timer may be counting down. The same happens with a failed backup download. - A foreign edit during the work makes the disarm fail its conflict check, so it is never sent. The router timer then fires after 300 s and discards all unsaved ...
- **Fix:** Send the disarm (and keep-alive) through a path that skips the conflict and backup preflight and keeps the authorization. Have `arm_failed` report `None` when the arm failed before anything was sent.

#### M29. `guarded` replaces and then cancels a recovery timer the operator armed earlier
- **Area:** Safety bracket. **Ids:** C-03. **Critic:** C-03 confirmed.
- **Where:** `crates/kcc-domain/src/configuration/bracket.rs:112-137`, `configuration.rs:103-121`
- **Impact:** An operator arms `kcc config failsafe arm 3600` as a safety net, then makes a management change in the Web UI. The bracket resets the timer to 300 s and then sends `no system configuration fail-safe timer`, so the operator's net is silently gone. In scheduled-reboot mode, `no system reboot` likewise cancels a reboot the operator scheduled.
- **Fix:** When the baseline shows `fail-safe.active == true`, either refuse the bracket or run the work without arming or disarming and leave the existing timer to its owner.

#### M30. Component commit job reports "completed" before the router reboots
- **Area:** Safety bracket. **Ids:** C-11. **Critic:** C-11 confirmed.
- **Where:** `crates/kcc-domain/src/components/commit.rs:66-81`
- **Impact:** A real router keeps answering while it downloads and flashes. The job finishes at once with `after_firmware` and `after_components` equal to the old state, and then the router reboots. The test (`tests/components.rs:57-73`) checks a fresh `poll_info` after the job ends, not the job's own report, so it passes anyway.
- **Fix:** Require one failed probe (down) before accepting a successful one, and compare the components against what was staged.

#### M31. Finish failures report "timer not armed" while the timer is still armed
- **Area:** Safety bracket. **Ids:** G-05. **Critic:** G-05 adjusted.
- **Where:** `crates/kcc-migrate/src/apply/finish.rs:32-39`, `failure.rs:113-133`, `crates/kcc-web/src/wizard/finish.rs:232`
- **Impact:** the operator clicks Keep. A transient `detect()` failure or a concurrent change makes the UI, CLI or MCP report a plain failure with the timer off, while the router timer is still armed. The router then rolls back the changes the operator believed were kept.
- **Critic correction:** `Drift` comes from `commit` and `keep_unsaved`, not from `rollback`. The harmful cases are commit and keep; rollback's misreport is cosmetic.
- **Fix:** map every pre-close failure in `commit`, `keep_unsaved` and `rollback` (including `ensure_unchanged`) to an armed variant: `FinishFailed`, or a new `Drift`-with-armed fate.

#### M32. An abandoned or timed-out Web apply, or an applied MCP migration/preset, holds the router lease for the life of the process
- **Area:** Change workflow. **Ids:** W5-01, E-03. **Critic:** W5-01 confirmed; E-03 adjusted.
- **Where:** `crates/kcc-web/src/migrate_wizard/apply.rs:75-88`, `brackets.rs:142-150`, `migrate_wizard/launch.rs:53`, `presets_page/launch.rs:60`, `crates/kcc-mcp/src/migration_tools/state.rs:38-39,69-74,177-190`
- **Impact:** A user confirms Apply, and either the fresh read of a slow target takes more than 30 s or the user closes the tab. The future is dropped at an `.await`, so `release` never runs. The `active` entry (`wizard/service.rs:52-57`) keeps the target. Every other run of that wizard against that router then gets "busy" until kcc restarts. A related path: if `visit.save()` fails at `launch.rs:109` after the job started, ...
- **Critic correction:** Restate it as: MCP has no recovery path for an abandoned apply (owner-only finish, no TTL), and its plan map grows without bound. A lease TTL tied to the armed timer belongs in the shared design, because the Web has the same retention.
- **Fix:** Wrap the claim in a guard whose `Drop` releases it unless it is disarmed after `start_run` has been saved. Do the reads before claiming, and call `brackets::hold()` right before `Applier::start`.

#### M33. Wizard session eviction breaks per-run mutual exclusion; any Migrate user can trigger it
- **Area:** Change workflow. **Ids:** W2-02. **Critic:** W2-02 adjusted.
- **Where:** `wizard/visit.rs:54-59`, `wizard/service.rs:296-301`, `migrate_wizard/launch.rs:52-85`
- **Impact:** An operator who holds `Migrate` sends 64 GETs to `/ui/migrate/<valid-looking-id>`, which creates 64 sessions. Another user's run is evicted while its launch is in flight: - A second request on that run gets a fresh session and turn, so two requests interleave on the record. - The `Live` lands on the orphaned session. The page then reads the apply as interrupted (`resume.rs:311`), and finish answers 409 ...
- **Critic correction:** Evidence is at `wizard/service.rs:73-79` and `wizard/resume.rs:114`; the 409 is at `finish.rs:213-215`. The fix stands as proposed.
- **Fix:** Load and check the record's owner before calling `wizards.session(id)`, then take the turn and re-read. Evict only sessions with `Arc::strong_count(session) == 1` and `live == None`.

#### M34. `kcc mcp stdio` has no signal handling, so a signal skips the bracket wait, job drain and audit flush
- **Area:** Process lifecycle. **Ids:** F-05. **Critic:** F-05 confirmed.
- **Where:** `crates/kcc/src/server.rs:234-235`, `rmcp-server-kit-3.21.1/src/transport.rs:5916-5937`
- **Impact:** An MCP client that stops its child with SIGTERM (or a Ctrl-C) during a management change kills the process at once. The disarm is never sent, so the router's timer rolls back an applied change later. Queued audit entries are lost and jobs are not drained. BACKLOG line 43 ("kcc mcp stdio do[es] wait for open brackets") holds only when stdin reaches EOF.
- **Fix:** Wrap `serve_stdio` in a `select!` with `tokio::signal::ctrl_c()` and a SIGTERM stream, then fall through to the existing wait, drain and flush.

#### M35. DHCP: `parse_pools` attaches later indented lines to the last pool; pool planning keeps only the first DNS server, cannot clear DNS, defaults the gateway and lets a "new" pool overwrite an existing one
- **Area:** Domain correctness. **Ids:** C-08, C-09, W3-04, F-11. **Critic:** C-08 confirmed; C-09 adjusted; W3-04 confirmed; F-11 adjusted.
- **Where:** `crates/kcc-domain/src/dhcp/model.rs:175-187`, `crates/kcc-domain/src/dhcp.rs:107-112`, `dhcp/model.rs:140-143`, `kcc-web/src/clients_pages/dhcp_forms.rs:140`, `clients_pages/dhcp_forms.rs:86`
- **Impact:** A later block such as `ipv6 subnet Default` with ` bind Bridge0`, or any block with an indented `enable`, overwrites the last pool's `interface` or `enabled`. The DHCP page then shows the wrong binding. `plan_static_lease` (`dhcp.rs:130-135`) also runs its subnet check against the wrong bridge, so it wrongly accepts or refuses leases.
- **Critic correction:** The reachable path is `kcc dhcp pool … --dns A --dns B`, not the Web UI. Drop "clears the DNS servers". The harmful default is the gateway, and the replace resets only lease and state.
- **Fix:** Clear the current pool on any non-indented line that is not an `ip dhcp pool` header.

#### M36. Firewall planner/reader bugs: FQDN group description always refused, ports rendered for ICMP/ESP/GRE/IP rules, one unparsable rule fails every CLI/MCP firewall write after the write
- **Area:** Domain correctness. **Ids:** D-03, D-05, D-06. **Critic:** D-03 confirmed; D-05 confirmed; D-06 confirmed.
- **Where:** `crates/kcc-domain/src/dns/change.rs:172-175`, `kcc-catalog/src/validate.rs:225-230`, `firewall/change.rs:193-202`, `crates/kcc-mcp/src/domains/write/filtering.rs:214,227`, `tests/firewall_render.rs:25,117-121`
- **Impact:** MCP `fqdn_group` with a description (`kcc-mcp/src/domains/write/dns.rs:152`) and the CLI (`kcc/src/cli/dom_dns.rs:172`) always fail with a validation error. No test covers it.
- **Fix:** Validate `{"description"}` only and carry `name` outside the validated value, as `FqdnInclude` does. Add a test.

#### M37. Clearing a connection-policy description always fails
- **Area:** Domain correctness. **Ids:** D-04. **Critic:** D-04 confirmed.
- **Where:** `crates/kcc-domain/src/policies/change/plan.rs:36`, `crates/kcc-domain/src/policies/change/render.rs:46-49`
- **Impact:** The Web policy description dialog with an empty field (`kcc-web/src/routing_page/policy_forms.rs:154`) goes through `apply::apply` → `render::request` → `expected_leaf`, which returns `InvalidResponse`. Removing a description is impossible from any surface.
- **Fix:** When `no` is set, render `no ip policy N description` without an argument.

#### M38. Route removal verified by routing-table row count; the route-wipe recovery is lossy
- **Area:** Domain correctness. **Ids:** D-08. **Critic:** D-08 confirmed.
- **Where:** `crates/kcc-domain/src/routing/change.rs:83-104`, `change/ipv6.rs:95-118`
- **Impact:** Several removals go wrong: - **Inactive route:** a static route whose gateway is down is not in `show ip route`. Its removal returns `RouteCountMismatch` even though it succeeded. - **Concurrent changes:** any DHCP or PPP route change between the two reads does the same. - **Interface-only routes:** in the "cleared" recovery, a route like `net mask Wireguard0` is planned with `gateway=Wireguard0` and fails ...
- **Fix:** Verify absence of the exact command in `show rc`. Take the restore set from the running config, not the table, and restore every route before returning the first error.

#### M39. Segment create does not roll back the step that failed
- **Area:** Domain correctness. **Ids:** D-09. **Critic:** D-09 confirmed.
- **Where:** `crates/kcc-domain/src/segments.rs:206-224`, `segments/step.rs:255-265`
- **Impact:** If the router accepts a step (for example `interface Bridge23 ip address …`) but the read-back does not match, `Bridge23` stays configured. kcc still returns `StepFailed`, whose doc says rollback ran. The test `bridge_failure_rolls_vlan_and_trunks_back` only covers a parse refusal.
- **Fix:** When the step's own request was sent, include that step in the rollback (run its delete line).

#### M40. VPN-client Delete removes any interface and drops the catalog's Destructive risk
- **Area:** Domain correctness. **Ids:** D-11. **Critic:** D-11 confirmed.
- **Where:** `vpn_clients/render.rs:21-25`, `vpn_clients/change.rs:96-101`, `interfaces/management.rs:92-120`, `kcc-catalog/src/runtime.rs:466-467`
- **Impact:** An MCP `vpn` call with `op=delete, name=ISP` (or `Bridge1`, or a Wi-Fi AP) deletes a non-VPN interface with `Write` only. Deleting `Bridge0` needs just `confirm:true`.
- **Fix:** Read the interface first and refuse names whose `type` is not a VPN client type. Keep `max(catalog risk, classified risk)`.

#### M41. VPN server status reads the crypto-map virtual IP at the wrong JSON pointer
- **Area:** Domain correctness. **Ids:** D-12. **Critic:** D-12 confirmed.
- **Where:** `crates/kcc-domain/src/vpn_servers.rs:208,222-225`, `vpn_servers/verification.rs:37-41`
- **Impact:** Any configured IPsec virtual-IP server shows up as `{}`. The read only works if a map is literally named `virtual-ip`.
- **Fix:** Request `crypto map {}` and collect `virtual-ip` per map name.

#### M42. WireGuard ASC: the doc says extra values are ignored, but the line keeps them
- **Area:** Domain correctness. **Ids:** D-17. **Critic:** D-17 confirmed.
- **Where:** `vpn_clients.rs:227-228`, `vpn_clients/render.rs:62-66`
- **Impact:** `kcc vpn wireguard-asc NAME v1 … v17` (`kcc/src/cli/dom_vpn.rs:185-187`) sends 17 words while 16 were validated. An `I1` value containing spaces (AmneziaWG's `<b 0x…>`) splits into several words.
- **Fix:** Refuse more than 16 values, and quote each value.

#### M43. Migration verification always fails without WAN Internet or `Bridge0`; the management interface is guessed as the first bridge
- **Area:** Domain correctness. **Ids:** G-06. **Critic:** G-06 confirmed.
- **Where:** `crates/kcc-migrate/src/apply/verify.rs:152-174`, `inventory.rs:245-248`
- **Impact:** pre-staging a replacement router on the bench (no uplink), the typical migration flow, can never reach `verified`. Commit and Keep are refused, and only rollback remains. A router managed through `Bridge1` gets its management-IP change classified as additive (no reconnect), and verification still checks `Bridge0`.
- **Fix:** make the Internet check informational or an explicit option. Derive the management interface from the interface carrying the management URL's address, and check that interface's link.

#### M44. Failed router reads are swallowed into defaults that drive later Web changes
- **Area:** Domain correctness. **Ids:** W3-05. **Critic:** W3-05 adjusted.
- **Where:** see ids
- **Impact:** After one transient read failure, the security-level dialog opens with Private selected for a Public WAN, and the address dialog opens in DHCP for a static IPoE connection. Submitting either unchanged plans a management change the user never meant. Elsewhere the user gets a misleading field error, and the audit records "gone" instead of "unreachable".
- **Critic correction:** 1. The two dialogs whose wrong defaults could plan a management change still ask before it runs: security level uses `.confirming(Risk::Management)` (`net_interface_edits.rs:201`), and the address dialog uses `.confirming_planned` (`net_internet_address.rs:193`). The risk is a misleading ...
- **Fix:** On a dialog `GET`, answer with `net_change::unusable(..)` (already used by `net_internet_settings.rs:46`). In checks, return `Rejected::Failed(unread(..))` instead of defaulting.

#### M45. MCP result truncation replaces the whole payload, including error codes and fail-safe messages
- **Area:** MCP. **Ids:** E-04. **Critic:** E-04 confirmed.
- **Where:** `crates/kcc-mcp/src/support/shape.rs:191-203`, `kcc-app/src/settings.rs:202`
- **Impact:** A confirmed 64-item `kcc_rci_batch` whose disarm fails returns `BatchFailSafeArmed` with every response included. If that is over 32 KiB, the agent gets `is_error` with no `error` code, no `management_applied_fail_safe_armed` message and no per-item outcomes. A successful large write loses `unsaved`, `persists_immediately`, `audit_pending` and the notice. `"next_cursor":"1"` is meaningless for tools without a cursor ...
- **Fix:** Always keep `error`, `message`, `field`, `unsaved`, `persists_immediately` and `audit_pending`, and truncate only the bulky array. Emit a real next offset only for tools that take `cursor`.

#### M46. Every MCP interface write failure becomes `conflict`, losing `verification_failed` and its field
- **Area:** MCP. **Ids:** E-07. **Critic:** E-07 confirmed.
- **Where:** `crates/kcc-mcp/src/domains/write/interfaces.rs:143-150`
- **Impact:** A `description` or `security_level` change the router accepts but does not apply returns `conflict` with no `field`, and so do forbidden, unreachable and rejected outcomes. The test hides it: `tests/support/interface_refusals.rs:71-73` only checks `reply.error().is_some()`.
- **Fix:** Expose a mapping accessor on `InterfaceChangeError` (Domain/Workflow) and route it through `map_domain`/`map_workflow`.

#### M47. Log sinks: transport errors are not retried, there is no HTTP timeout, retries are unbounded and shutdown drops queued records uncounted (docs promise at-least-once)
- **Area:** Telemetry. **Ids:** G-08, G-09. **Critic:** G-08 confirmed; G-09 confirmed.
- **Where:** `crates/kcc-telemetry/src/logs/sink.rs:290-305`, `pipeline_delivery.rs:216-219`, `elastic_sink.rs:188`, `sink.rs:76`, `elastic_sink.rs:76`
- **Impact:** any Loki or Elasticsearch restart, connection reset or DNS blip permanently loses up to 1,000 records per batch. The retry and backoff machinery covers only HTTP 429 and 5xx.
- **Fix:** treat `Transport` (and `BulkError::Delivery(Transport)`) as retriable.

#### M48. One malformed router log record silently blocks all forwarding for that router
- **Area:** Telemetry. **Ids:** G-10. **Critic:** G-10 confirmed.
- **Where:** `crates/kcc-telemetry/src/logs/service.rs:285-287`, `parser.rs:42-48`
- **Impact:** none of the records in a failing response pass dedupe, so every poll or stream read returns the same bad record and drops the whole batch again. Forwarding for that router stops until the record leaves the router's 200-line window. Nothing is logged and no metric counts it.
- **Fix:** parse per record, skip and count the bad ones (`log_records_dropped("collector","parse")`), and keep the rest.

#### M49. Router-local log timestamps are stamped as UTC
- **Area:** Telemetry. **Ids:** G-11. **Critic:** G-11 confirmed.
- **Where:** `service.rs:280-284`, `parser.rs:130`, `types.rs:13`, `tests/logs.rs:60`
- **Impact:** for a router at UTC+3, every record is sent 3 h in the future (INFERRED: Loki then rejects these as "too far in the future", and Elasticsearch stores the wrong `@timestamp`). Year inference near midnight on New Year's is also off by the offset.
- **Fix:** obtain the router's UTC offset (for example from `show clock date`) per collector and pass it to `parse_records`. Otherwise label the field "naive local time" and do not claim UTC.

#### M50. Log batch selection re-encodes the whole batch per record while holding a std `Mutex`
- **Area:** Telemetry. **Ids:** G-13. **Critic:** G-13 confirmed.
- **Where:** `pipeline_delivery.rs:157-162`
- **Impact:** up to about 500,000 record serializations (O(n²)) per 1,000-record batch run on a runtime worker thread. Meanwhile every relay's `push` blocks on the same std mutex and stalls its executor thread during log bursts.
- **Fix:** add each record's encoded size incrementally (plus a fixed envelope), and pop the batch under the lock but measure it outside.

#### M51. A failed sign-in shows nothing in the browser (htmx never swaps the 401)
- **Area:** Web UX. **Ids:** W1-04. **Critic:** W1-04 confirmed.
- **Where:** `crates/kcc-web/src/auth.rs:379-388`, `templates/pages/login.html`, `assets/js/app.js:27-32,418-424,450-456`, `base.html`
- **Impact:** Every wrong password or locked account in a real browser leaves the form unchanged, with no "Invalid username or password" message. `tests/auth.rs:189-224` checks the raw 401 body, so the suite cannot catch this.
- **Fix:** Answer the failed login with 422, which app.js already swaps and which keeps the uniform text. Alternatively, add 401 to the app.js `beforeSwap` override.

#### M52. Router connection test ignores the selected sign-in mode and never uses a typed token
- **Area:** Web UX. **Ids:** W1-06. **Critic:** W1-06 adjusted.
- **Where:** `crates/kcc-web/src/router_check.rs:57-58,74-82`, `router_form.rs:251-257`, `kcc-app/src/registry.rs:92`, `kcc-app/src/registry/auth.rs:41-46`
- **Impact:** (a) With Digest, NDW2 or NDW4 selected, the test signs in with Auto, so it can pass while the saved profile fails, or the reverse. (b) On the add form in token mode, a typed token always gives "password required". (c) On the edit form in token mode, the test silently checks the old stored URL and token instead of the typed values.
- **Critic correction:** (b) On the add form in token mode, a typed token is never used. The test answers with the id-format error, or "password required" when the id is empty.
- **Fix:** Set `profile.auth` from the parsed form, which needs an accessor on `Parsed`. Make `Typed` expose the primary secret of either kind, and add a `test_connection_with` variant that takes a token.

#### M53. `kcc backup diff` compares sets of redacted lines, so it misses real changes
- **Area:** CLI. **Ids:** F-07. **Critic:** F-07 adjusted.
- **Where:** `crates/kcc/src/cli/persist.rs:176-186`, `args_fleet.rs:139`, `kcc-web/src/config_page/text.rs:36-43`
- **Impact:** A changed password, PSK or WireGuard key becomes `<redacted>` on both sides and is invisible. A repeated line (`up`, `exit`, `shutdown`) added to one block while it exists elsewhere is also invisible. `kcc backup diff` prints nothing (exit 0) for backups that differ. The help promises a count; the command prints lines.
- **Critic correction:** Drop the claim about `up`/`exit`/`shutdown` in other blocks. The defect is invisible secret changes, plus set semantics for reordering and exact duplicates.
- **Fix:** Diff the full-text digests in order (as the Web does), print `shown[i]`, and fix the help text.

#### M54. User-visible English strings outside `kcc-i18n` (project rule (f))
- **Area:** i18n. **Ids:** F-10. **Critic:** F-10 confirmed.
- **Where:** see ids
- **Impact:** `--lang ru`, `de`, `kk` and the other locales get English detail lines. `Detail::Text` is documented as typed-error text, but these are hand-written sentences.
- **Fix:** Add keys and use `Failure::message`.

#### M55. CI and container workflows trigger on `main`; the only branch is `master`
- **Area:** Build/CI. **Ids:** X-01. **Critic:** X-01 adjusted (high→medium).
- **Where:** `.github/workflows/ci.yml:3-8`, `.github/workflows/container.yml:3-8`, `CONTRIBUTING.md:3`
- **Impact:** Pushes to `master` and pull requests against it, including Dependabot's, start neither CI nor the container e2e. No G0 or G1 gate (fmt, clippy, test, deny, audit, vet, machete, xtask gates, shellcheck, actionlint) blocks a merge. This also explains how X-02 could go unnoticed.
- **Critic correction:** Medium, not high: the gap is in the CI process and has no runtime consequence. Fix it with `branches: [master]` in `ci.yml` and `container.yml`, or by removing the branch filter. Also fix `kcc.container:12` `blob/main`, which will 404.
- **Fix:** Use `branches: [master]` in `ci.yml` and `container.yml`, or rename the default branch and update CONTRIBUTING.md. Then make the CI jobs required status checks.

#### M56. `deploy/podman/e2e.sh` step functions ignore `set -e`, so failures in the middle of a step pass
- **Area:** Build/CI. **Ids:** X-03. **Critic:** X-03 confirmed.
- **Where:** `deploy/podman/e2e.sh:74-77`, `e2e.sh:327-332`, `e2e.sh:414-421`, `live-e2e.sh:72-75`
- **Impact:** Bash ignores errexit inside a function called as an `if` condition. I confirmed this with a scratch run: `f(){ false; echo after; true; }; if f; then echo PASS; fi` prints PASS. The container e2e is the only proof that the seccomp profile allows the write and save path. If the profile misses a syscall that only `config save` uses, the step still passes. The `no-denials` grep does not catch it either, because kcc ...
- **Fix:** In both `step()` helpers, run `set +e; ( set -e; "$@" ) >"$log" 2>&1; rc=$?; set -e`, then test `rc`. I verified this form returns 1 on a failure in the middle of the function.

#### M57. Secret-leak tests cannot fail: every test secret contains `"`/`\`, which quoting escapes before the comparison
- **Area:** Tests. **Ids:** T-01. **Critic:** T-01 confirmed.
- **Where:** `crates/kcc-app/tests/secrets_write.rs:72`, `crates/kcc-domain/tests/users.rs:77`, `crates/kcc-domain/tests/wifi.rs:134,140-161`, `wan.rs:119,125-150`
- **Impact:** - `Debug` and JSON both write `"` as `\"` and `\` as `\\`. The raw secret is therefore never a substring of those encodings. - Example: a regression that copied the plaintext into the audit entry's `detail` would produce `...with \"quote\" and \\\\ slash` in `audit.jsonl`, and every assertion above would still pass. The same holds for a `#[derive(Debug)]` on a secret-holding type or a `?`-formatted tracing field. - ...
- **Critic correction:** Scope note: "only catch leaks printed raw" is overstated. `kcc/tests/cli_domain_writes/secrets.rs` (`PASSWORD = "s3cret-Vpn-Passw0rd"`, WireGuard keys) and `kcc-migrate/tests/support/apply_secrets.rs` use quote-free secrets against the audit log. The `kcc-app` scrub test and the four domain suites ...
- **Fix:** Check each sink against every encoding the secret can take there: `serde_json::to_string(secret)` without its outer quotes, `secret.escape_debug()`, and the CLI-quoted form. Alternatively, add a second secret with no characters that need escaping and run the checks on both.

#### M58. `live_presets` and `live_mcp` cannot reach a real router; their twins hide it with `allow_loopback`
- **Area:** Tests. **Ids:** T-02. **Critic:** T-02 confirmed.
- **Where:** `crates/kcc/tests/live_presets.rs:186-190`, `crates/kcc-mcp/tests/live_mcp/session.rs:218-220`, `crates/kcc-app/src/registry.rs:387-395`, `kcc-rci/src/outbound.rs:254-259`
- **Impact:** - With the live variables set against, say, 192.168.1.1, both suites pass the gate and the serial check: `capture::connect` uses `OutboundPolicy::default()`, which allows private networks. - The `kcc` process (`live_presets`) and the MCP registry (`live_mcp`) then refuse the router, so both suites always fail on hardware. - The twins pass because loopback is allowed, so the fake runs never exercise the real outbound ...
- **Fix:** Copy `outbound` from the admitted `KCC_LIVE_TARGET_CONFIG` into the hermetic `kcc.toml` and into the MCP registry, as `live_domains/campaign.rs:157-161` and `live_migration/rehearsal.rs:211-215` already do. In the twins, set `allowed_networks` instead of relying on loopback alone.

#### M59. Radio mappings never rewrite access-point tokens (`WifiMaster0/AccessPoint0`)
- **Area:** Domain correctness. **Ids:** H4a (from the G critic's NEW-1). **Critic:** confirmed by the second critic (medium).
- **Where:** `crates/kcc-config/src/config_text.rs:295-345`, `crates/kcc-migrate/src/rules.rs:682-690`, `crates/kcc-migrate/src/presets/plan/classify.rs:28-46`
- **Impact:** A proposed radio mapping moves the radio settings but leaves SSID, schedule and PSK on the source-numbered AP, which may be on the other band. The wizard lists APs separately, so an operator can work around it.
- **Fix:** When a radio is mapped, derive mappings for its `WifiMasterN/…` children (or match on the token prefix before `/`).

## Anti-patterns introduced by the worker (themes)

These are the recurring shapes behind the findings. Each theme lists validated ids, which are in the sections above or in Appendix A.

1. **One rule written per surface or per planner, then drifting.**
   - Examples:
     - secret masking: MCP denylist vs Web `mask` vs `kcc_config::secrets` (H1, M07, M10);
     - CLI quoting (M06);
     - management risk (M17);
     - confirmation gating (M16);
     - permission rule on firewall pages (M14);
     - domain-to-workflow error mappings (W3-06);
     - typed-name confirmation, three implementations (W2-12);
     - redaction pipeline, three copies (F-08);
     - Unix-time helper, five copies (F-25);
     - copied planner helpers (C-17, D-19);
     - config-text walkers (D-13);
     - helpers copied between the wizards (W5-07);
     - MCP tool metadata duplicated (E-14);
     - drifted telemetry copies (G-21).
   - This is the dominant source of real bugs.
2. **Opt-in safety.**
   - Confirmation (W2-01, W3-01, N11) and the bracket (C-06, C-05, N7) apply only where a handler or planner remembers to ask for them, instead of being derived from `ChangeOp.risk` in one place.
   - Tests are written the same way: they send `confirm=yes` up front (W3-07, N12).
3. **Blocking work on async workers.** File I/O and fsync, `flock`, DNS and crypto run directly in handlers (B-07, C-05, G-22, W2-08, W5-05, SEC2-09). This violates §5 "Don't call blocking I/O in async functions".
4. **Cancel-safety annotations missing or contradictory** on mutating handlers (A-18, E-11, G-20, W5-09, B-18). §5 requires them, and the xtask gate does not cover private functions.
5. **Module- or crate-wide `#![expect]` blankets** whose reasons cite "the plan mandates". They hide wildcard arms and real defects (B-11, C-14, E-10). The rule is the narrowest item with a real reason.
6. **Validated objects mutated after validation.** These bypass the validated-constructor rule of §3 (C-07, D-15, B-08), so the line sent can differ from the request that was checked.
7. **Errors swallowed or turned into the wrong variant.** Examples: `InvalidResponse` used as a catch-all, failed reads replaced by defaults, store errors downgraded (B-10, B-12, C-13, D-18, W2-11, W3-05, W4-05, W5-10, W5-14).
8. **Stringly-typed decisions.** Matching on error names, i18n keys, audit strings or `Debug` output (E-15, E-16, E-17, W3-09, W5-08, D-21).
9. **Dead, test-only or speculative code shipped in production.** Examples: an accepted-but-ignored `fields` argument, a `RevealSecrets` gate with no caller, unused public APIs that bypass the outbound policy (A-17, C-18, D-14, D-22, E-12, G-14, G-23, W2-16, W2-18).
10. **HTML carried as plain `String` and rendered with `|safe`** (SEC1-10, W2-15, W3-17). It is not exploitable today, but it is against project rule (e) "askama auto-escaping only".
11. **Review-process labels in shipped code and JS** (A-22, SEC1-13, W1-10).
12. **Tests that cannot fail or that test the fake.**
    - Every leak-test secret contains `"`, which quoting escapes before the comparison (T-01).
    - Tests send the confirmation up front, so a missing prompt cannot fail them (W3-07, N12).
    - Live twins hide the real path behind `allow_loopback` (T-02).
    - The fake hashes secrets itself, so "kcc hashes" tests check the fake (T-04).
    - Source greps stand in for behaviour (T-11, F-30).
    - Tests compare `Debug` strings as an equality proxy (T-12).
13. **Unbounded growth.** The audit log via usernames (H2), anonymous sessions (M03), the pseudonym map (E-13, G-17), wizard run directories (W5-06), shared wizard sessions (W5-12), global caps that evict other sessions (W4-07), and per-job lock files left behind (B-09).

## Guideline and overlay compliance

- **§9 lint profile:** enforced. The workspace builds clean under the full profile, and `allow-gate`/`profile-eq` pass. No gate checks lint *levels* against the vendored table (X-05, info).
- **§3 type safety:**
  - exhaustive-match intent is undermined by the blanket `#![expect]`s (theme 5);
  - validated constructors are bypassed (theme 6).
- **§5 async:**
  - blocking calls in async code (theme 3);
  - cancel-safety annotations missing or wrong (theme 4);
  - a std `Mutex` held during heavy work (M50).
- **§10 security:**
  - input bounds missing at the login boundary (H2);
  - free text reaches router CLI lines unquoted (M06);
  - outbound clients honour proxy environment variables (M05).
- **§13 testing:** tests that cannot fail and `Debug`-string comparisons (theme 12).
- **http-services overlay:**
  - cookie flags in proxy mode (M01);
  - `Cache-Control` lost on kit routes without a recorded deviation (W1-14).
- **mcp-servers overlay:**
  - tool inputs are not all treated as untrusted (M06, N3);
  - wire errors lose meaning (M45, M46).
- **Project rules:**
  - (b) raw input validated: M06;
  - (c) every curated write read back: C-22, C-23, D-07;
  - (d) secrets: H1, M07-M11;
  - (f) i18n: M54, W1-13.

## Sound areas (checked and found correct)

Reviewers and critics agreed on these. Each is backed by a lane's "Clean" section and was not contradicted by any validated finding.

- **Sealed state.** XChaCha20-Poly1305 with a fresh nonce and associated data per record. The master key is permission-checked, created race-free and zeroized. Atomic `create_new` + 0600 + fsync + rename writes. State names are validated against traversal.
- **Outbound policy.** DNS is pinned. Metadata and embedded-IPv4 forms are refused. No redirects. SPKI pinning compares in constant time. The one gap is the proxy environment variables (M05).
- **RCI authentication.** Single-flight login. ndw4 checks the endpoint, nonce prefix and cost bounds, verifies the server signature in constant time, never downgrades, and runs Argon2 off the async workers. Responses are size-capped while streaming.
- **Web CSRF and CSP.** Token plus Origin plus Fetch-Metadata on every non-GET, login included. CSP is `default-src 'none'` with no inline code. Assets carry SRI. There are no open redirects, and errors don't leak internals. 256-bit session ids rotate at login. Role-dominance checks hold.
- **MCP.** Every router tool checks permission and router scope before any request. Toolset and read-only gating removes the routes themselves. Destructive actions need the server switch plus `confirm`.
- **Shared safety bracket.** The counter is balanced on every path, panics included. The same permission is used for arm, work and disarm. `SafetyMode::decide` matches the owner's table. The bracket matrix test can fail.
- **Migration preflight order.** Authorization, then source, then tier, then firmware, then drift, then a dry build of every line, all before arming. `ApplyError` is exhaustive and serde-stable.
- **Privilege floor.** It runs before the runtime exists, verifies itself, and refuses root.
- **Live suites.** Gated on the serial allowlist and on `test_device` before any write. T-05, T-06 and T-08 are low-severity gaps in the read-only suites.

## Refuted findings (not issues)

- **SEC2-08:** one hostile LAN router stalling ndw4 logins for the whole fleet. Already in `docs/BACKLOG.md`.
- **W4-04:** cancel-safety annotations missing on ~50 handlers. Already in `docs/BACKLOG.md`.
- **G-07:** prune ordering. No front end sets `prune_lines`.
- **E-21:** `kcc_diagnostics_write` is not registered as a read-only tool.
- **W2-04:** an accepted rollback is not audited as a failure.
- **W2-13:** the cited tests don't assert on `Debug`.
- **W3-03:** Wi-Fi settings are management-classified where it matters.
- **W3-12:** read-back regions do compute permissions.
- **N13:** DHCP pool writes are read back.
- **H1d:** the CLI is not a boundary for H1.

## Recommended order

1. **High fixes, each with a regression test that would fail today:** H2, H3, H1, H7, H5, H4.
2. **Centralize the drifting rules first, then the mediums fall out:**
   - one secret masker/redactor shared by Web, MCP and config (H1, M07-M10);
   - one CLI-word rule enforced in `CliCommand::new` (M06);
   - confirmation and the bracket derived from `ChangeOp.risk` in the kit (M16-M17);
   - one error mapping.
3. **Audit and resource bounds:** M18-M22.
4. **The remaining mediums, then Appendix A.** Fix the tests in theme 12 alongside the code they cover, so they can actually fail.

## Appendix

- **Appendix A:** every validated low/info finding with location and critic verdict. File: `~/.cache/kcc-review/APPENDIX-LOW-INFO.md`.
- **Per-lane material:** reviewer reports in `~/.cache/kcc-review/findings/<lane>.md`; critic verdicts in `~/.cache/kcc-review/critics/<lane>.md`, plus `critics/SECOND-*.md`.
