# Validated findings (kcc review, HEAD 349b7fb, guidelines 49898c9)

Every row passed critic validation (first critic per finding; second critic for every high and for critic-raised items). Refuted findings are excluded and listed at the end.

## High

| # | Finding | Source ids | Where | Validation |
|---|---|---|---|---|
| H1 | Read-only role can read router secrets: MCP `kcc_rci_read` and Web explorer on `show running-config`; Web `mask` passes `{"password":{"ns3":…}}` | SEC1-01, E-01, W4-01 | `crates/kcc-mcp/src/generic/rci.rs:186-210`, `crates/kcc-web/src/advanced/viewer.rs:72-118`, `crates/kcc-web/src/page_kit/secret.rs:14-47` | 3 reviewers; 1st critics confirmed; 2nd critic confirmed (CLI part refuted); own check |
| H2 | Unauthenticated audit-log disk fill: unbounded login username written per failed login | SEC1-02 | `crates/kcc-web/src/auth.rs:47-55,495-510` | 1st + 2nd critic confirmed; own check |
| H3 | Clearing a firewall rule's description/schedule sends `no ... disable` and enables a disabled rule | D-01 | `crates/kcc-domain/src/firewall/change.rs:92-98`, `firewall/change/render.rs:127-143` | 1st + 2nd critic confirmed; own check |
| H4 | Secret-bearing lines (ns3, WireGuard keys) ignore interface/port/radio mappings in migration and presets | G-01 | `crates/kcc-migrate/rules/rules.toml:142-168`, `crates/kcc-migrate/src/rules.rs:522-535` | 1st + 2nd critic confirmed; own check |
| H5 | Migration reconnects with the new management password before it is sent | G-03 | `crates/kcc-migrate/src/apply/preflight.rs:104-110`, `apply/reconnect.rs:37-60` | 1st + 2nd critic confirmed; own check |
| H7 | CLI `apikey revoke` / `user disable` / password reset don't reach a running `kcc serve` | F-01, SEC1-05, W1-01 | `crates/kcc/src/server.rs:136`, `crates/kcc/src/cli/api_keys.rs:71-76`, `crates/kcc-web/src/authz.rs:159-201` | 1st + 2nd critic confirmed; own check |

## Medium

| # | Finding | Source ids | Where | Validation |
|---|---|---|---|---|
| M01 | Session cookie lacks `Secure` / `__Host-` when kcc runs behind the documented HTTPS reverse proxy | SEC1-03, F-03 | `crates/kcc/src/server.rs:138`, `kcc-app/src/settings.rs:895-901` | SEC1-03 adjusted high→medium; F-03 confirmed |
| M02 | SSE, log, job and traffic streams keep sending data after logout, account disable or role reduction | SEC1-06, W1-02, W5-02 | `crates/kcc-web/src/system_pages/logs.rs:151-174`, `crates/kcc-web/src/overview.rs:222-226` | SEC1-06 confirmed; W1-02 confirmed; W5-02 adjusted |
| M03 | Unauthenticated `GET /ui/login` creates anonymous sessions without a cap | SEC1-07 | `crates/kcc-web/src/auth.rs:150-156`, `session.rs:456-462` | SEC1-07 confirmed |
| M04 | Router edit seals the new credentials before the profile update and never rolls them back (Web and CLI) | SEC1-09, W1-05, F-02 | `crates/kcc-web/src/routers.rs:236-250`, `plan.rs:182` | SEC1-09 adjusted; W1-05 adjusted; F-02 confirmed |
| M05 | Router and log-sink HTTP clients honour HTTP(S)_PROXY/ALL_PROXY, bypassing the resolved-address pinning | SEC2-01 | `crates/kcc-rci/src/outbound.rs:220-224`, `session.rs:264-269` | SEC2-01 confirmed |
| M06 | Free text goes into router CLI lines unquoted (DHCP pool/host, `known host`, several firewall/policy names): extra arguments can be injected | SEC2-02, C-01, D-02 | `crates/kcc-domain/src/clients/command.rs:133`, `crates/kcc-domain/src/dhcp/command.rs:64-65` | SEC2-02 confirmed; C-01 adjusted high→medium; D-02 adjusted |
| M07 | MCP secret denylist misses hyphenated and short secret keys the Web masks | SEC1-04 | `crates/kcc-mcp/src/support/shape.rs:211-224`, `crates/kcc-web/src/page_kit/secret.rs:15-29` | SEC1-04 confirmed |
| M08 | `redact_clients` pseudonymization misses client names, free text and progress notifications | E-05 | `crates/kcc-mcp/src/support/shape.rs:271-278`, `kcc-domain/src/clients.rs:38` | E-05 confirmed |
| M09 | Generic interface reads pass `show interface` credential blobs (ns3) through `extra` | C-04 | `crates/kcc-domain/src/interfaces/models.rs:35-37`, `wan/models.rs:76-77,83-91` | C-04 adjusted |
| M10 | `secrets::redact` misses router-written ns3 secrets and blanks the wrong word for `crypto ike key` | A-01 | `crates/kcc-config/src/secrets.rs:65-93,101-107,110-130`, `crates/kcc-domain/tests/vpn_credentials.rs:81-87` | A-01 confirmed |
| M11 | WireGuard parse error can keep a raw key line in a Debug/Display error | D-16 | `crates/kcc-domain/src/vpn_clients/wireguard/parser.rs:68-74`, `wireguard.rs:102` | D-16 adjusted |
| M12 | MCP `kcc_preset_capture` overwrites an out-of-scope preset (name-derived id), with an existence oracle | E-02, G-02 | `crates/kcc-mcp/src/preset_tools/capture.rs:152-156,190-193`, `crates/kcc-migrate/src/presets/store.rs:120-129` | E-02 confirmed high, G-02 adjusted medium; 2nd critic set medium |
| M13 | Preset/migration changes to kcc's own login password bypass the management safeguards | G-04 | `crates/kcc-migrate/src/presets/apply/convert.rs:61-65`, `presets/plan/classify.rs:48-51` | G-04 adjusted high→medium |
| M14 | Firewall pages require `Destructive` for management changes, unlike every other page (contradicts D-Q1) | W3-02 | `firewall_page/run.rs:154-158`, `kcc-domain/src/configuration.rs:223-228` | W3-02 confirmed |
| M15 | Router-account protection fails open when kcc's login is empty or the profile lookup fails | W4-03 | `system_pages/shared.rs:152-157`, `user_delete.rs:104-106,119` | W4-03 adjusted |
| M16 | Management changes run without the fail-safe confirmation dialog on several Web handlers | W2-01, W3-01 | `page_kit/submit/flow.rs:51-57`, `submit.rs:317-321` | W2-01 confirmed; W3-01 adjusted |
| M17 | Management changes run without the fail-safe bracket: WAN planners hard-code `Risk::Write`; management detection falls back to Write after a blocking DNS lookup | C-06, C-05 | `crates/kcc-domain/src/wan.rs:228-237`, `crates/kcc-domain/src/interfaces/management.rs:206-209` | C-06 confirmed; C-05 confirmed |
| M18 | Read-only polling login opens a new router session (and ndw4 Argon2) every round and never logs out | SEC2-03, B-06 | `crates/kcc-app/src/registry.rs:646-655`, `poller.rs:358` | SEC2-03 confirmed; B-06 confirmed |
| M19 | Every audit append re-reads, re-parses and re-hashes the whole retained log under the cross-process lock | B-01, SEC2-05 | `crates/kcc-app/src/audit.rs:582-597`, `audit.rs:750-783` | B-01 adjusted high→medium; SEC2-05 confirmed |
| M20 | One torn or partial audit line stops `kcc serve` from starting and kills the writer | B-03, SEC2-04 | `crates/kcc-app/src/audit.rs:621-624`, `audit.rs:761-762` | B-03 confirmed; SEC2-04 confirmed |
| M21 | "Bounded" audit waits block without limit once the 128-slot queue is full, including inside a safety bracket | B-04 | `crates/kcc-app/src/audit.rs:452`, `workflow_receipts.rs:48` | B-04 confirmed |
| M22 | Every login attempt runs Argon2 and rewrites `users.json` with fsync under the exclusive cross-process lock | B-05 | `crates/kcc-app/src/accounts.rs:386-406`, `persist.rs:206-224` | B-05 adjusted |
| M23 | Conflict check needs both checksum and agent to differ, so a change by another RCI client goes unnoticed | B-02 | `crates/kcc-app/src/workflow.rs:692-700`, `crates/kcc-testkit/src/config_state.rs:42` | B-02 adjusted |
| M24 | Several successful MCP actions are not audited although Web and CLI audit them | E-08 | `crates/kcc-mcp/src/config_tools/backups.rs:82-87`, `generic/fleet.rs:216-220` | E-08 confirmed |
| M25 | RCI cookie refresh stores any `Set-Cookie` into the session, including on 401 and from requests sent with an older cookie | A-02 | `crates/kcc-rci/src/session.rs:425-433,644-651,698-703` | A-02 confirmed |
| M26 | `RciClient::show` drops the query on the POST fallback and caches the path as POST-only | A-03 | `crates/kcc-rci/src/engine.rs:399-412` | A-03 confirmed |
| M27 | `batch` never checks the reply length and drops completed chunks on a later error | A-04 | `crates/kcc-rci/src/engine.rs:429-449`, `crates/kcc-app/src/workflow_batch.rs:52-70` | A-04 adjusted |
| M28 | Bracket disarm runs the full write preflight, so a local refusal blocks cleanup and is reported as "may be armed" | C-02 | `crates/kcc-domain/src/configuration.rs:271-273`, `kcc-app/src/workflow.rs` | C-02 confirmed |
| M29 | `guarded` replaces and then cancels a recovery timer the operator armed earlier | C-03 | `crates/kcc-domain/src/configuration/bracket.rs:112-137`, `configuration.rs:103-121` | C-03 confirmed |
| M30 | Component commit job reports "completed" before the router reboots | C-11 | `crates/kcc-domain/src/components/commit.rs:66-81` | C-11 confirmed |
| M31 | Finish failures report "timer not armed" while the timer is still armed | G-05 | `crates/kcc-migrate/src/apply/finish.rs:32-39`, `failure.rs:113-133` | G-05 adjusted |
| M32 | An abandoned or timed-out Web apply, or an applied MCP migration/preset, holds the router lease for the life of the process | W5-01, E-03 | `crates/kcc-web/src/migrate_wizard/apply.rs:75-88`, `brackets.rs:142-150` | W5-01 confirmed; E-03 adjusted |
| M33 | Wizard session eviction breaks per-run mutual exclusion; any Migrate user can trigger it | W2-02 | `wizard/visit.rs:54-59`, `wizard/service.rs:296-301` | W2-02 adjusted |
| M34 | `kcc mcp stdio` has no signal handling, so a signal skips the bracket wait, job drain and audit flush | F-05 | `crates/kcc/src/server.rs:234-235`, `rmcp-server-kit-3.21.1/src/transport.rs:5916-5937` | F-05 confirmed |
| M35 | DHCP: `parse_pools` attaches later indented lines to the last pool; pool planning keeps only the first DNS server, cannot clear DNS, defaults the gateway and lets a "new" pool overwrite an existing one | C-08, C-09, W3-04, F-11 | `crates/kcc-domain/src/dhcp/model.rs:175-187`, `crates/kcc-domain/src/dhcp.rs:107-112` | C-08 confirmed; C-09 adjusted; W3-04 confirmed; F-11 adjusted |
| M36 | Firewall planner/reader bugs: FQDN group description always refused, ports rendered for ICMP/ESP/GRE/IP rules, one unparsable rule fails every CLI/MCP firewall write after the write | D-03, D-05, D-06 | `crates/kcc-domain/src/dns/change.rs:172-175`, `kcc-catalog/src/validate.rs:225-230` | D-03 confirmed; D-05 confirmed; D-06 confirmed |
| M37 | Clearing a connection-policy description always fails | D-04 | `crates/kcc-domain/src/policies/change/plan.rs:36`, `crates/kcc-domain/src/policies/change/render.rs:46-49` | D-04 confirmed |
| M38 | Route removal verified by routing-table row count; the route-wipe recovery is lossy | D-08 | `crates/kcc-domain/src/routing/change.rs:83-104`, `change/ipv6.rs:95-118` | D-08 confirmed |
| M39 | Segment create does not roll back the step that failed | D-09 | `crates/kcc-domain/src/segments.rs:206-224`, `segments/step.rs:255-265` | D-09 confirmed |
| M40 | VPN-client Delete removes any interface and drops the catalog's Destructive risk | D-11 | `vpn_clients/render.rs:21-25`, `vpn_clients/change.rs:96-101` | D-11 confirmed |
| M41 | VPN server status reads the crypto-map virtual IP at the wrong JSON pointer | D-12 | `crates/kcc-domain/src/vpn_servers.rs:208,222-225`, `vpn_servers/verification.rs:37-41` | D-12 confirmed |
| M42 | WireGuard ASC: the doc says extra values are ignored, but the line keeps them | D-17 | `vpn_clients.rs:227-228`, `vpn_clients/render.rs:62-66` | D-17 confirmed |
| M43 | Migration verification always fails without WAN Internet or `Bridge0`; the management interface is guessed as the first bridge | G-06 | `crates/kcc-migrate/src/apply/verify.rs:152-174`, `inventory.rs:245-248` | G-06 confirmed |
| M44 | Failed router reads are swallowed into defaults that drive later Web changes | W3-05 | `crates/kcc-web/src/net_interface_edits.rs:162-166`, `net_internet_address.rs:141-149` | W3-05 adjusted |
| M45 | MCP result truncation replaces the whole payload, including error codes and fail-safe messages | E-04 | `crates/kcc-mcp/src/support/shape.rs:191-203`, `kcc-app/src/settings.rs:202` | E-04 confirmed |
| M46 | Every MCP interface write failure becomes `conflict`, losing `verification_failed` and its field | E-07 | `crates/kcc-mcp/src/domains/write/interfaces.rs:143-150` | E-07 confirmed |
| M47 | Log sinks: transport errors are not retried, there is no HTTP timeout, retries are unbounded and shutdown drops queued records uncounted (docs promise at-least-once) | G-08, G-09 | `crates/kcc-telemetry/src/logs/sink.rs:290-305`, `pipeline_delivery.rs:216-219` | G-08 confirmed; G-09 confirmed |
| M48 | One malformed router log record silently blocks all forwarding for that router | G-10 | `crates/kcc-telemetry/src/logs/service.rs:285-287`, `parser.rs:42-48` | G-10 confirmed |
| M49 | Router-local log timestamps are stamped as UTC | G-11 | `service.rs:280-284`, `parser.rs:130` | G-11 confirmed |
| M50 | Log batch selection re-encodes the whole batch per record while holding a std `Mutex` | G-13 | `pipeline_delivery.rs:157-162` | G-13 confirmed |
| M51 | A failed sign-in shows nothing in the browser (htmx never swaps the 401) | W1-04 | `crates/kcc-web/src/auth.rs:379-388`, `templates/pages/login.html` | W1-04 confirmed |
| M52 | Router connection test ignores the selected sign-in mode and never uses a typed token | W1-06 | `crates/kcc-web/src/router_check.rs:57-58,74-82`, `router_form.rs:251-257` | W1-06 adjusted |
| M53 | `kcc backup diff` compares sets of redacted lines, so it misses real changes | F-07 | `crates/kcc/src/cli/persist.rs:176-186`, `args_fleet.rs:139` | F-07 adjusted |
| M54 | User-visible English strings outside `kcc-i18n` (project rule (f)) | F-10 | `crates/kcc/src/cli/persist.rs:96,237` (and others) | F-10 confirmed |
| M55 | CI and container workflows trigger on `main`; the only branch is `master` | X-01 | `.github/workflows/ci.yml:3-8`, `.github/workflows/container.yml:3-8` | X-01 adjusted high→medium |
| M56 | `deploy/podman/e2e.sh` step functions ignore `set -e`, so failures in the middle of a step pass | X-03 | `deploy/podman/e2e.sh:74-77`, `e2e.sh:327-332` | X-03 confirmed |
| M57 | Secret-leak tests cannot fail: every test secret contains `"`/`\`, which quoting escapes before the comparison | T-01 | `crates/kcc-app/tests/secrets_write.rs:72`, `crates/kcc-domain/tests/users.rs:77` | T-01 confirmed |
| M58 | `live_presets` and `live_mcp` cannot reach a real router; their twins hide it with `allow_loopback` | T-02 | `crates/kcc/tests/live_presets.rs:186-190`, `crates/kcc-mcp/tests/live_mcp/session.rs:218-220` | T-02 confirmed |
| M59 | Radio mappings never rewrite access-point tokens (`WifiMaster0/AccessPoint0`) | H4a (G critic NEW-1) | `crates/kcc-migrate/src/rules.rs:682-690` | 2nd critic confirmed medium |

## Low

| Id | Sev | Finding | Where | Validation |
|---|---|---|---|---|
| SEC1-08 | low | The audit log page and export ignore the viewer's router scope | `crates/kcc-web/src/authz.rs:252`, `admin_audit.rs:110-116` | adjusted (medium→low) |
| SEC1-10 | low | HTML is passed around as plain `String` and rendered with `\|safe`, against "askama auto-escaping only, no bypass" | `crates/kcc-web/templates/partials/kit_result.html:4,10,13`, `crates/kcc-web/src/page_kit/respond.rs:122-126` | adjusted (medium→low) |
| SEC1-11 | low | Login timing reveals disabled or locked accounts; all logins are serialised on the users file | `crates/kcc-app/src/accounts.rs:386-401` | confirmed |
| SEC1-12 | low | A self-service password change keeps the current session id | `crates/kcc-web/src/auth.rs:306-313` | confirmed |
| SEC1-13 | low | `app.js` carries review-process labels and three copies of the same swap override | `crates/kcc-web/assets/js/app.js:322,364,388,412,427,443` | confirmed |
| SEC2-06 | low | `OutboundPolicy::default()` is permissive, and public migration entry points connect with it plus loopback | `crates/kcc-rci/src/outbound.rs:96-123`, `engine.rs:80-95` | adjusted (medium→low) |
| SEC2-07 | low | Redaction registry blanks the IKE key name instead of the PSK, and misses ipsec-profile secrets | `crates/kcc-config/src/secrets.rs:76-90`, `kcc-app/tests/cli_templates.rs:24,71` | adjusted (medium→low) |
| SEC2-09 | low | `RouterRegistry::client` holds the fleet-wide client mutex across DNS resolution and blocking file I/O | `crates/kcc-app/src/registry.rs:626-637`, `outbound.rs:195-205` | adjusted |
| SEC2-10 | low | IPv6-literal router URLs always fail the outbound policy | `crates/kcc-rci/src/outbound.rs:192-201` | confirmed |
| SEC2-12 | low | Every login attempt, including unknown users, rewrites and fsyncs `users.json` under its exclusive lock; disabled and locked accounts answer fast | `crates/kcc-app/src/accounts.rs:386-400`, `persist.rs:221-222` | adjusted |
| SEC2-13 | low | Preset records bypass the state store's private atomic writer | `crates/kcc-migrate/src/presets/store.rs:239,259-261` | adjusted |
| SEC2-14 | low | Log-sink clients have no timeouts, and the Elasticsearch reply body is unbounded | `crates/kcc-telemetry/src/logs/elastic_sink.rs:76`, `sink.rs:76` | confirmed |
| SEC2-15 | low | `CredentialStore` path methods build paths from an unvalidated router id, and their docs say otherwise | `crates/kcc-app/src/credentials.rs:316-327` | confirmed |
| SEC2-16 | low | Gaps in zeroizing decrypted and downloaded secrets | `crates/kcc-app/src/secrets.rs:277-285`, `kcc-config/src/ns3.rs:43-49,67-69` | confirmed |
| SEC2-17 | low | Two write and delete helpers follow symlinks with predictable temp names | `crates/kcc/src/cli/files.rs:32-39`, `cli/migrate.rs:53,105` | confirmed |
| A-05 | low | Status items that do not fully deserialize are dropped, so error-level replies count as success | - | adjusted (medium→low) |
| A-06 | low | Tab-indented config text quietly flattens nested commands to the top level | `crates/kcc-config/src/config_text.rs:145-163` | adjusted (medium→low) |
| A-07 | low | Every background operation logs in afresh and never logs out | `crates/kcc-rci/src/session.rs:502` | adjusted (medium→low) |
| A-08 | low | DELETE risk is not enforced by the catalog; three frontends patch it themselves | `crates/kcc-catalog/src/request.rs:48-59`, `crates/kcc-catalog/src/runtime.rs:457-468` | adjusted (medium→low) |
| A-09 | low | Digest proxy state is not safe under concurrent requests | `crates/kcc-rci/src/auth_digest.rs:79-104` | adjusted (medium→low) |
| A-10 | low | Secret bytes are copied into buffers that are never zeroized | `crates/kcc-rci/src/engine.rs:698-710`, `crates/kcc-rci/src/session.rs:622` | adjusted |
| A-11 | low | Unbounded edit-distance work on attacker-controlled field names | - | confirmed |
| A-12 | low | `connect_bootstrap_with` loses the observer, and request accounting differs per method | `crates/kcc-rci/src/engine.rs:189-194` | adjusted |
| A-13 | low | `OutboundPolicy::default()` is permissive, contrary to the documented "empty by default" | `crates/kcc-rci/src/outbound.rs:96-123`, `engine.rs:259-261` | adjusted |
| A-14 | low | Router-controlled Argon2 iterations are not capped locally | `crates/kcc-rci/src/ndw4_reply.rs:110-120`, `crates/kcc-rci/src/ndw4_keys.rs:18` | confirmed |
| A-15 | low | Timeout errors are mapped differently on each auth path | `crates/kcc-rci/src/auth_token.rs:24`, `auth_digest.rs:87,105` | adjusted |
| A-16 | low | Duplicated magic numbers and helpers | `auth_options.rs:47`, `session.rs:315` | confirmed |
| A-17 | low | Dead or speculative API shipped in production | `engine.rs:72-73`, `session.rs:194-223` | adjusted |
| A-18 | low | Cancel-safety comments contradict each other | `engine.rs:238-240`, `session.rs:345-346` | confirmed |
| A-20 | low | Generated argument types fall back to an unconstrained `String` | `crates/kcc-catalog/src/runtime/data.rs:267-277` | adjusted |
| A-21 | low | Tests that cannot fail, duplicated scenarios, and source-grep tests | `crates/kcc-config/tests/config_text.rs:25-29`, `ns3.rs` | adjusted |
| B-07 | low | Blocking file I/O and blocking `flock` waits run directly on Tokio workers | `crates/kcc-app/src/workflow.rs:1370-1374`, `backups/store.rs:85,101` | adjusted (medium→low) |
| B-08 | low | `CliCommand` does not tie the line it sends to the request it validated | `crates/kcc-app/src/workflow_cli/command.rs:42-48`, `workflow_replay.rs:77-82` | adjusted (medium→low) |
| B-09 | low | Every job leaves two lock files in the state root forever | `crates/kcc-app/src/jobs.rs:601`, `jobs/job_ownership.rs:89-91` | adjusted (medium→low) |
| B-10 | low | A failed final write of a job record is dropped silently, and the next start reports a false interruption | `crates/kcc-app/src/jobs.rs:476` | confirmed |
| B-11 | low | Module-wide `#![expect]` blankets with "the plan mandates" reasons hide wildcard arms | `crates/kcc-app/src/workflow.rs:2-13`, `registry.rs:2-16` | confirmed |
| B-12 | low | `WorkflowError::InvalidResponse` reports "invalid last-change response" for unrelated failures | `workflow.rs:510-511`, `workflow_verify.rs:158,165-166` | confirmed |
| B-13 | low | Router-profile and router-id validation is duplicated and has drifted | `settings.rs:958-1006`, `registry.rs:108-134` | adjusted |
| B-14 | low | Audit module: duplicated helpers, dead state and unused public API | `audit.rs:692-704`, `audit.rs:890-904` | confirmed |
| B-17 | low | Poller idle-exit race can hand out a receiver that never gets data | `poller.rs:318-323` | confirmed |
| B-20 | low | Workflow audit entries use timestamps as request ids, and terminal changes drop their audit receipt | `workflow.rs:1022`, `workflow.rs:438-444` | adjusted |
| B-21 | low | One malformed backup file turns off retention for that router permanently | `backups/store.rs:221`, `tests/backups.rs:201-233` | confirmed |
| B-23 | low | Several tests cannot fail, describe the wrong failure, or wait in real time | `jobs.rs:822-834`, `tests/jobs_recovery.rs:242` | confirmed |
| B-24 | low | A route transition on a `kcc.toml` router keeps the new URL only in memory but rewrites the operator's password file | `registry.rs:358-365`, `registry/stored.rs:54-65` | confirmed |
| C-07 | low | Validated requests are overwritten after validation, bypassing the catalog check | `crates/kcc-domain/src/keendns.rs:168-169`, `keendns.rs:184-185` | adjusted (medium→low) |
| C-10 | low | Partition check and format can never work, yet ship in Web, MCP and CLI | `crates/kcc-domain/src/storage.rs:186-199`, `verification.rs:28-31` | adjusted (medium→low) |
| C-12 | low | Changing the listener kcc itself uses always rolls back the router | `crates/kcc-domain/src/services.rs:198-205`, `kcc-app/src/workflow.rs:1138-1141` | adjusted (medium→low) |
| C-13 | low | Local planning errors are reported as "invalid router response" | `crates/kcc-domain/src/configuration.rs:249-250,271-272,290-291`, `system.rs:205-206` | adjusted (medium→low) |
| C-14 | low | Module- and crate-wide `#[expect]`s hide real defects | `crates/kcc-domain/src/lib.rs:2-5`, `system.rs:2-8` | adjusted (medium→low) |
| C-15 | low | `close(Save)` in router mode sends a second save after the commit and can misreport the result | `crates/kcc-domain/src/configuration/close.rs:82-83`, `workflow.rs:1180-1188` | confirmed |
| C-17 | low | The same helpers are copied across planners | `interfaces.rs:262`, `wan.rs:177` | confirmed |
| C-18 | low | Production code that only tests use, or that does nothing | `crates/kcc-domain/src/interfaces/guard.rs:33-43`, `configuration.rs:383` | confirmed |
| C-19 | low | Diagnostics poll the router every 10 ms | `crates/kcc-domain/src/diagnostics.rs:212`, `kcc-rci/src/engine/background.rs:100-106,129` | confirmed |
| C-21 | low | The bracket reports refusals with the wrong error and drops an audit failure | `crates/kcc-domain/src/configuration/bracket.rs:109-110` | confirmed |
| C-22 | low | Read-back of secret writes passes when an old secret is already there | `router_users.rs:161-169`, `wifi/plan.rs:72-79` | confirmed |
| C-23 | low | Client and DHCP read-back runs after the audit entry says "success" | `clients.rs:226-227`, `dhcp.rs:170-193` | adjusted |
| C-24 | low | `plan_tag` does not protect the login kcc uses | `router_users.rs:128-133` | confirmed |
| C-25 | low | Tests that cannot fail or miss the behavior they name | `tests/system.rs:117-131`, `tests/components.rs:65-73` | confirmed |
| D-07 | low | Read-back cannot detect a no-op when the target already exists | `firewall/change/verify.rs:98-100,129-133`, `vpn_clients/import.rs:172-176` | adjusted (medium→low) |
| D-10 | low | `RuleProperty::Order` can never be planned, and the Web builds its own order line | `firewall/change.rs:107`, `crates/kcc-web/src/firewall_page/lines.rs:80-82` | adjusted (medium→low) |
| D-13 | low | Hand-written config-text walkers, duplicated and already drifted | `vpn_clients/secrets.rs:141-161`, `vpn_servers/secrets.rs:58-87` | adjusted (medium→low) |
| D-14 | low | `RevealSecrets` gate is shipped with no production caller, and its scope check is not tied to the router | `crates/kcc-domain/src/vpn_servers/secrets.rs:38-41`, `lib.rs:61-66` | adjusted (medium→low) |
| D-15 | low | Validated requests are changed after validation | `vpn_clients/change.rs:95`, `vpn_servers.rs:246` | adjusted (medium→low) |
| D-18 | low | Verification and validation failures turned into `InvalidResponse` | `policies/change/apply.rs:55-57`, `nat/change.rs:306-308` | adjusted |
| D-19 | low | The same planner helpers are copied across seven modules | `firewall/change.rs:267-272`, `policies/change/plan.rs:117-122` | adjusted |
| D-20 | low | One stray `kcc-segment:` description breaks segment discovery | `crates/kcc-domain/src/segments/discovery.rs:194-211` | confirmed |
| D-21 | low | Planners signal invalid input through sentinels and string dispatch | `vpn_servers/render.rs:107` | confirmed |
| D-23 | low | Tests that duplicate, cannot fail, or cost a lot for little | `tests/firewall.rs:153-174`, `tests/firewall_binding.rs:197-218` | adjusted |
| E-06 | low | The global migrations mutex is held across router commit and rollback | `crates/kcc-mcp/src/migration_tools/finish.rs:66,83-94,103` | adjusted (medium→low) |
| E-09 | low | Logged failure causes cannot be tied to the `request_id` returned to the client | `crates/kcc-mcp/src/support/shape.rs:61-65`, `support/errors.rs:49,70` | adjusted (medium→low) |
| E-10 | low | Crate-root `#![expect]` blankets 8 clippy lints plus private-item docs | `crates/kcc-mcp/src/lib.rs:6-16` | adjusted (medium→low) |
| E-11 | low | About 70 async fns have no cancel-safety annotation, including mutating handlers | `domains/write/wifi.rs:114`, `clients.rs:210,224` | adjusted (medium→low) |
| E-12 | low | The `fields` projection argument is accepted and validated but never applied | `crates/kcc-mcp/src/support/shape.rs:174-183`, `generic/fleet.rs:39-41,58-60` | confirmed |
| E-13 | low | The pseudonymizer over-matches on the substring "ip", and its map grows without bound | `crates/kcc-mcp/src/support/shape.rs:258-264,274-276`, `lib.rs:244` | confirmed |
| E-14 | low | Tool metadata and helper logic are duplicated and can drift | `generic/router.rs:247-255`, `registry/definitions.rs:137-141` | confirmed |
| E-15 | low | Stringly-typed dispatch with wildcard fallbacks binds unknown names to real handlers | `crates/kcc-mcp/src/config_tools/routes.rs:62,91-97`, `migration_tools/routes.rs:84` | confirmed |
| E-16 | low | Debug formatting is used as a wire value, and a test pins it | `crates/kcc-mcp/src/handler.rs:148`, `support/errors.rs:135` | confirmed |
| E-17 | low | Recovery mapping decides meaning by comparing an i18n message key | `crates/kcc-mcp/src/support/errors.rs:22` | confirmed |
| E-18 | low | Input schemas call `confirm` "unused", but it is required for some writes | `crates/kcc-mcp/src/domains/write/filtering.rs:96-98`, `common.rs:117` | confirmed |
| E-19 | low | `resources/read` maps router failures to `internal`, skips the audit, and starts pollers for unregistered names | `crates/kcc-mcp/src/handler.rs:105-118` | adjusted |
| E-20 | low | `catalog_search` with `limit: 0` returns a `next_cursor` equal to the current cursor | `crates/kcc-mcp/src/generic/fleet.rs:144,155` | confirmed |
| E-23 | low | Test quality: tautologies, tests that pin known-broken behavior, and review labels | `crates/kcc-mcp/src/tests/random.rs:37-61`, `src/tests/gates.rs:196` | adjusted |
| E-24 | low | Some write paths drop the audit receipt, so `audit_pending` is never reported | `crates/kcc-mcp/src/domains/write/vpn.rs:182-192`, `vpn_servers.rs:119-134` | adjusted |
| F-06 | low | CLI `apikey create` and `user add` skip the role-dominance check the Web enforces | `crates/kcc/src/cli/api_keys.rs:31-33`, `accounts.rs:42-48` | adjusted (medium→low) |
| F-08 | low | The redaction pipeline exists three times | `crates/kcc/src/cli/redact.rs:47-63`, `kcc-web/src/config_page/text.rs:63-83` | adjusted (medium→low) |
| F-09 | low | Two composition roots, and some CLI commands build them twice | `crates/kcc/src/cli/persist.rs:144`, `accounts.rs:33` | adjusted (medium→low) |
| F-12 | low | Inconsistent confirmation gates for the same action | `migrate_apply.rs:49`, `preset/run.rs:75` | adjusted (medium→low) |
| F-13 | low | Permission refusals on local-state commands are not audited | `persist.rs:276-277`, `persist.rs:150,175,199,266` | adjusted (medium→low) |
| F-14 | low | Two parsers for `--from`, and preset sources copy the startup configuration into a plain `Vec<u8>` | `preset/source.rs:120-130`, `migrate_plan.rs:127-163` | adjusted (medium→low) |
| F-15 | low | Rollback results report `"unsaved": true` | `persist.rs:130`, `migrate.rs:185` | confirmed |
| F-17 | low | Credential misbinding through the single `KCC_PASSWORD` fallback | `router_secrets.rs:56-59`, `secret.rs:33-35` | confirmed |
| F-18 | low | `ServerError` is a stringly-typed error, and one constructor is dead with a false doc | `server.rs:66`, `server.rs:643-645` | adjusted |
| F-22 | low | `write_private` reuses a predictable temporary file and follows symlinks | `files.rs:32-39` | confirmed |
| F-23 | low | Startup and shutdown edges in `run_serve` | `server.rs:544-558`, `server.rs:211-214` | confirmed |
| F-25 | low | Unix-time helper copied five times; audit request ids are not unique | `context.rs:426,447`, `server_migrations.rs:25-27` | confirmed |
| F-27 | low | `--json` contract is broken for argument errors | `main.rs:20-25` | confirmed |
| F-29 | low | Test quality: a vacuous assertion, prose pins and a review label | `tests/cli_domain_writes/admin.rs:15`, `tests/cli/outbound.rs:62` | adjusted |
| F-30 | low | Test quality: port race, copied helpers, time windows, source greps | `serve.rs:242-247`, `serve_origin.rs:211` | confirmed |
| G-12 | low | Log-collector shutdown waits out uncancellable sleeps, one router after another | `service.rs:201`, `runtime.rs:114-116` | adjusted (medium→low) |
| G-14 | low | Shipped but unused public APIs bypass the configured outbound policy and allow loopback | `crates/kcc-migrate/src/source.rs:130-134`, `inventory.rs:57-60` | adjusted (medium→low) |
| G-15 | low | Migration reports contain no command text at all, and the HTML/Markdown skeleton is English-only | `planner/types.rs:146-151`, `report.rs:176-178` | confirmed |
| G-16 | low | `kcc_metrics_series_dropped_total` grows per scrape, not per event | `metrics/collector.rs:106-108`, `catalogue.rs:357` | confirmed |
| G-17 | low | The per-client pseudonym map grows without bound and is shared across routers | `metrics/clients.rs:180-185`, `collector.rs:44-45` | adjusted |
| G-18 | low | `keenetic_interface_up` carries the free-text interface description as a label | `metrics/interfaces.rs:35-43` | confirmed |
| G-19 | low | The `kcc_jobs` gauge drifts on broadcast lag | `metrics/instrumentation.rs:197` | confirmed |
| G-20 | low | Wrong or missing cancel-safety annotations | `apply/finish.rs:134`, `apply/verify.rs:95` | adjusted |
| G-21 | low | Copy-paste duplication that has already drifted | `rules.rs:693-711`, `presets/plan/classify.rs:145-150` | confirmed |
| G-22 | low | `PresetStore` duplicates a method and does blocking file and crypto I/O on async handlers | `presets/store.rs:194-199`, `kcc-mcp/src/preset_tools/capture.rs:190-193` | confirmed |
| G-23 | low | The `ContinueOnNonCritical` retry path is test-only, and its Indeterminate case is not recovered | `tests/support/apply_policy.rs`, `apply_secrets.rs` | confirmed |
| G-25 | low | Test quality: real bugs above have no tests, and some test code is noise | `tests/logs.rs:58-88`, `tests/rules.rs:448-455` | confirmed |
| W1-03 | low | Unauthenticated `GET /ui/login` grows the session map without bound | `crates/kcc-web/src/auth.rs:141-156`, `session.rs:456-462` | adjusted (medium→low) |
| W1-07 | low | The "account kcc signs in with" guard fails open and ignores the read-only login | `crates/kcc-web/src/secret_pages/user_password.rs:103-109`, `vpn_server.rs:227-233` | adjusted (medium→low) |
| W1-08 | low | Each audit-page view and export verifies and loads the whole log | `crates/kcc-web/src/admin_audit.rs:234-254`, `admin_audit.rs:343` | adjusted (medium→low) |
| W1-09 | low | Copy-pasted helpers in the admin and auth modules, and the bare 500s don't match the docs | `auth.rs:567-570`, `admin_users.rs:781-787` | confirmed |
| W1-10 | low | Review-process labels shipped in production JavaScript | `crates/kcc-web/assets/js/app.js:322,364,388,412,427,443` | confirmed |
| W1-13 | low | Localization slips: sign-in error language, "UTC", "(you)" | `auth.rs:377-384`, `admin_shared.rs:412` | confirmed |
| W1-14 | low | Kit routes lose `Cache-Control`, with no deviation recorded | `crates/kcc-web/src/csp.rs:41-45` | adjusted |
| W1-16 | low | A new API key is lost if the page refresh or render fails after creation | `crates/kcc-web/src/admin_keys.rs:220-249` | confirmed |
| W1-17 | low | Deleting a role counts holders without the users/API-key locks | `crates/kcc-web/src/admin_roles.rs:631-637,648-650` | confirmed |
| W1-18 | low | The cross-site CSRF test sets two rejecting conditions at once | `crates/kcc-web/tests/auth.rs:251-262` | adjusted |
| W2-03 | low | A wizard commit or rollback that succeeded on the router is not audited if the record save fails | `wizard/finish.rs:243-251`, `finish.rs:275-280` | adjusted (medium→low) |
| W2-05 | low | `Plan::at` drops the management bracket when the effective risk is Destructive | `page_kit/change.rs:308-331`, `change.rs:341-370` | confirmed |
| W2-06 | low | The config page's backup "copy" logic is built on a false premise | `config_page/store.rs:122-124`, `kcc-app/src/backups/store.rs:86-108` | confirmed |
| W2-07 | low | Read-only page views do far more work than needed | `config_page/store.rs:233-241`, `backups.rs:110-114` | adjusted |
| W2-08 | low | The wizard store does blocking file I/O, including fsync, in async handlers | `wizard/store.rs:648-652`, `visit.rs:59` | confirmed |
| W2-09 | low | Save does not re-check the "not while the timer is armed" rule the page shows | `partials/config_status.html:19`, `config_page/safety.rs:66-80` | adjusted |
| W2-10 | low | Wizard refusals and failures are not audited the way the kit audits them | `wizard/visit.rs:64-69`, `running.rs:511-513` | confirmed |
| W2-11 | low | Store errors are swallowed or downgraded | `config_page/create.rs:98-104`, `restore.rs:105-108` | adjusted |
| W2-12 | low | The typed-router-name confirmation is implemented three times | `confirm/stakes.rs:88-99`, `confirm/prompt.rs:74-89` | adjusted |
| W2-14 | low | The finish-recovery "budget" tests barely assert anything, and the two suites are copies | `tests/wizard_finish_recovery.rs:265-274`, `tests/preset_finish_recovery.rs:244-253` | confirmed |
| W2-15 | low | Pre-rendered HTML passes through `\|safe` as plain `String` | `partials/kit_result.html:4,10,13`, `respond.rs:115-127` | confirmed |
| W2-18 | low | Dead template calls and an unused Batch path in the kit | `partials/system_general_facts.html:9`, `system_general/fields.rs:57-64` | confirmed |
| W3-06 | low | Three hand-written DomainError→WorkflowError mappings that already disagree | `routing_page/frame.rs:227-236`, `net_mesh.rs:242-252` | adjusted (medium→low) |
| W3-07 | low | Tests of management changes send the confirmation up front, so a missing prompt cannot fail them | `tests/network_pages/wifi.rs:106-112`, `tests/clients_pages/segments.rs:121-122` | confirmed |
| W3-08 | low | Firewall rule reorder builds its CLI line in the web layer, with a validated leaf that doesn't match the line | `firewall_page/lines.rs:80-83`, `lines.rs:65` | confirmed |
| W3-09 | low | Permission re-checked inside page code and refusals matched on the audit string "forbidden" | `clients_pages/segment_create.rs:79-82`, `page_kit/action.rs:259-266` | adjusted |
| W3-10 | low | `Arc<Mutex<Option<String>>>` side channel copied three times to pass a note out of the work closure | `clients_pages/segment_create.rs:42`, `segment_delete.rs:153-157` | confirmed |
| W3-11 | low | Same small helpers and constants duplicated across page families | `firewall_page/checks.rs:29-37`, `nat_page/forward_forms.rs:187-195` | adjusted |
| W3-13 | low | Static route read-back compares typed text with the router's stored text | `routing_page/route_form.rs:36-57`, `route_add.rs:160` | confirmed |
| W3-14 | low | Access-point rows round-trip through serde and read password presence from raw interface data | `net_wifi_rows.rs:226-233`, `kcc-domain/src/interfaces/models.rs:9-37` | adjusted |
| W3-15 | low | Misleading or dead bits | `net_pages.rs:8-9`, `clients_pages/dhcp.rs:173` | adjusted |
| W3-16 | low | Ambiguous test label hides a missing case | `tests/network_pages/internet.rs:238-249` | adjusted |
| W4-02 | low | Any reader of a router can stop or follow other users' jobs, and job ids are predictable | `advanced/jobs.rs:214-219`, `advanced/jobs.rs:187-196` | adjusted (medium→low) |
| W4-05 | low | Existence guards swallow read errors (one path lets "Add account" overwrite an existing account) | `user_forms.rs:201-206`, `component_queue.rs:94-97` | confirmed |
| W4-06 | low | Comments say management changes need `Destructive`; the code does not require it | `service_toggle.rs:3-5`, `services.rs:5-7` | confirmed |
| W4-07 | low | Global caps evict other sessions' downloads and running jobs' answers | `advanced.rs:51-55`, `advanced.rs:129-134` | confirmed |
| W4-08 | low | The explorer offers Execute for background changes that it always refuses | `detail.rs:150,172-176`, `request.rs:63-68` | confirmed |
| W4-09 | low | Raw-form secrets are held in plain `String`s with derived `Debug` | `rci_check.rs:24-34`, `cli.rs:50-54` | confirmed |
| W4-11 | low | Releasing a KeenDNS name has no confirmation and no management bracket | `keendns_forms.rs:215-237`, `kcc-domain/src/keendns.rs:134-141` | confirmed |
| W4-13 | low | Each log-page stream polls the router itself | `log_source.rs:25-26`, `log_source.rs:67-71` | confirmed |
| W5-03 | low | Migrations keep the whole sealed source config and the typed passwords forever | `migrate_wizard/finish.rs:21-64`, `wizard/finishing.rs:86-87` | adjusted (medium→low) |
| W5-04 | low | Changing source or target clears the password list but keeps `passwords.sealed`; old passwords are reused silently | `migrate_wizard/record.rs:266-276`, `target.rs:231-232` | adjusted (medium→low) |
| W5-05 | low | Wizard file I/O, including fsync, runs on the async workers | `wizard/store.rs:324-328`, `migrate_wizard/inputs_submit.rs:85-96` | adjusted (medium→low) |
| W5-06 | low | Any Migrate user can create unlimited run directories, and every landing page reads them all | `migrate_wizard/landing.rs:174-238`, `presets_page/landing.rs:190-212` | adjusted (medium→low) |
| W5-07 | low | The two wizards still duplicate apply, launch, target, inputs and download code after the engine split | `migrate_wizard/apply.rs:46-100`, `presets_page/apply.rs:49-112` | adjusted (medium→low) |
| W5-08 | low | Cross-crate reason keys and display text are matched as strings, and unknown keys fall into wildcard arms | `migrate_wizard/reasons.rs:136-161`, `warnings.rs:26,219-229` | confirmed |
| W5-09 | low | About 18 handlers and helpers have no cancel-safety comment | `migrate_wizard/apply.rs:46`, `downloads.rs:39` | confirmed |
| W5-10 | low | Errors are swallowed or recorded as the wrong outcome | `presets_page/reveal.rs:99-105`, `migrate_wizard/preview.rs:393` | adjusted |
| W5-11 | low | A user-controlled form size makes review submit quadratic on the async worker | `migrate_wizard/review_submit.rs:138-144`, `page_kit/request.rs:69-75` | confirmed |
| W5-12 | low | Up to 64 sessions are shared by all users; eviction drops a session another request is still using | `wizard/service.rs:73-79`, `visit.rs:128` | confirmed |
| W5-13 | low | The copied preset is held in a plain `Vec<String>` that is never zeroized | `presets_page/saved.rs:41-50,58-62,85-87` | adjusted |
| W5-16 | low | Migration passwords are mapped by row index; the hidden user-name field is ignored | `templates/partials/migrate_inputs.html`, `inputs_submit.rs:147-148` | confirmed |
| W5-17 | low | Test gaps: the cross-user check covers only GET, and tests assert on markup fragments | `tests/migration_wizard/plan_steps.rs:197-200`, `tests/migration_wizard/records.rs:106-111` | confirmed |
| X-02 | low | The `gates` job cannot run `lint-completeness` as configured, and when it fails the other gates in that job are skipped | `xtask/src/cargo_lints.rs:41-47`, `xtask/src/lint_completeness.rs:56` | adjusted (medium→low) |
| X-04 | low | Releases and published images skip every G1 gate | `.github/workflows/release.yml:59-61`, `container.yml:105-108` | adjusted (medium→low) |
| X-06 | low | The cargo-vet gate is nominal, and the documented bump procedure keeps it that way | `supply-chain/audits.toml:1-4`, `supply-chain/config.toml:703-713` | confirmed |
| X-09 | low | Image publishing: prerelease tags overwrite `:latest`, and the version label is always 0.1.0 | `container.yml:131-132`, `release.yml:173-176` | confirmed |
| X-10 | low | `web-smoke.sh` puts the admin Web password on a command line | `scripts/live/web-smoke.sh:157-161` | confirmed |
| X-12 | low | `ci-local.sh` has drifted from `ci.yml` | `scripts/ci-local.sh:51-58`, `ci.yml:191` | confirmed |
| T-03 | low | Fake router request log keeps only the last parse line of a batch and can misattribute lines under concurrency | `crates/kcc-testkit/src/server.rs:439-453`, `server.rs:974-976` | adjusted (medium→low) |
| T-04 | low | The fake hashes or encodes plaintext secrets itself, so "kcc hashes / never stores plaintext" tests check the fake; the conversion is undocumented | `crates/kcc-testkit/src/cli_engine/secrets.rs:84-104`, `kcc-domain/src/router_users.rs:217` | adjusted (medium→low) |
| T-05 | low | Live migration reads a live source router without the serial allowlist | `crates/kcc/tests/live_migration/rehearsal.rs:260-273`, `live_migration.rs:119-127` | adjusted (medium→low) |
| T-06 | low | `live_mcp_smoke` skips silently: no tracing subscriber, so `live-skip:` is never printed | `crates/kcc-mcp/tests/live_mcp.rs:79-89`, `live_mcp/session.rs` | confirmed |
| T-07 | low | Ports reserved by bind-0-then-drop are reused by child processes | `crates/kcc/tests/serve_bracket/process.rs:91`, `metrics_serve.rs:99-102` | confirmed |
| T-08 | low | Read-only live suites contact routers without a `test_device = true` profile | `crates/kcc/tests/live_smoke.rs:87-93`, `live_domains/gate.rs:59-62` | confirmed |
| T-09 | low | Live migration probe writes after the safety net and records results instead of asserting them | `crates/kcc/tests/live_migration/rehearsal.rs:126-134`, `live_migration/probe.rs:74-94` | adjusted |
| T-11 | low | Source-grep tests stand in for behaviour tests | `crates/kcc/tests/source_guards.rs:37-40` | adjusted |
| N1 | low | The "stale read" conflict check never runs in production: every caller of `ChangeWorkflow::begin*` passes `last_read = None` (docs describe the check) | - | adjusted (narrowed) |
| N2 | low | `ChangeSet::apply_cli` returns before `audit_cli` when a later line of a batch fails, so the partly applied batch has no `router.change_cli` workflow entry | - | adjusted |
| N3 | low | CLI `label()` (`crates/kcc/src/cli/dom_core.rs:231-233`) puts a router-reported client name unsanitized into `known host {name} {mac}`; the Web sanitizes it | - | adjusted |
| N4 | low | Web login answers "locked" distinctly; only existing accounts can be locked, so repeated bad passwords enumerate usernames and can lock out an admin | - | adjusted (info→low) |
| N5 | low | `parse_set_cookie` (`crates/kcc-rci/src/session.rs:771-772`) fails the whole response on any unrelated non-ASCII `Set-Cookie`, including POSTs the router applied | - | confirmed |
| N7 | low | Firewall `list_risk` matches bindings by the exact `acl` string; an MCP `acl` with spaces is classified Write and skips the bracket | - | adjusted |
| N8 | low | WireGuard parser `UnknownField.field` can carry key text and is printed by Display (`vpn_clients/wireguard/parser.rs:173-176,194-197`) | - | confirmed |
| N11 | low | Wi-Fi schedule edit and access-point toggle submit management-classified changes without the confirmation dialog | - | adjusted (broadened) |
| N12 | low | `crates/kcc-web/tests/network_pages/wifi.rs:106-112` sends the confirmation up front, so a missing prompt cannot fail the test | - | confirmed |
| N16 | low | Saved-preset runs abandoned before the last step keep `passwords.sealed` forever (`presets_page/saved.rs:129-141` sweeps only `Origin::Copy`) | - | confirmed |
| N17 | low | CLI `router edit` seals new secrets before the registry update and never restores them (`crates/kcc/src/cli/router_secrets.rs:120-122`); same family as M04 | - | confirmed |

## Info

| Id | Sev | Finding | Where | Validation |
|---|---|---|---|---|
| SEC1-14 | info | Route-table scope checks use the raw path, handlers use the decoded one | `crates/kcc-web/src/authz.rs:268-281`, `page_kit/context.rs:181-195` | confirmed |
| SEC2-11 | info | The metadata deny list misses other link-local cloud credential endpoints | `crates/kcc-rci/src/outbound.rs:25-29` | adjusted (low→info) |
| SEC2-18 | info | info: AEAD associated data has no record-type prefix for router passwords and account hashes | `crates/kcc-app/src/credentials.rs:110-112`, `accounts.rs:346` | confirmed |
| SEC2-19 | info | info: The privilege floor ignores GID 0 | `crates/kcc/src/privileges.rs:249-251` | confirmed |
| SEC2-20 | info | info: `MasterKey::load_or_create` forces the key file's parent directory to mode 0700 | `crates/kcc-app/src/secrets.rs:197-198`, `persist.rs:562-566` | confirmed |
| A-19 | info | `FirmwareVersion` mixes derived equality with hand-written ordering | `crates/kcc-rci/src/version.rs:57` | adjusted (low→info) |
| A-22 | info | Review-process labels left in code and tests | `crates/kcc-rci/tests/auth_survivors.rs:1-2`, `tests/auth_parser.rs:18,55` | confirmed |
| B-15 | info | Audit retention runs only on rotation and only on whole files, unlike its documentation | `settings.rs:272`, `audit.rs:615-620` | adjusted (low→info) |
| B-16 | info | `glob_matches` claims to be kit-compatible but is not | `registry.rs:962-966`, `rmcp-server-kit-3.21.1/src/rbac.rs:1118-1130` | adjusted (low→info) |
| B-18 | info | More private async functions lack cancel-safety annotations than BACKLOG lists (KNOWN-BACKLOG) | `poller.rs:306`, `poller/extended.rs:72,125,153` | adjusted (low→info) |
| B-19 | info | A write job with no router fails as "router busy: missing" | `jobs.rs:411-414` | adjusted (low→info) |
| B-22 | info | The two-group env-override macro adds structure nothing needs | `settings/env_overrides.rs:30-55,137-139` | adjusted (low→info) |
| C-16 | info | `close` doc gives the wrong fate for a failed keep-unsaved | `close.rs:55-56`, `recovery.rs:128,155-158` | adjusted (low→info) |
| C-20 | info | Schedule descriptions cannot contain spaces | `crates/kcc-domain/src/schedules.rs:139`, `interfaces.rs:294` | adjusted (low→info) |
| D-22 | info | Dead branches and phantom inventory entries | `vpn_clients/import_fields.rs:69-71`, `vpn_conf.rs:138-143` | adjusted (low→info) |
| E-22 | info | The unvalidated CLI escape is not recorded as a deviation from project rule (b) | `crates/kcc-mcp/src/generic/rci.rs:433-439`, `kcc-catalog/src/request.rs:49-50` | confirmed |
| F-16 | info | VPN secret writes use a fixed gate and a hard-coded `unsaved` | `dom_vpn.rs:101-105`, `dom_vpn_server.rs:54-58` | adjusted (low→info) |
| F-19 | info | The privilege `Report` is discarded, so a kept bounding set is never reported | `privileges.rs:87`, `main.rs:16` | adjusted (low→info) |
| F-20 | info | Dispatchers have arms that return success for "unreachable" variants | `entry.rs:77`, `domains.rs:76-90` | adjusted (low→info) |
| F-21 | info | `Family<B, W>` encodes development history | `args_dom_family.rs:6-19`, `dom_admin.rs:29` | adjusted (low→info) |
| F-24 | info | `authorize_apply` restates code in comments and repeats a permission-label table | `context.rs:216-235` | adjusted (low→info) |
| F-26 | info | Duplicated CLI commands | `dom_core.rs:117-119`, `dom_wire.rs:67-68` | adjusted (low→info) |
| F-28 | info | Root cause of the `-` router in confirmation messages (KNOWN-BACKLOG) | `secret.rs:118-126`, `dom_jobs.rs:242-243` | adjusted (low→info) |
| F-31 | info | `live_smoke` checks only the serial allowlist, not `test_device` | `tests/live_smoke.rs:61-92`, `live_domains/gate.rs:96` | confirmed |
| G-24 | info | The Loki `level` stream label comes straight from untrusted router input | `logs/parser.rs:73-76`, `format.rs:62` | adjusted (low→info) |
| W1-11 | info | The permission list is hand-maintained in 3 places and silently drops unknown permissions | `crates/kcc-web/src/admin_roles.rs:69-108`, `errors/refusal.rs:63` | adjusted (low→info) |
| W1-12 | info | Wildcard arms map unknown future variants to a specific behaviour | `router_form/plan.rs:189-192`, `router_access.rs:67-70` | adjusted (low→info) |
| W1-15 | info | The connection test shows a server file path to the Web user | `crates/kcc-web/src/router_check.rs:202-206` | adjusted (low→info) |
| W2-16 | info | Public or `non_exhaustive` API surface that nothing outside the crate uses | `table.rs:15,17`, `lib.rs:118` | adjusted (low→info) |
| W2-17 | info | The step count is a magic number in two places | `wizard/flow.rs:90`, `wizard/screen.rs:399` | adjusted (low→info) |
| W3-17 | info | `\|safe` on composed regions | `pages/net_interfaces.html:20`, `net_internet.html:19` | confirmed |
| W4-10 | info | Copy-paste duplication across the two job streams and the handlers | `advanced/job_stream.rs:31-43,176-183`, `system_pages/jobs.rs:93-106,218-224` | adjusted (low→info) |
| W4-12 | info | Two tests pin English copy instead of message keys | `tests/explorer_pages/consoles.rs:327-329`, `tests/system_pages/diagnostics.rs:90` | adjusted (low→info) |
| W4-14 | info | The RCI console's read batch sends the redacted projection | `rci.rs:251-255`, `kcc-catalog/src/secret_value.rs:49-52` | confirmed |
| W5-14 | info | Maps go through a JSON round-trip and silently become empty if it fails | `migrate_wizard/maps.rs:265-274`, `kcc-migrate/src/maps.rs:22-25` | adjusted (low→info) |
| W5-15 | info | Two stacked firmware-update caches with different retry rules, and a doc comment that describes the wrong one | `fleet.rs:220-222`, `fleet_updates.rs:391-418` | adjusted (low→info) |
| X-05 | info | No gate checks lint *levels* against the vendored profile | `xtask/src/lint_completeness.rs:97-101`, `xtask/src/profile_eq.rs:34-36` | adjusted (low→info) |
| X-07 | info | The xtask workspace's dependencies are never advisory- or vet-checked | `xtask/Cargo.toml:13-22`, `ci.yml:134` | adjusted (low→info) |
| X-08 | info | `ci.yml` checkouts keep the token in `.git/config` | `ci.yml:34`, `container.yml:38-40` | adjusted (low→info) |
| X-11 | info | kcc-rci depends directly on the outdated getrandom 0.2, and the duplicate-skip reason does not mention it | `crates/kcc-rci/Cargo.toml:12`, `deny.toml:40` | adjusted (low→info) |
| X-13 | info | Seccomp drift never blocks, and the profile admits 32-bit ABIs the image never uses | `container.yml:86-91` | confirmed |
| T-10 | info | Bracket fate matrices are copied across the Web, MCP and domain tests | `kcc-web/tests/explorer_pages/bracket.rs:111-142`, `kcc-mcp/tests/support/bracket_failures.rs:47-92` | adjusted (low→info) |
| T-12 | info | `Debug` strings compared as an equality proxy | `crates/kcc-web/src/page_kit/request.rs:173-176` | confirmed |
| N9 | info | The catalog lacks `new-index` for `access-list rule ... order`; no catalog-validated reorder is possible | - | adjusted |

## Refuted (not issues)

| Id | Claim | Why refuted |
|---|---|---|
| SEC2-08 | Hostile router stalls fleet ndw4 logins | already in docs/BACKLOG.md |
| W4-04 | ~50 handlers lack cancel-safety comments | already in docs/BACKLOG.md |
| G-07 | Prunes run before the management phase | no front end sets `prune_lines` |
| E-21 | `kcc_diagnostics_write` registered read-only | it is not |
| W2-04 | Accepted rollback audited as failure | it is audited correctly |
| W2-13 | Tests assert on Debug output | cited tests don't |
| W3-03 | Wi-Fi settings never management-classified | classified where it matters |
| W3-12 | Read-back regions assume permissions | they compute them |
| N13 | DHCP pool writes never read back | they are read back |
| H1d | CLI `show running-config` leaks secrets with Read | CLI principal holds the master key; not a boundary |
