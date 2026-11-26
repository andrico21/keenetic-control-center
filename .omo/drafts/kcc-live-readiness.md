---
slug: kcc-live-readiness
status: approved
intent: clear
review_required: true
classification: architecture
plan_path: .omo/plans/kcc-live-readiness.md
plan_sha256: 3a7e9a10855d072abca2fa8bd5a9651cce7ee22ff960b3dd6bb7f5ae9750c113
review_round_id: r3-20261126T014501Z
round_status: closed
pending-action: "handoff done; the owner starts execution with $ulw-execute kcc-live-readiness"
review:
  momus:
    status: approved
    workspace_root: /home/andrico/keenetic-control-center
    runtime_home: null
    target: .omo/plans/kcc-live-readiness.md
    round_id: r3-20261126T014501Z
    plan_sha256: 3a7e9a10855d072abca2fa8bd5a9651cce7ee22ff960b3dd6bb7f5ae9750c113
    launch_id: 37c65c76b19c
    session: "bg_b7926a18 - attempt 1 ses_dea712f98ffe9Y46bpLyve1yOE failed on a model lookup before any read; attempt 2 ses_dea712922ffesC8x3qCkGHSORY completed; receipt pid 2326386"
    result: "OKAY - echo and digest match; no blockers; 2 non-blocking notes"
  independent:
    status: approved
    workspace_root: /home/andrico/keenetic-control-center
    runtime_home: null
    target: .omo/plans/kcc-live-readiness.md
    round_id: r3-20261126T014501Z
    plan_sha256: 3a7e9a10855d072abca2fa8bd5a9651cce7ee22ff960b3dd6bb7f5ae9750c113
    launch_id: 683e987bab36
    session: "ses_dea701414ffeISuUSdy6zGpz2N (bg_07e99233); receipt pid 2326437"
    result: "OKAY - echo and digest match; no blockers; 2 non-blocking notes and 2 optional remarks"
approach: >-
  Six components: (C1) RCI diagnostics in kcc-rci (typed transport causes, HTTP status and
  router error ids in Display/Debug, one WARN per failed request deduped, DEBUG per request,
  value-free decode details); (C2) honest surfaces (domain decode details via one helper,
  Web read-failure messages by class, CLI cause + RUST_LOG on stderr, no silent drops);
  (C3) evidence: capture covers every kcc read, capture -> offline decode harness, owner or
  agent capture per Q1; (C4) evidence-driven compatibility fixes for every failing page and
  the DNS/VPN server writes, simulator moved to captured shapes; (C5) Web UX fixes (password
  confirmation, router display name per Q2, segments explanation); (C6) docs, troubleshooting,
  CHANGELOG, 1.0.1 readiness per Q3. TDD with the fake router; leak tests with planted
  secrets; final wave F1-F4 plus an owner real-router confirmation.
---

# Draft: kcc-live-readiness

Request (2026-11-25, owner): "Prepare a plan based on your proposal. Plan should be fully
validated and approved by all critics." plus live-test notes and a `podman logs` excerpt
(kcc 1.0.0 container, real Keenetic router at $OWNER_ROUTER_HOST, model/firmware not yet known).
Proposal being planned (my previous answer): keep transport causes, log every request
(DEBUG) and failures (WARN), field-level decode logging, CLI prints cause and honours
RUST_LOG, tests incl. no-secret log checks, deliver to master + an image for the owner, then
1.0.1 after fixing what it shows. Refinement adopted (A2): no raw-answer log dump; the
anonymizing capture tool is the channel for answers.

## Affected user and ideal state

Users: (U1) the owner operating kcc in rootless Podman against a real Keenetic router (Web
UI, CLI in the container, logs via `podman logs`); (U2) future kcc users on other real
models/firmware; (U3) the developer/agent who must diagnose and fix from logs and captures;
(U4) MCP clients that receive kcc's error codes and texts.

| IS | Ideal-state property | Reason |
|---|---|---|
| IS-1 | Every failed router request leaves one WARN line: router id, method, RCI path (no query, value-like segments masked), cause class (connection refused/reset/timeout, closed before answer, body interrupted, TLS, local, HTTP status, router error ident/code, not found, method not allowed, body too large, not JSON, decode path+found+expected), elapsed ms; identical lines deduped (60 s, suppressed count) | owner could not tell why anything failed |
| IS-2 | `RUST_LOG=...kcc_rci=debug` shows every request incl. sign-in: method, path, status, bytes, ms | reconstruct a session without packet capture |
| IS-3 | Error Display/Debug name the cause: transport cause, HTTP status, router ident/code, decode path; no "see audit log" where nothing is audited | CLI and MCP logs inherit it |
| IS-4 | Logs and error texts never contain passwords, tokens, cookies, session ids, query strings, request/answer bodies or values, MACs/client names (masked path keys) | SECURITY.md (d), PRIVACY.md |
| IS-5 | Web pages tell the truth by class: did not answer / timed out / sign-in failed / HTTP N / router refused (with its message) / feature absent (404) / answered but unreadable (command + field) | pages said "did not answer" for decode failures |
| IS-6 | No silent drops: components page, DHCP name join, log poller, facts detection keep and log the real cause | "Unnamed device", synthetic transport error on Log page |
| IS-7 | CLI shows the cause in its detail line; with RUST_LOG set, CLI logs go to stderr, stdout/JSON unchanged | `router test` said only "transport failed" |
| IS-8 | A real-router capture covers every read kcc's pages perform (incl. detection and `show rc` roots), anonymized, passes `no_secrets`, and is replayable offline against kcc's decoders | evidence channel for U2/U3 |
| IS-9 | On the owner's router every failing page shows the router's data: clients, DHCP active leases, names in static leases/ARP, Wi-Fi, mesh members, IPv4/IPv6 routes, policies, NAT sessions, UPnP, router users, services, components, storage, schedules, KeenDNS, log, Entware | 1.0.0 unusable on real hardware |
| IS-10 | The DNS servers and VPN servers changes apply on the owner's router | both failed live |
| IS-11 | The fake router serves the captured (real) shapes for every fixed resource; decoders accept real shapes; BEHAVIOUR.md marks them captured | simulator diverged from hardware |
| IS-12 | Every self-service new password is typed twice (Web account page incl. forced first change; CLI interactive new-password prompts); a mismatch sends nothing | owner note |
| IS-13 | A router can carry a human name with spaces shown wherever people read it; the id stays a stable slug (per Q2) | owner note; form label says "Name" for an id |
| IS-14 | The Segments page explains what a segment is, why only kcc-made ones are listed, and where other bridges/VLANs are | owner question |
| IS-15 | Docs: troubleshooting (enable debug logs in the container, capture a router), CHANGELOG, PRIVACY/SECURITY notes on logging; master ready for 1.0.1 (per Q3) | operability |

| GAP | Today | Reason / evidence | Closed by |
|---|---|---|---|
| GAP-1 | `RciError::Transport` is a unit variant; 12 `map_reqwest_error` sites + ~10 local sites drop the cause | kcc-rci/src/session.rs:825-831, lib.rs:534 | C1 |
| GAP-2 | Http Display has no status; Debug prints only variant names (`error=RciError::Http`) | lib.rs:543, 583-606; owner log 19:44:42 | C1 |
| GAP-3 | kcc-rci has no tracing at all; no request or failure logs | explore bg_4d3fa17a §13 | C1 |
| GAP-4 | 391 `DomainError::InvalidResponse` sites; `read_show` and 5 `from_value` sites drop serde errors | kcc-domain/src/lib.rs:360-368 | C2 |
| GAP-5 | ~32 Web read sites map every error to `WEB_KIT_UNREACHABLE` | net_wifi.rs:94, route_views.rs:240, policy_rows.rs:153, sessions.rs:228, firewall views.rs:167 ... | C2 |
| GAP-6 | Log poller logs the real error at DEBUG and returns a synthetic `RciError::Transport` | kcc-web/src/system_pages/log_poller.rs:58,85,88 | C2 |
| GAP-7 | DHCP names: `read_clients(..).unwrap_or_default()` swallows the hotspot failure -> "Unnamed device" | kcc-web/src/clients_pages/dhcp.rs:164 | C2, C4 |
| GAP-8 | Components page logs no error | kcc-web/src/system_pages/components.rs:184-186 | C2 |
| GAP-9 | CLI installs no tracing subscriber; detail = `RciError` Display | kcc/src/cli/entry.rs:34-59, cli/exit.rs:229-251 | C2 |
| GAP-10 | Capture list (26 items) lacks most page reads (arp, nat, upnp, show rc user/service/opkg/policy..., components, mws associations, identification, interface bands, system mode ...) | kcc-testkit/src/capture.rs:83-121 vs domain reads | C3 |
| GAP-11 | Decoders and simulator shapes are synthetic; no fixture is captured from hardware; e.g. fake `show ip hotspot` is a bare array while kcc decodes `Vec<Client>` | BEHAVIOUR.md:45,78; projection/hosts.rs:35-60; clients.rs:126 | C3, C4 |
| GAP-12 | kcc reads `show components list`/`show components pending`; the 5.1 catalog has `components list`, `components preview`, `show components status` only -> likely the Components page and Entware NotFound | components.rs:155,168; catalog/5.1 | C4 |
| GAP-13 | DNS servers change: router error status, message not logged; VPN servers change: HTTP error, status not logged | failure.rs:82-103 | C1, C4 |
| GAP-14 | Account password form has no confirmation; CLI new-password prompts read once | templates/pages/account.html:11-15; auth.rs:387-447; cli/secret.rs:40 | C5 |
| GAP-15 | Router "Name" field is the id (`[a-z0-9-]{1,32}`); no display name exists | web.ftl:118-119; settings.rs:1123-1130, 689-718 | C5 |
| GAP-16 | Segments page states the rule without explaining it | web.ftl:1891-1892; USER_GUIDE.md:124-139 | C5 |
| GAP-17 | No troubleshooting doc for logs/capture; CHANGELOG/version | docs | C6 |

## Components (topology ledger)

| id | outcome | status | evidence |
|---|---|---|---|
| C1 | kcc-rci diagnostics: typed causes, logging, dedupe, value-free decode detail | active | explore bg_4d3fa17a, librarian bg_0f37162f |
| C2 | honest surfaces: domain decode detail, Web read-failure classes, CLI cause + RUST_LOG, no silent drops | active | bg_b930a59f, bg_4abfa9e3, direct reads |
| C3 | evidence channel: capture covers all reads, offline decode harness, capture run (Q1) | active | bg_3b9ff172 |
| C4 | evidence-driven compatibility fixes (reads + DNS/VPN writes), simulator to real shapes | active | depends on C3 output |
| C5 | Web/CLI UX: password confirmation, router display name (Q2), segments explanation | active | bg_4abfa9e3 |
| C6 | docs, troubleshooting, CHANGELOG, 1.0.1 readiness (Q3) | active | - |

## Open assumptions (announced defaults)

| id | assumption | adopted default | rationale | reversible? |
|---|---|---|---|---|
| A1 | log levels | failure = WARN (deduped 60 s per router+method+path+cause, `suppressed=N`), request = DEBUG, sign-in ok = DEBUG, sign-in failure = WARN | default level `info` shows failures only | yes |
| A2 | raw answers in logs | never; the capture tool (anonymizer) is the channel | mask_reply hides secrets, not MACs/IPs/names | yes |
| A3 | decode detail | `serde_path_to_error` path, map keys not matching `^[A-Za-z][A-Za-z0-9_-]{0,63}$` masked as `*`; found JSON kind from the Value; `expected ...` suffix of the serde message (our type) cut at 80 chars; "missing field `x`" keeps our field name | value-free by construction | yes |
| A4 | dependency | `serde_path_to_error` 0.1.20 direct dep of kcc-rci (already in Cargo.lock via axum; cargo-vet exemption supply-chain/config.toml:1109) | no new crate | yes |
| A5 | Web messages | class-specific keys in all 6 locales; decode failures show command + masked field; "the server log has details" hint | i18n rule | yes |
| A6 | CLI logs | stderr `fmt` subscriber only when `RUST_LOG` is set; nothing changes otherwise | stdout/JSON contract | yes |
| A7 | fix patterns | F1 lenient helpers, F2 serde alias, F3 envelope, F4 map->list, F5 catalog/tree path, F6 text form only if documented, F7 write command per router error+catalog | removes executor judgment | yes |
| A8 | simulator | fake router emits the captured shape for each fixed resource; decoders keep only captured + catalog-documented shapes | no hardware ever produced the synthetic ones | yes (git) |
| A9 | password confirmation scope | Web account page + CLI interactive prompts of `user add`, `user passwd`, `router-users passwd`; file/env sources unchanged | same lock-out risk | yes |
| A10 | segments | explanation text + docs; no adoption of foreign bridges | safety model of delete | yes |
| A11 | test strategy | TDD (red first), fake router + fault injection, tracing capture with planted secrets for leak tests | repo convention | yes |
| A12 | diagnostic image | agent builds `localhost/kcc:diag` locally from master; no pre-release tag | no external publish | yes |
| A13 | owner's router writes | only the owner retries writes on the real router | home network safety | - |

Extrinsic sweep: budget - none (local work); mandated stack - existing Rust workspace and
crates, no new external crate (A4); scale - one to a few routers, log volume bounded by A1
dedupe; audience/compliance - SECURITY.md rule (d), PRIVACY.md (no secrets/personal data in
logs) - asserted by leak tests.

## Findings (cited - path:lines)

- RciError enum and Debug: crates/kcc-rci/src/lib.rs:529-606 (Transport unit, Http{status} Display without status, Debug prints variant names only).
- Transport cause drop: session.rs:825-831 `map_reqwest_error`; `.send()` sites: session.rs:380,456,491,522,603,674; auth_ndw4.rs:163,189; auth_token.rs:22; auth_digest.rs:92,118; session/transport.rs:28; body read engine/body.rs:28-30; local: session.rs:230,595,750,793; auth_digest.rs:70,73,203; auth_ndw4.rs:88; ndw4_keys.rs:66,74; engine/admit.rs:37; session/transport.rs:51.
- Central send: engine.rs:600-615 (`Engine::send`); status mapping engine.rs:669-681; non-JSON fallback to `RciBody::Text` engine.rs:705-716.
- Metrics labels: observe.rs:35-72 (ok, auth_error, transport_error, http_error, error) - must stay stable.
- Variant consumers outside kcc-rci: kcc-web page_kit/failure.rs:80-105, advanced/deliver.rs:244-262, router_check.rs:264, system_pages/log_poller.rs:85,88; kcc/src/cli/exit.rs:229-251; kcc-mcp/src/support/errors.rs:95-110; kcc-app workflow_replay.rs:96-107, workflow.rs:1704, workflow_output.rs:158; kcc-migrate inventory.rs:487.
- Domain decode: kcc-domain/src/lib.rs:360-368 `read_show`; from_value sites wifi.rs:96, dns.rs:399, interfaces.rs:139, interfaces/membership.rs:44, entware.rs:58-66; DomainError lib.rs:283-340; 16 `InvalidResponse` uses outside kcc-domain.
- Read-failure mapping to unreachable: 15 direct `WEB_KIT_UNREACHABLE` + 17 `Family::Changes.unreachable()` in kcc-web (e.g. net_wifi.rs:94, net_mesh.rs:108, route_views.rs:240, policy_rows.rs:153, nat_page/sessions.rs:228, firewall_page/views.rs:167); facts FactsError::Unreachable page_kit/facts.rs:31-45,78-81.
- Silent drops: dhcp.rs:164 (names), components.rs:184-186, log_poller.rs:58,85-89.
- Domain read paths: read_show list (35 paths) and show_rc roots (opkg, user, service, ip policy, interface, access-list, ip static, ip dhcp host, dns-proxy tree, vpn-server tree, interface access-group) - grep output recorded in this session.
- Catalog drift: kcc reads `show components list|pending` (components.rs:155,168); catalog/5.1 has `components list`, `components preview`, `show components status`.
- Capture tool: kcc-testkit/src/capture.rs:83-121 (26 items), serial allowlist :256-277, anonymizer :436-530; CLI bin/kcc-capture.rs; CONTRIBUTING.md:128-140.
- Fake router: FaultInjection lib.rs:129-220 (disconnect at parse, HTTP 500 by substring, show_requires_post ...), `show_fixture` override lib.rs:506; hotspot projection projection/hosts.rs:35-60 (bare array).
- Tracing init: serve uses rmcp_server_kit init_tracing_from_config_strict (server.rs:226) honouring RUST_LOG; CLI none; tracing-subscriber 0.3.23 with env-filter already compiled in the graph; kcc has tracing-subscriber only as dev-dependency (crates/kcc/Cargo.toml:60-61).
- Redaction engine: kcc-config/src/mask.rs (is_secret_name, mask_json, mask_reply, redact_text); kcc-rci has no kcc-* deps.
- Web password forms: account.html:11-15 (no repeat), auth.rs:81-86 PasswordForm, :387-447 handler; repeat pattern user_dialog.rs:140-167 (`secret_again`, WEB_SECRET_REPEAT, web-secret-mismatch web.ftl:1906).
- Router id: settings.rs:1123-1130 `is_valid_router_id`, RouterProfile settings.rs:689-718, registry.rs:76; web.ftl:118 "Name" label.
- Segments: kcc-domain/src/segments/discovery.rs:87-200 ownership record in the VLAN description; USER_GUIDE.md:124-139.

## Decisions (with rationale)

- D1 intent CLEAR (owner knows the outcome), review_required true ("fully validated and approved by all critics").
- D2 DomainError gains `UnreadableAnswer(Box<DecodeDetail>)` produced by central decode helpers; `InvalidResponse` stays for the other 380+ sites (minimal churn).
- D3 RciError: `Transport(TransportCause)`, `Decode(Box<DecodeDetail>)` (detail for detection decodes); Http Display carries status; Debug prints causes/status/ident/code, never `message`.
- D4 Router error message is logged only after the existing scrub (kcc-app workflow) at the Web/CLI layer; kcc-rci logs ident/code/pointer only.
- D5 Path masking rule for logs: drop query; mask segments/keys not matching the identifier rule.
- D6 Capture list = existing 26 + every domain read path and show-rc root + detection reads + both components forms; a kcc-domain test asserts every DESCRIPTOR read op has a capture item.

## Scope IN

C1-C6 as above; owner checkpoints per Q1; final wave F1-F4 plus owner confirmation on hardware.

## Scope OUT (Must NOT have)

- No raw router answers or request bodies in logs; no secrets, cookies, tokens, query strings, MACs or client names in logs or error texts.
- No change of metrics label values (`transport_error`, ...).
- No agent writes to the owner's real router; no saving of router configuration by any test.
- No adoption/import of foreign segments; no new MCP tools; no change of router id rules.
- No new external crates beyond A4; no release tag or GitHub release by the agent unless Q3 says so.

## Open questions (answered 2026-11-25)

- Q1 evidence route -> (b) "Agent runs the capture". Follow-up owner message: "you have `kcc` container on the same host with preconfigured router there - you can use it for any read-only operation or even curl (secret is inside)". => The executing agent may perform READ-ONLY operations against the owner's router: `podman exec kcc /kcc ...` read commands, the capture tool, a separate kcc instance that only reads, and raw HTTP GET / show-POST with the password from the Podman secret named by `$OWNER_ROUTER_PASSWORD_SECRET` (never printed, never committed). Writes on the owner's router stay with the owner (A13).
- Q2 router names -> (a) display name (label) with spaces shown everywhere; id derived in the add form, stays the stable key.
- Q3 release -> (b) the agent tags 1.0.1 and watches Release + Container workflows (after F1-F4 approve and the owner's okay).

## Live evidence (planner, read-only, 2026-11-25)

Router: `$OWNER_ROUTER_ID` (state router, URL `$OWNER_ROUTER_URL`, login admin), Keenetic Ultra KN-1811, firmware 5.1.10. Auth offered: `x-ndw2-interactive` only. Method: `kcc --json rci get/post` in the owner's container plus raw ndw2 sign-in from the Podman secret; only value-free shapes were printed (keys, JSON kinds, lengths).

| read (kcc code) | kcc expects | router 5.1.10 returns | effect |
|---|---|---|---|
| `show ip hotspot` (clients.rs:126) | top-level array `Vec<Client>`; `interface: Option<String>`; `rx`/`tx` | `{"host":[...]}` (hundreds of rows); `interface` object `{id,name,description}`; `rxbytes`/`txbytes`; `hostname`, `name`, `first-seen`, `last-seen`, `active`, `link`, `ssid`, `rssi`, `priority`, `registered`, `access`, `policy`, `schedule`, `mws{...}`, `dhcp{expires}` | Clients page fails; DHCP/ARP names empty ("Unnamed device") |
| `show ip dhcp bindings` (dhcp.rs:90) | `Vec<Binding>`, `expires: Option<u64>` | `{"lease":[...]}`; `expires` int OR string; `device`, `hostname`, `ip`, `mac`, `mode`, `name`, `via` | Active leases fail |
| `show ip arp` (dhcp.rs:103) | `Vec<Neighbour>` | top-level array `{interface, ip, mac, name, state}` | decodes; `name` unused |
| `show associations` (wifi.rs:152) | `Vec<Station>`; `rx-rate`/`tx-rate` | `{"station":[...]}`; `rxrate`/`txrate`, `rxbytes`/`txbytes`, `rssi`, `ap`, `uptime` | Wi-Fi page fails |
| `show interface` AccessPoint/WifiMaster | AccessPoint {id, ssid, state, hide-ssid} | AP fields id, ssid, state, description, link, mac, encryption, auth-type ...; WifiMaster channel int, bandwidth str# | decodes |
| `show mws member` (mesh.rs:118) | `Vec<Member>` {id, name, mac, online} | array {cid, known-host, mac, model, mode, ip, fw, fw-available, associations int, internet-available bool, cloud-agent-state, system{}, wireless{}, port[], backhaul{}} | all "Not reported" |
| `show mws associations` (mesh.rs:131) | `Vec<Association>` | `{}` | fails when read |
| `show ip route` | `Vec<RouteTableEntry>` | top-level array {destination, gateway, interface, metric, flags, proto, static, floating, rejecting} | decodes |
| `show ipv6 route` | `Vec<RouteTableEntry>` | `{"route6":[...]}` | IPv6 table fails |
| `show ip policy` (policies/read.rs:16) | `Vec<PolicyState>` | object keyed by policy name {description, mark, route4{route[]}, route6{route6[]}, table4, table6} | Policies fail |
| `show ip nat` + `offset`/`limit` (nat/read.rs:64-90) | <= 200 rows per page | ignores offset/limit (catalog: unknown fields); returns all rows (more than 200 on the owner's router); kcc errors when rows > 200 | Active connections fail |
| `show upnp redirect` (firewall/read.rs:139) | `Vec<UpnpRedirect>` | `{}` (no redirects) | UPnP fails |
| `show media` (storage.rs:105) | `Vec<MediaVolume>` | object keyed by media name {bus, state, size str#, removable, ejectable, initialize-supported[], partition{<name>{...}}} | Storage fails |
| `show usb` (storage.rs:118) | `Vec<UsbDevice>` | `{"device":{<id>:{DEVICE, DEVPATH, port, subsystem, usb-version, power-control}}}` | fails |
| `show schedule` (schedules.rs:128) | `Vec<ScheduleState>` | object keyed by schedule name {action[]} | Schedules fail |
| `show ndns` (keendns.rs:128) | KeenDnsState `booked: Option<bool>` | object {name, domain, address, address6, access, access6, booked: string, updated: bool, xns, ttp{...}} | KeenDNS fails |
| `show rc user` (router_users.rs:107) | `user: Vec<RawRouterUser>` | `user: {<name>: {tag: [...]}}` | Router users fail |
| `show rc service` (services.rs:186) | `service: Vec<ServiceState>` | `service: {<name>: bool}` | Services fail |
| `show components list`/`pending` (components.rs:155,168) | exist | HTTP 404 (GET). Real: `POST /rci/components/list {}` -> `{"continued":true}` while fetching, then `{firmware, sandbox, local, component:{<name>:{installed: version string, queued, group, description{}, depend, size, version, ...}}, group, changelog}` (~250 KB); `POST components/preview {}` -> status-only when nothing pending | Components page fails; Entware NotFound (read_status calls read_components) |
| `show log` (diagnostics.rs:164-192) | text, or JSON finished; on `continued:true` it calls `start()` which needs `/process/id` | `{continued: true, log: {<id>: {id, ident, timestamp, message:{label, level, message}}}}` unless `"once": true`; fake router defaults `once` to true (server.rs:1461) | Log page: Decode in start(), poller hides it as synthetic Transport |
| VPN servers `show rc` tree (vpn_servers.rs:194-202) | 200 | HTTP 500 with empty body: two or more sub-keys requested under a node absent from the running config (vpn-server, oc-server here); whole-subtree requests answer 200 with a "not found" status (Core::Configurator 1179781) | VPN servers page and change fail (log: RciError::Http) |
| `show rc` absent nodes (nextdns, opkg, vpn-server, wireguard-server, crypto map) | - | 200 with nested `status` error `not found: "show/rc/<path>"` | tolerated today |
| DNS servers change | - | router error status (message not yet seen) | needs owner retry with diagnostics |
| `show identification` | optional (not in catalog) | exists: cid, hwid, mac, serial, servicetag | capture serial gate works |
| `whoami` | optional | {agent, host, mac, password, user, where} | capture must mask `password` |
| `kcc info` | - | prints `Ultra (KN-1811) (KN-1811)` (model already contains the hw id) | cosmetic |

Additional defaults from the evidence:

| id | assumption | adopted default | rationale | reversible? |
|---|---|---|---|---|
| A14 | router data in git | none: the full anonymized capture stays local (gitignored `.omo/evidence/live/`); committed fixtures are hand-written real-shape JSON with synthetic values, checked against the capture by a shape-parity script | publishing derived home-network data is irreversible | yes |
| A15 | agent hardware QA | the executor may run a separate `kcc-diag` container (own state, router added from the Podman secret) and drive its pages read-only; it never submits a form against the owner's router | owner allowed read-only operations | yes |
| A16 | `show rc` requests | never ask for two or more sub-keys under a node that may be absent; ask for the whole node | router answers 500 otherwise | yes |
| A17 | NAT | send no `offset`/`limit`; read all rows (8 MiB body cap) and page locally | catalog has no such args; router ignores them | yes |
| A18 | mesh | id = `cid`, name = `known-host` (fallback `model`); show model, mode, IP, firmware, clients (`associations`), internet; drop the unsupported "online" column | no online flag in the real answer | yes |

## Approval gate
status: approved (answers 2026-11-25 + read-only permission)
next: scaffold the plan, run Metis, append todos, fill TL;DR, run dual review (momus + oracle) to convergence, then hand off.
review: converged in round r3-20261126T014501Z; momus OKAY and oracle OKAY on plan sha256 3a7e9a10855d072abca2fa8bd5a9651cce7ee22ff960b3dd6bb7f5ae9750c113; handed off 2026-11-26.


## Metis gap analysis (bg_f532e236, ses_deb695551ffeWwPc3x4kjMLE0l) - dispositions

All 26 findings folded into the plan (no owner question needed):
- B1 continuation protocol: verified read-only (POST tools ping -> continued without /process/id; GET same path continues; second POST restarts) -> todo 28, GAP-17, IS-9 Diagnostics, capture items (todo 4), one self-ping allowed in the hardware protocol.
- B2 CLI subscriber before dispatch breaks serve -> todo 10 installs only in Local/Domain/non-stdio Mcp arms; serve and mcp stdio acceptance tests.
- B3 key masking leaks names -> F4 `lenient::keyed_rows` (paths carry indices), Must NOT rule, leak tests (todo 20, todo 22).
- I4 management detection, I5 write/planning callers, I6 dashboard count, I7 Telegram/metrics users -> todo 29, GAP-18, IS-16, U5/U6.
- I8 read_log raw text consumers -> todo 21 keeps raw text, Web page parses.
- I9 more silent drops -> todo 9 (storage USB, schedule eligibility, telemetry items) and todo 29 (management, alerts).
- I10 expected 404 noise -> todo 2 (NotFound/MethodNotAllowed/Cancelled at DEBUG; generic surface WARNs to DEBUG).
- I11 non-serde decode kinds + missing consumer sites -> todo 1 (NotUtf8, MissingPointer, Length; full consumer list + lsp_find_references).
- I12 router id vs label -> todo 2 `with_log_id`, construction sites listed.
- I13 downgrade -> todo 7 `skip_serializing_if`, GAP-19, CHANGELOG/CONFIG note (todo 26); kcc-diag uses its own state.
- I14 Cyrillic labels -> todo 11 `router-<n>` fallback, `-2` suffix, editable id.
- I15 MCP/CLI JSON stability -> procedure step 3 (deserialize-only aliases), Must NOT.
- I16 NAT body cap -> todo 8 `web-kit-too-large`; sessions_page signature kept.
- I17 password choke point -> todo 5 (`new_secret` interactive branch, accounts, migrate_plan; PasswordForm deny_unknown_fields).
- I18 coverage beyond descriptors -> todo 4 `CALL_SITES` table.
- I19 version bump -> todo 27 (already), release.yml tag==version noted.
- I20 RUST_LOG recipe -> IS-2, todo 23 (`[observability] log_level`), todo 26 docs.
- I21 live contract -> Must NOT (no live_* suites), todo 12/23.
- N22 two instances/footprint -> executor never uses the owner's container; owner retries only on kcc-diag; password never in argv; agent-actions log.
- N23 owner evidence -> todos 24/25 collect kcc-diag logs.
- N24 VPN whole-node secrets -> todo 22 mask_json + leak test.
- N25 stack/translations/firmware tier/timeout -> G0 1 MiB children kept; CHANGELOG translation caveat; FIRMWARE note without tier change; map_reqwest_error timeout split kept.
- N26 acceptance criteria -> present per todo.
- Contrarian (A8): adopted - decoders tolerant (captured + previous shape), simulator on captured shapes, BEHAVIOUR "captured: KN-1811 5.1.10; assumed: other models, 4.3, 5.0", shape parity as a Rust harness test (no Python script).


## Review rounds (convergence ledger)

Round r1-20261125T231422Z (plan sha256 0b2083f7...cc2):
- momus (ses_deaff5a08ffeD4k4m45aeqwXyf, bg_8e4e3067): OKAY with 5 notes (classify get_ref; Blocks lists vs matrix; F1 scope 28/29; todo-4 Continued on the existing session + sign-out; todo-5 migrate_plan reads files only) - all folded.
- independent/oracle (ses_deafebd34ffe455gn9erNuf41E, bg_2f3774bb): REJECT, 6 blockers - ledger frozen with:
  - B1 diagnostics output lost under continuation (job reads final `reply`) -> todo 28 `poll_each`, `message` chunks to progress lines, fake chunk shape, harness asserts >= 1 line.
  - B2 storage id change breaks the Entware guard / initialize target -> todo 18 keeps `id` = media key, adds `partition`, de-dup in listings, guard and wait_initialized tests.
  - B3 owner literals in tracked `.omo/` files of a public repo; volume labels copied into fixtures -> literals replaced by `$OWNER_ROUTER_*` from gitignored `.omo/evidence/live/owner-router.env`; Must NOT covers `.omo/`; pre-commit scan; F1 scans `.omo/`; only log `message.label` copied.
  - B4 router refusal message at WARN could carry MACs/names -> WARN has ident/code only; message at DEBUG with MAC redaction; IS-4 states the single exception; planted-MAC test.
  - B5 todo 3 needs Deduper from todo 2 (parallel) and its WARN lacks router -> Deduper, `with_log_id`, `RciClient::log_id()` moved into todo 1; decode WARN carries `router`.
  - B6 owner checkpoint used a stale kcc-diag password -> todo 23 writes the new password back to admin.json; todo 24 reads it.
  - Oracle notes folded: lenient helpers use invalid_type/invalid_value; empty-ARP management verdict test; bytes wording; TL;DR accuracy; raw explorer paths noted (operator-typed, kept as is).
Round r2-20261125T235541Z (plan sha256 b53972cc7c3b1c76f4200067586c84e91781ffe8070495689ea00f4fb1773601):
- momus (ses_deadb4efcffeWl8Q0CwRtHiZX2, bg_c36c5808; attempt 1 ses_deadb5417ffe47ikArtn2E5jBM failed on a model lookup): echo and digest match; B1-B6 and the round-1 notes closed; REJECT, 1 blocker:
  - R2-1 the B3 leak scan looked for every env value, including the factory-default login (in 63 tracked `.omo` files and the plan) and the secret name (plan, draft): the first `chore(omo)` commit and F1 could never pass.
  - Notes: todo 12's harness called `poll_each` before todo 28 adds it; the IS-4 success row lacked todo 9; todo 9 cited a test instead of `scrub_error`.
- independent/oracle (ses_deada3e42ffe68dzoS5AestcFU, bg_16f900e5): echo and digest match; B2, B4, B5, B6 closed; REJECT, 3 blockers:
  - R2-1 (same as momus).
  - R2-2 B1 still open on the Web: `diagnostic_lines::sentence()` drops an output line that is not a known JSON kind (`jobs.rs:248-257` `filter_map`), so the raw `message` strings never reach the Diagnostics page.
  - R2-3 todo 18's `extra` with partition fields would serialize `id` (and `label`) twice through `#[serde(flatten)]`; a client that reads the last key gets the partition id.
- Fixes (smallest edits, each claim checked in the code first):
  - R2-1: one leak scan defined in "Execution strategy": always `OWNER_ROUTER_ID`/`_URL`/`_HOST`/`_NET` (0 tracked hits today); the other env values and each line of the gitignored `.omo/evidence/live/identifiers.txt` only when the tracked tree at `<start>` lacks them (`git grep -F`); hits reported by name, never value; `<start>` defined and recorded; F1 and fixture step 1 point at that scan; the secret name replaced by `$OWNER_ROUTER_PASSWORD_SECRET` in plan and draft; todo 4 gains `--identifiers-out` (0600, refused inside the capture directory), todos 12 and 23 pass it.
  - R2-2: todo 28 emits each `message` string as `{"kind":"text","text":...}` (new `ProgressLine::Text`); `sentence()` gains a `text` arm (no new key; the template escapes); a Web continuation-ping test; the existing process-id Web tests build their fake with `process_ids(true)`; commit scope adds domain and web.
  - R2-3: todo 18's `extra` leaves out the partition's `id`, `label`, `fstype`, `total`, `free` and any typed-field name; acceptance asserts one `id` key equal to the media key and `partition` = the partition id.
  - Notes folded: todo 12 uses `poll`, todo 28 switches it to `poll_each`; the IS-4 row adds todo 9 and its evidence; todo 9 cites `scrub_error` (`workflow.rs:1696-1715`); the IS-9 row adds the Web test and the task-28 evidence.
Round r3-20261126T014501Z (plan sha256 3a7e9a10855d072abca2fa8bd5a9651cce7ee22ff960b3dd6bb7f5ae9750c113, 146662 bytes; round-2 text kept locally at `.omo/evidence/plan-r2-b53972cc.md` for diffing):
- momus (bg_b7926a18; attempt 1 ses_dea712f98ffe9Y46bpLyve1yOE failed on a model lookup before any read, attempt 2 ses_dea712922ffesC8x3qCkGHSORY completed; receipt pid 2326386; launch 37c65c76b19c echoed): digest match; R2-1, R2-2, R2-3 and the folded notes closed; no regression in the changed lines; OKAY, no blockers. Notes: todo 9's QA command runs only the kcc-web tests (G0 still runs the workspace); `identifiers.txt` exists only after todo 12 (expected).
- independent/oracle (ses_dea701414ffeISuUSdy6zGpz2N, bg_07e99233; receipt pid 2326437; launch 683e987bab36 echoed): digest match; R2-1 checked by variable name and count only (ID, URL, HOST, NET in 0 tracked files; LOGIN and PASSWORD_SECRET already tracked, so the at-`<start>` rule leaves them out), R2-2, R2-3 and the folded notes closed against the code; no regression; OKAY, no blockers. Notes: a plain-word identifier that a new commit happens to contain blocks it with no override path; Stop in continuation mode has no test. Optional: the existing Web diagnostics tests run a paused clock with a loopback fake, which the new continuation test must not copy; the `diagnostic_lines.rs` module comment overstates what is shown.
- Convergence: both lanes approved the same digest in round 3 (rounds: r1 REJECT with 6 blockers, r2 REJECT with 3, r3 OKAY/OKAY); the review is closed. The plan was not edited after approval; the notes stay here, because any plan edit voids both approvals.
- Final live-plan validation before handoff: descriptor-safe sha256 3a7e9a10855d072abca2fa8bd5a9651cce7ee22ff960b3dd6bb7f5ae9750c113 (matches the approved digest).

## Executor notes (non-blocking, from review round 3)
- Leak scan: a hit blocks the commit and the plan offers no override; if a learned identifier is an ordinary word that new code legitimately contains, stop and ask the owner rather than weakening the scan.
- Todo 28: add one test for Stop in session-continuation mode (the dedicated session is signed out, no `DELETE` is sent).
- Todo 28: the new Web continuation-ping test must not use `#[tokio::test(start_paused = true)]` with the loopback fake (plan Must NOT, line 100), even though the existing tests in that file do.
- Todo 9: if its evidence log should show the schedule-eligibility (`kcc`) and telemetry (`kcc-app`) tests, run those packages too; G0 already runs them.
