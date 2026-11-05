---
slug: keenetic-control-center
status: approved
phase: review_approved
intent: clear
review_required: true
plan_path: .omo/plans/keenetic-control-center.md
plan_sha256: 8db86d1160def4f4892f4407c6fa9094f1b2ca41dca92e89bb932c4ee3376a3b
review_round_id: s4r3-20261105T113752Z-1db302cb
round_status: approved
pending-action: handoff - execution via $ulw-execute keenetic-control-center (owner starts it)
review:
  momus:
    status: approved
    workspace_root: /home/andrico/keenetic-control-center
    runtime_home: null
    target: .omo/plans/keenetic-control-center.md
    round_id: s4r3-20261105T113752Z-1db302cb
    plan_sha256: 8db86d1160def4f4892f4407c6fa9094f1b2ca41dca92e89bb932c4ee3376a3b
    launch_id: L-momus-s4r3-01
    session: ses_e5485b2f6ffeQ33XsoyGFKNJue (bg_b3cf1b58)
    result: OKAY (s4r3)
  independent:
    status: approved
    workspace_root: /home/andrico/keenetic-control-center
    runtime_home: null
    target: .omo/plans/keenetic-control-center.md
    round_id: s4r3-20261105T113752Z-1db302cb
    plan_sha256: 8db86d1160def4f4892f4407c6fa9094f1b2ca41dca92e89bb932c4ee3376a3b
    launch_id: L-oracle-s4r3-01
    session: ses_e54858503ffemmiSp3YLBwhwS2 (bg_1632c436)
    result: OKAY (s4r3)
approach: >
  Rust 1.99.1 cargo workspace. Own RCI client (ndw2 + ndw4 SCRAM/Argon2id + X-NDMA-TKN token + Digest via
  port-79 proxy), a command catalog generated from the official per-model CLI Reference PDFs (Appendix B says
  the CLI reference IS the RCI resource reference) used for validation/search/full coverage, curated typed
  domain operations with read-back verification, a startup-config migration engine (parse -> inventory ->
  remap -> plan/diff -> apply via `parse` under the native fail-safe timer -> verify -> commit), an MCP server
  on rmcp-server-kit 3.21.x (stdio + Streamable HTTP, API-key/RBAC, read-only mode, confirm gates), and a `kcc`
  CLI. Core Section 9 lint profile verbatim, strict deny.toml, full Section 12 CI.
---

# Draft: keenetic-control-center

## Affected user and ideal state

Affected users:
- U1 Home/SOHO admin (the owner) running `kcc` CLI against one or more Keenetic/Netcraze routers.
- U2 AI agent (Claude/Codex/Cursor/OpenCode) driving the router through MCP tools.
- U3 Operator running the MCP server as a networked service (Streamable HTTP, API keys, RBAC).
- U4 Future maintainers/agents working in the repo under rust-guidelines.

Today: nothing exists (empty dir). Prior art: keenetic-mcp (TS, 18 tools, ndw2 only), keenetic-router-plugin (TS, confirm/dryRun),
keenetic-rci (Rust lib, ndw2 only, weak lints). None does full coverage, ndw4/token auth, or migration.

| IS | Ideal-state property | Reason |
|----|----------------------|--------|
| IS-1 | Connects to any KeeneticOS/NetcrazeOS 5.1+ device on LAN (and via KeenDNS rci proxy) with whatever auth scheme the firmware advertises (ndw2, ndw4, token), re-authing transparently on the 300s sliding session | 5.2 adds ndw4 + X-NDMA-TKN and devs said ndw2 will be removed "as soon as possible"; session expires after 5 idle min |
| IS-2 | Every RCI resource documented for the model (settings/actions/background processes, show/rc/sc, DELETE/no) is reachable and validated before sending | "Full API coverage"; wrong field names are silent no-ops on the router |
| IS-3 | Common domains have typed, verified operations (read-back after write; errors inside HTTP 200 surfaced) | Router accepts wrong commands silently; prior incident wiped all routes |
| IS-4 | Nothing is persisted without explicit save; risky applies run under fail-safe timer with automatic rollback on lockout | Avoid self-lockout; keep reboot-reverts semantics |
| IS-5 | Migration old->new router produces a reviewable plan (what is copied, remapped, skipped, needs input) before touching the target, then applies, verifies, and reports | Different models differ in ports/radios/components; secrets/realm-bound hashes differ |
| IS-6 | Secrets (router password, tokens, PSKs, keys) never appear in logs, tool results (unless explicitly requested export), errors, or Debug | Security; guidelines Section 10 |
| IS-7 | MCP surface is LLM-usable: bounded tool count, bounded response sizes, accurate readOnly/destructive annotations, read-only mode removes write tools | Context window; agent safety |
| IS-8 | Networked MCP deployment is authenticated, RBAC-scoped, rate-limited, OWASP-hardened | http-services + mcp-servers overlays |
| IS-9 | Codebase passes the core Section 9 strictest lint profile verbatim, deny/audit/vet/machete, full CI | Mandatory user requirement |
| IS-10 | Everything verifiable without hardware (fake router), plus env-gated live tests | Agent-executable QA |

| GAP | Difference | Reason | Closed by |
|-----|-----------|--------|-----------|
| GAP-1 | No workspace/lint/CI baseline | IS-9 | baseline todos |
| GAP-2 | No RCI client/auth | IS-1 | rci todos |
| GAP-3 | No machine-readable command catalog (RCI has no introspection: GET /rci/show returns []) | IS-2 | catalog todos |
| GAP-4 | No typed domains | IS-3 | domain todos |
| GAP-5 | No migration engine | IS-5 | migration todos |
| GAP-6 | No MCP server | IS-7, IS-8 | mcp todos |
| GAP-7 | No CLI | U1 | cli todos |
| GAP-8 | No fake router/test tiers | IS-10 | test infra todos |

## Components (topology ledger)
| id | outcome | status | evidence |
|----|---------|--------|----------|
| C1 | kcc-rci: transport, auth (ndw2/ndw4/token/digest), sessions, errors, batch, background processes, /ci file download, put+/fui upload | active | rci-tools docs/AUTH.md, RCI_API.md; CLI ref App. B |
| C2 | kcc-catalog: generated per-model command catalog (path, kind, no-prefix, multiple-input, args, iface type, since-version) + validator + search | active | cli_manual_kn-1811.pdf 5.1 outline: 187 groups, 779 leaf cmds, 127 show cmds |
| C3 | kcc-domain: curated typed ops per domain w/ read-back verify | active | keenetic-mcp docs/rci-api.md traps |
| C4 | kcc-migrate: startup-config parser, model inventory, remap, plan, apply under fail-safe, verify, report | active | CLI ref 3.179.5-3.179.10 fail-safe; forum put/fui |
| C5 | kcc-mcp: rmcp-server-kit 3.21 server handler, tools/resources/prompts, safety gates | active | rmcp-server-kit README/GUIDE |
| C6 | kcc (bin): CLI + `mcp serve --stdio/--http` | active | - |
| C7 | Engineering baseline: workspace, lints, deny, vet, CI, guidelines pointer + project overlay, fake router, test tiers | active | rust-guidelines core S9/S10/S12/S13 |

## Open assumptions (announced defaults)
| assumption | default | rationale | reversible |
|---|---|---|---|
| Rust version | `rust-version = "1.99.1"`, no rust-toolchain.toml; local `rustup update stable` (installed is 1.99.0) | user said 1.99.1; guideline forbids toolchain pin | yes |
| HTTP client | reqwest 0.13 (rustls, no default features) - same line rmcp-server-kit already depends on | avoid dup; kit pins reqwest 0.13.4 normal dep | yes |
| Crypto | md-5, sha2 0.11, sha3, hmac 0.13, argon2 0.6 (shared with kit), base64 0.23 (shared), getrandom/rand 0.10 | ndw2/ndw4 | yes |
| All crates `publish = false` | application workspace; semver-checks N/A (documented) | not a library product | yes |
| License | MIT OR Apache-2.0 | matches user's crates | yes |
| CI host | GitHub Actions | user's repos on GitHub | yes |
| Secrets input | env var / `password_file` (perm-checked 0600 on unix) / interactive prompt for CLI; no OS keychain | avoid platform deps; prior art used keychain | yes |
| WireGuard private keys | migrated as-is | keeps peers working (public key unchanged) | yes |
| User account password hashes | NOT copied when realm (model) differs; plan marks `needs-input`, applied with `password plain` from operator-provided secret | `password md5` = md5(login:realm:password) per ndw2 handshake; realm is model-specific (UNVERIFIED but derived) | yes |
| ns3 secrets (wpa-psk, ppp password, iapp key) | carried over verbatim | ns3 is a reversible device-independent scramble (public decoder has no device key) | yes |
| Migration apply mode | `parse` command line-by-line in dependency order under `system configuration fail-safe timer`; whole-file upload (put + /fui + reboot) only as explicit `raw-restore` for same-model | per-command status, incremental, rollback | yes |
| MCP transports | stdio + Streamable HTTP (both from rmcp-server-kit) | desktop + server deployments | yes |

## Findings (cited)
- RCI = official HTTP API; CLI Reference Appendix B: "every 'a b c' command corresponds to /rci/a/b/c ... Command Reference gives you a complete picture of all RCI resources" (/tmp/opencode/research/cli/cli_5.1.txt:29976-30146; PDF https://storage.googleapis.com/docs.help.keenetic.com/cli/5.1/en/cli_manual_kn-1811.pdf, 948 pages). XML /ci deprecated.
- Resource kinds: settings (GET/POST/DELETE), actions (POST; GET only for show/readonly), background processes (POST start, GET poll -> `continued:true`, DELETE stop; session-bound) (cli_5.1.txt:29992-30018; rci-tools docs/RCI_API.md:79-180,1264-1503).
- POST body free-form JSON, empty `{}` required, arrays ordered, parent params apply to nested; response mirrors input; ~1 MB body limit; show rc / show sc prefixes; `no: true` negation; status array {status: message|warning|error, code, ident, message} (RCI_API.md:591-1751).
- Auth: GET /auth -> 200 (already auth) or 401 + `WWW-Authenticate: x-ndw2-interactive realm=.. challenge=.. session_id=.. session_cookie=..`, X-NDM-Realm, X-NDM-Challenge, random cookie name, Max-Age=300 sliding; ndw2 password = sha256(challenge + md5hex(login:realm:password)) (rci-tools docs/AUTH.md:18-96; keenetic-mcp docs/rci-api.md:34-92; keenetic-rci src/auth.rs test vector admin/"Keenetic Ultra"/secret/0123..cdef -> 9071bc0a...3632).
- ndw4 (5.2): SCRAM-SHA3-512 + Argon2id (p=1, 64-byte), POST to `endpoint=` phases, replies base64 JSON in X-NDM-Data header, salt 16 bytes, iter 1..64, memcost 8..262144 KiB, mutual auth (rci-tools docs/AUTH.md:98-195; packages/core/src/session-manager/auth-protocol/x-ndw4-interactive/*).
- 5.2: token auth header `X-NDMA-TKN`; x-ndw2 to be removed; tokens "forever" only so far; no login->token exchange; browser-redirect bootstrap planned (forum.keenetic.ru topic 29419, 2026-07-22 NDMS dev Q&A).
- Digest auth works only through HTTP Proxy service (port 79 / KeenDNS rci.* name) with `http-proxy` user tag (support.keenetic.com 55035).
- User tags: cli, manager, readonly, http-proxy, http, ... (cli_5.1.txt:28620+). 5.2 Beta 2: readonly restricted from IPsec secrets.
- Traps: wrong field = silent `{}`; errors inside HTTP 200; config branch doesn't echo writes; names with `/` must be passed as `name` param not path; show/netfilter is text; large outputs (show/ip/nat >100KB) (keenetic-mcp docs/rci-api.md:94-241).
- Config files: GET /ci/startup-config.txt, /ci/running-config.txt (octet-stream CLI text); POST 405 (keenetic-mcp docs/rci-api.md:262-271). Upload: POST /rci/ {"put":{"filename":"flash:startup-config","size":N}} -> port; POST /fui/ multipart port+Filedata; then system reboot (forum.keenetic.ru topic 20762, single source - UNVERIFIED).
- `parse` command: POST /rci/ {"parse": "<cli line>"} (keenetic-mcp src/router/segments.ts:386; Toxblh/Keenetic-Manager src/api/keenetic_dns.py:261).
- Fail-safe: `system configuration fail-safe timer reboot <60..86400>`, `... keep-alive`, `... commit` (commits + stops), `... rollback` (revert + reboot); timer persists across reboots (cli_5.1.txt:26955-27052). keenetic-mcp describes it as connectivity watchdog (3 min) - semantics partially UNVERIFIED; design keeps alive explicitly and commits at end, so either semantics rolls back on lockout.
- startup-config: header `! $$$ Model:`, `! $$$ Version:`, `! $$$ Agent:`, `! $$$ Md5 checksum:`; `!` lines ignored; quoted args; indentation = context; secrets `ns3 <b64>` (reversible scramble, decoder github.com/evgenart/zyxel_scramble_ns3, PowerShell ConvertFrom-NS3); user `password md5`/`password nt` hashes (cli_5.1.txt:25120; superuser 1249064; habr 850532).
- Capability detection: `show version` -> `ndw.components`, `ndw.features`, hw_id, model, release (keenetic-mcp docs/rci-api.md:133-151; CLI App. B example).
- Per-model CLI PDFs: `https://storage.googleapis.com/docs.help.keenetic.com/cli/<ver>/en/cli_manual_<model>.pdf` (5.1 exists for kn-1811; 5.2 not published yet).
- rmcp-server-kit 3.21.1: `McpServerConfig::new(..).with_auth(..).with_rbac(..).validate()?` + `serve(config, || handler)`; `serve_stdio(handler)` (unauthenticated, process boundary); `ServerConfig`/`ObservabilityConfig`/`RbacConfig` TOML sections composed into app root with `deny_unknown_fields`; `ApiKeyEntry`, `generate_api_key`, `RateLimitConfig`, `RoleConfig`, `ArgumentAllowlist::new_required`; RBAC host-scoping reads tool argument named `host` (src/rbac.rs:1959-1995); `ToolHooks`/`with_hooks` (src/tool_hooks.rs); `current_role()`. rmcp 3.x `#[tool_router]`/`#[tool(annotations(read_only_hint, destructive_hint, idempotent_hint, open_world_hint))]` (rmcp-macros-3.4.0 src/tool.rs:155-242). Kit deps: reqwest 0.13.4, argon2 0.6, base64 0.23, sha2 0.11, hmac 0.13, rand 0.10, secrecy 0.10.
- Guidelines: core S9 profile verbatim (RUST_GUIDELINES.md:1586-1847), deny.toml (2740-2779), CI list (3023-3031), test tiers (3280-3292), overlays http-services + mcp-servers; projects get overlays/projects/<project>.md + pointer file.

## Decisions (with rationale)
- D1 Single cargo workspace `crates/*` + `xtask` (catalog generator, lint completeness check).
- D2 RCI path segments built only from validated identifiers; names with `/` always sent as `name` param in POST body.
- D3 Catalog is generated offline by `cargo xtask catalog` from CLI-reference PDF text and committed as data (`catalog/<version>/<model>.json` + provenance sha256); runtime never needs the PDF.
- D4 MCP tool naming `kcc_<domain>_<verb>`; every tool that targets a router takes `host` (router profile name) so kit RBAC host-globs work.
- D5 Writes default to unsaved running-config; `kcc_config_save` separate; destructive actions (reboot, factory-reset, firmware/components commit, media format, erase) need `confirm` + server flag `allow_destructive`.

## Scope IN
C1-C7 as above.

## Scope OUT (Must NOT have)
- No firmware modification, no on-router agents/Entware installs, no cloud (Keenetic Cloud/RMM) integration.
- No XML /ci API (deprecated).
- No pushing to external repos (rust-guidelines overlay PR) without explicit approval.

## Open questions (owner-decisions) - ANSWERED 2026-11-05
1. Front-end: CLI + MCP + **Web UI; the Web UI is the MAIN feature**, MCP secondary.
2. Coverage: catalog-driven generic engine + curated typed domains (in Web UI and MCP).
3. Distribution: linux x86_64/aarch64 musl, macOS aarch64, windows x86_64 + OCI image.
4. Hardware: spare test routers available -> env-gated live read+write e2e incl. migration rehearsal.
5. Web stack: Rust SSR (askama) + htmx + SSE, vendored pinned assets, strict CSP, no npm.
6. Web login: local accounts (Argon2id) + roles admin/operator/viewer shared with MCP RBAC; cookie sessions + CSRF + login rate limit.
7. Languages: en, ru, uk, de, be, kk (Fluent) for Web UI and CLI messages.

## Decisions added after answers
- D6 Web UI mounted on the same listener via rmcp-server-kit `with_extra_router` (bypasses kit auth -> own session auth middleware, own rate limit via `with_extra_route_rate_limit`), CSP overridden via `SecurityHeadersConfig` to allow 'self' scripts/styles only.
- D7 One permission model (Read, Write, Save, Destructive, Migrate, Admin) -> roles; MCP RbacConfig generated from it + tool registry; web middleware uses it directly; router scoping by profile-name globs (= kit `host`).
- D8 State dir (atomic JSON files, 0600/0700): routers, ui users, audit.jsonl, backups, migrations; router secrets encrypted at rest with XChaCha20-Poly1305 key from KCC_MASTER_KEY_FILE (auto-created 0600).
- D9 xtask is a separate cargo workspace (keeps PDF/tooling deps out of product graph) with an identical lint profile (checked).
- D10 Catalog source text via poppler `pdftotext -layout`; headings parsed by regex; per-group JSON files < 1 MB (large_include_file).
- D11 Migration flattens context blocks into full-path single CLI lines (e.g. `interface Bridge0 ip address ...`) preserving startup-config order; management-address changes applied last with reconnect under fail-safe.
- D12 Router outbound policy (LAN-adapted SSRF): admin-only router profiles, scheme http/https, no redirects, allowlisted networks (RFC1918, CGNAT, ULA, link-local v6 opt-in, KeenDNS suffixes) configurable; metadata IPs always denied; TLS verify or SHA-256 pin, never skip.

## Approval gate
status: approved (owner answers 2026-11-05 count as approval)
next: on approval -> run scaffold without --draft-only, Metis gap analysis, append todos, TL;DR last, then dual review (Momus + Oracle).
critics: metis/momus/oracle verified alive 2026-11-05 (probe sessions ses_e54f78912ffei0k26mYeT1fF7D, ses_e54f78323ffeAkpJOX9ItKxVc6, ses_e54f77e66ffeHPqrSdfbeb4lQY). librarian/explore unavailable (ProviderModelNotFoundError kimi-for-coding-highspeed) - research done directly.

## Metis gap analysis (session ses_e54e7f4d6ffeFX3rMDSOKcWJQk, 2026-11-05) - folded into the plan
- B1 ledger stale -> plan Scope rewritten (U1-U6, IS-1..13, GAP-1..14).
- B2 fail-safe/persistence conflict -> todo 53 live probe, `persists_immediately` catalog flag, SafetyNet (fail-safe or scheduled reboot), save/commit re-check last-change, startup recovery of armed timers.
- B3 PDF extractability unproven -> bookmarks via lopdf, poppler via podman fallback, >=98% gate + bbox fallback, overlay.toml, facts-only catalog.
- M4 old source firmware -> todo 27. M5 preflight (factory-fresh, DPN/EULA, address collision) -> todo 30. M6 parse vs boot -> deferred retry, ns3 plaintext fallback, residual list.
- M7 concurrency -> per-file locks + per-router leases (18, 20). M8 Argon2 cost -> semaphore 1 + derived-key cache; token experimental.
- M9 kit vs Web UI -> /ui prefix, own timeout/body limits/SSE cap, derived allowed_origins, CSP without upgrade-insecure-requests on HTTP.
- M10 sessions -> todo 34 additions. M11 own authz -> todo 45 handler checks, two-router scope, stdio viewer.
- M12 secrets -> catalog secret flags, key in config dir, Windows DACL. M13 privacy -> no telemetry history, redact_clients_in_mcp, PRIVACY.md.
- M14 scale -> IS-13 (2 in-flight, 15 s/60 s poller). M15 state schema -> todo 18. M16 lint vs macros -> todo 52 spike.
- M17 unrunnable criteria -> tooling bootstrap in todo 1, macOS/Windows verified on first CI run. M18 wrong router -> KCC_LIVE_ALLOW_SERIAL.
- Minor 19-25 -> overlay deviation + UPSTREAM, role map, RustCrypto generation, licensing/notices, Netcraze alias, read-only router credential, audit verify.

## Review ledger
### Round 1 (r1-20261105T100607Z-f924ed60, plan sha 2fff0641...)
- momus (ses_e54d35cb0ffeHAO5Czqp5lGHSP): changes_requested. Blockers frozen into ledger:
  - L1 todo 22 used `fail-safe commit` after management changes (persists everything) -> fixed: SafetyNet::disarm (`no system configuration fail-safe timer`), commit only as explicit save; todo 53 probe 7b verifies disarm keeps unsaved.
  - L2 todo 30 preflight required reachable source URL for File/Backup sources -> fixed: preflight per MigrationSource + offline-source tests.
  - L3 todo 14 method validation blocked background GET poll / DELETE stop -> fixed: Background kind rules + start/poll/cancel test.
  - note: todo 48 `/login` -> `/ui/login` (fixed); todo 35 screenshot paths -> /ui (fixed).
- oracle (ses_e54d32144ffeLtj0tgsDZ2yovM): inconclusive - its own descriptor-chain read failed (`openat ... Not a directory`); no review performed. Round 1 closed; plan changed -> fresh round 2 with a provided reader script /tmp/opencode/read_plan.py.
### Round 2 (r2-20261105T100948Z-a05171b6, plan sha 60fd8720...)
- momus: OKAY - L1, L2, L3 closed, no new eligible blockers.
- oracle (ses_e54cffe17ffelkcsSrKCPCVW7w, pid 20357): REJECT with 8 new eligible blockers (first real review), all fixed with smallest edits:
  - O1 F4 omitted IS-13 -> F4 covers IS-1..13 (+ note: F1 covers todos 1-53).
  - O2 todo 5 in W2 with its dependency 2 -> moved to W3.
  - O3 todo 41 needed todo 30 (restore via migration engine) -> depends on 30, moved to W9.
  - O4 todo 50 used F3 screenshots (cycle) -> uses todos 35-44 Playwright evidence.
  - O5 max_result_bytes 64 KiB vs IS-9 32 KiB -> 32768 + default assertion.
  - O6 todo 45 tested a tool from todo 46 -> helper unit test in 45, real tool test in 46.
  - O7 CLI had no principal/permission/audit -> `cli:<OS user>` identity, [cli] role/scope, tests, IS-8 row includes 47.
  - O8 MCP resources not scope-checked -> resources/list filter + resources/read enforcement.
  - note: catalog "summary" removed from 14/42 (no manual prose).
- Plan changed -> both lanes re-run in round 3.
### Round 3 (r3-20261105T101523Z-c5d8c7e4, plan sha ac5487f0...)
- momus: OKAY (L1-L3 closed, no regressions; note: IS-8 evidence column lacked task-47 log -> added).
- oracle: REJECT, O1-O7 closed, O8 open (resource scope enforcement lacked an acceptance test) -> added list/read deny + allow tests to todo 45. No new blockers. Progress made (7 closures) -> round 4.
### Round 4 (r4-20261105T101647Z-669499f6, plan sha e8a51ac1...)
- momus: OKAY, no notes. oracle: OKAY, O1-O8 closed, no new blockers.
- Final live-plan validation (descriptor-relative no-follow read via /tmp/opencode/read_plan.py) matched the approved digest e8a51ac1c5c191919b349fdc7688496b20657cecb3e90743a7093ce639712a6b.
- Convergence: 4 rounds; ledger L1-L3 (momus) + O1-O8 (oracle) all closed; non-blocking notes folded.

## Scope change 2 (owner, 2026-11-05)
Owner: "1. 4.3+ fw also supported; monitoring/metrics (Prometheus exporter if metrics exposed via RCI); retrieve logs and forward to Loki/Elastic. 2. Binary must block sudo / unnecessary privileges like krb-passwd-ui. 3. Support rootless Podman with seccomp profile."
Research: 4.3 and 5.0 CLI manuals exist (cli/4.3/en/cli_manual_kn-1811.pdf 200, kn-3810 200; 5.2 not published); `show log` is a background process (POST once:false + GET polls + DELETE; once:true snapshot; records keyed by numeric id - forum topics 10914, 14215); rmcp-server-kit `metrics` feature + `with_metrics_handle` for custom collectors (unauthenticated loopback listener); krb-passwd-ui @43f6697 privileges.rs (refuse any UID 0, clear held caps, no_new_privs, verify, Threads==1, ports<1024 refused, no process::Command) and seccomp procedure (strace-derived allowlist, ERRNO default, clone3 ENOSYS, getsockopt outage lesson, podman flags).
Folded: IS-14..17, GAP-15..19, U7; todos 54 (Prometheus exporter + dashboard + alerts), 55 (log collection + Loki/Elasticsearch/OpenSearch/stdout sinks), 56 (privilege floor), 57 (hardened image, rootless Podman, seccomp); firmware 4.3/5.0 folded into 6, 11-14, 17, 21, 27, 31; 47 healthcheck + prologue; 48 prologue; 49 split (binaries only); 50 MONITORING/FIRMWARE docs; 51 container + 4.3 live paths; F1/F3/F4 updated; waves W10 {49, 57}, W11 {50, 51}.
Adopted defaults (owner may veto): RCI log pull only (no syslog listener); no disk spool (loss counted); no root/elevation override; metrics opt-in on 127.0.0.1:9090; per-client metrics off; Elasticsearch data stream `logs-keenetic.syslog-default`, OpenSearch dated index.
Metis delta pass skipped (dual review covers the delta); review cycle restarted (new ledger).
- s2r1 launch -01 failed to start (old sessions expired: 'Task not found'); relaunched as fresh sessions -02.
### Scope-2 round 1 (s2r1, plan sha bc4dc6e7...)
- momus (ses_e54af2cfbffeQS5qvBMMv4H0V8): REJECT -> ledger S1 healthcheck HTTP vs TLS listener (fixed: config-derived https + pinned configured cert); S2 container metrics bound to loopback unreachable via publish (fixed: container bind 0.0.0.0 + allow_non_loopback, host-loopback publish, host scrape test); S3 metrics poller contradicted IS-13 (fixed: shared Poller subscription, no processes/NAT polling, test). Notes fixed: clone3 rationale, IS-11 evidence row.
- oracle (ses_e54aef032ffeTtfsx2LqEXBNPd): REJECT -> ledger S4 firmware 5.0 not exercised (fixed: KN-1811 5.0.12 profile, detection, 5.0 view + 5.1-only rejection, IS-1 row); S2 duplicate. Note fixed: ES data stream template doc.
- Ledger frozen: S1-S4.
### Scope-2 round 2 (s2r2, plan sha 7aa298cb...)
- oracle: OKAY (S1-S4 closed, ES note closed). momus (fresh ses_e54a3eef1ffezuEOpdjwayD1TV): OKAY, S1-S4 closed; note: container health commands lacked `--config /etc/kcc/kcc.toml` -> applied (2-token edit). Plan changed after approval -> confirmation round s2r3.
### Scope-2 round 3 (s2r3-20261105T110015Z-477651e9, plan sha b7ff0ab5...)
- momus: OKAY. oracle: OKAY. Final live-plan validation (descriptor-relative no-follow read) matched b7ff0ab51a680959bf0f8be3ae363956bca5b45bd73c742019997f8edfda5d61.

## Owner clarification 3 (2026-11-05): "the only real test unit we have is 5.1+, 4.3 - just assumptions based on documentation"
Folded: support tiers (HardwareVerified = HARDWARE_VERIFIED const, initially 5.1; DocumentationBased = 4.3 LTS, 5.0), 4.3/5.0 fake profiles marked documentation-derived, tier badge (UI), tier in CLI `info` and MCP `kcc_router_info`, audited acknowledgement for migrations onto documentation-based targets (todos 30/43), FIRMWARE.md tiers + equality test, todo 51 records exercised firmware and `live-skip` for 4.3/5.0, IS-1 text + Success row, TL;DR decision line. Confirmation review s3r1.
### Clarification-3 round 1 (s3r1, plan sha 1ebda894...)
- momus: OKAY (note: FIRMWARE.md must distinguish configured tier from completed live verification -> applied in todo 50).
- oracle: REJECT -> ledger T1 ack_documentation_tier unreachable via MCP/CLI (fixed: typed MCP arg + CLI flag + refusal/audit tests in 46/47); T2 todo 50 parallel with 51 which may change HARDWARE_VERIFIED (fixed: 50 depends on 51, W12). Ledger frozen: T1-T2.
### Clarification-3 round 2 (s3r2-20261105T110731Z-999b0a91, plan sha a079839c...)
- momus: OKAY (T1, T2 closed). oracle: OKAY (T1, T2 closed). Final live-plan validation matched a079839c2a52dbd8cd1cbfd02c96d763aae9f41e464d3092424c30df7f2d279a.

## Owner answers 4 (2026-11-05)
- Migration only old router -> new clean router on the same or newer firmware (no downgrades). Folded: `TargetFirmwareOlder` refusal (todo 27, also restores/presets), clean-target warning `target_not_clean` (todo 29, wizard 43), IS-5 text.
- Live migration rehearsal: file source -> owner's single 5.1.x unit (KCC_LIVE_SOURCE_FILE; todos 31, 51, env contract).
- Test unit firmware 5.1.x: ndw4/token stay experimental, live auth matrix ndw2 only.
- New feature: presets (named settings-group snapshots captured from router/backup/file, applied one-to-one) covering all 10 suggested groups (DoH/DoT + DNS filtering, DNS records + domain routing, policies, static routes, firewall, VPN client tunnels, Wi-Fi, system/services baseline, router users, schedules); direct copy = transient preset; one-to-one only (no multi-target, no export/import). Folded: IS-18, GAP-20, todos 58 (engine), 59 (UI), 60 (MCP + CLI), matrix/waves (W9 += 58, W10 += 59, 60), 50/51 deps, F1/F3/F4, success row, TL;DR. WireGuard keys regenerated by default (adopted default).
- s4r1 launch -01 failed (sessions expired); relaunched fresh as -02.
### Owner-answers-4 round 1 (s4r1, plan sha ccdddee2...)
- momus (ses_e5485b2f6ffeQ33XsoyGFKNJue): REJECT -> P1 todo 31 matrix expected success onto older firmware (fixed: refusal assertion); P2 todo 60 dry-run forbade target inventory reads (fixed: reads allowed, zero writes).
- oracle (ses_e54858503ffemmiSp3YLBwhwS2): REJECT -> P3 transient/plan/job/wizard state not encrypted (fixed + state-dir scan test); P4 source-router scoping for presets/transients/backups unspecified/untested (fixed + tests); P5 CLI finalization missing (fixed: interactive choice, required --finish non-interactive, `preset finish`, tests); P6 Web preview secrets (fixed: redacted preview, Reveal audited, serialized scan test). Notes applied: 58 depends on 45; 57 traces a `kcc copy` path and depends on 58; router-side WG key generation, public key only; TL;DR WireGuard line qualified.
- Ledger frozen: P1-P6.
### Owner-answers-4 round 2 (s4r2, plan sha c678195a...)
- momus: OKAY (P1-P6 closed); notes: 57's `kcc copy` trace needs 60 (same wave) -> moved the in-container copy run to todo 51; todo 60 "without touching the target" wording -> fixed. oracle: OKAY (P1-P6 closed). Plan changed -> confirmation round s4r3.
### Owner-answers-4 round 3 (s4r3-20261105T113752Z-1db302cb, plan sha 8db86d11...)
- momus: OKAY. oracle: OKAY. Final live-plan validation matched 8db86d1160def4f4892f4407c6fa9094f1b2ca41dca92e89bb932c4ee3376a3b.
