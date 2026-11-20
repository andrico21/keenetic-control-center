# kcc-entware - Work Plan

## TL;DR (For humans)
**Who this is for and what changes for them:** You, managing your Keenetic and Netcraze routers from kcc. Today kcc knows nothing about Entware, the add-on package system you put on a USB drive. Afterwards, the Web page, the command line and (when you allow it) an AI assistant can show whether Entware can run on a router, set it up from scratch, change its settings, and, for routers you opt in, install and remove Entware packages and start or stop its services.

**What you'll get:**
- An Entware view per router: whether it is possible, which drive and settings it uses, which drives are suitable, and the right installer for the router's processor.
- A guided setup: install the needed router components (one reboot), pick a drive, let the router download and install Entware, and confirm from the router's own log that this attempt finished. Saving the router configuration stays a separate, explicit step.
- Settings changes with read-back, a "prepare drive" action (wipe and make it ext4), and warnings where a change can cut DNS for the whole household or would remove the drive Entware lives on.
- For routers you opt in: package and service management over a secured SSH connection that only ever runs a fixed set of commands, never a free shell.

**Why this approach:**
- The router's own management interface can configure Entware but cannot run anything inside it, so packages and services need SSH. That SSH access is locked down: one key per router, the router's identity pinned after you confirm its fingerprint, the root password typed once and never stored, every SSH action treated as destructive, and kcc's key line edited without touching your other keys.
- Everything is tested against a simulated router and a simulated Entware SSH server that behaves like Entware's real service scripts, so no real router is touched; you can run the real-hardware checks yourself later.

**What it will NOT do:**
- No free shell, no file editing on the router beyond kcc's own key line, no custom installer addresses, and no storing of the Entware password.
- No Entware actions from the AI assistant unless you switch them on, and never the SSH key setup over the assistant channel.
- No automatic saving of router settings, and no copying of Entware settings to another router during migration.

**Effort:** XL
**Risk:** Medium - a new SSH dependency and a new root-access trust boundary, mitigated by host-key pinning, typed commands, opt-in and Destructive-only access, all proven against fakes.
**Decisions to sanity-check:**
- Every SSH action needs the Destructive permission, reads included (your choice).
- The SSH library is russh with the ring backend; it brings 67 new crates, one of them a pre-release (`ssh-key` 0.7.0-rc), and one accepted duplicate (`num-bigint`).
- Entware settings are no longer copied by migrations and presets (today they are, which can switch off DNS on a router without Entware).
- Turning DNS override on or off runs under the router's fail-safe timer, which protects kcc's own access to the router; the warning dialog is what protects the household.
- While Entware's "chroot" mode is on, kcc refuses SSH management, because that mode hides the paths kcc relies on.
- The project rules gain two short clauses that allow SSH to Entware under these limits.

Your next move: start execution with `$ulw-execute kcc-entware` after the CI-fix task is finished. Full execution detail follows below.

---

> TL;DR (machine): XL, medium risk; 21 todos in 10 waves + F1-F4; Option 1 (RCI: Entware status, guided setup job with per-attempt log verification, OPKG settings, media initialize, catalog risk classes, migration skip) and Option 2 (crate kcc-ssh on russh+ring: async policy admission, pinned ed25519 host key by type, single-use bound probe tickets, sealed per-router key, closed typed command set with specified scripts tested under /bin/sh, rc.func `check` semantics, chroot refusal, Destructive-only, opt-in; orchestration in kcc-domain), surfaces Web/CLI/MCP (toolsets `entware`, `entware-ssh`, off by default), fake router + rc.func-faithful fake Entware SSH server, e2e/seccomp, ignored live suites, docs; D-LATEST/D-VET.

## Scope
### Affected user and ideal state
**Affected user:**
- **U1 router owner/admin** (Web UI main, CLI): today cannot see or manage Entware from kcc; uses the router UI and an SSH client by hand. After: sees status, sets Entware up end to end, changes settings, and (opt-in) manages packages and services from kcc.
- **U2 AI assistant over MCP** (possibly prompt-injected): today has no Entware tools. After: gets them only in toolsets the owner enables; every SSH tool needs `allow_destructive` and `confirm: true`; it never sees a password, a private key or raw SSH output.
- **U3 operator of `kcc serve`/the container**: after: a new outbound SSH path that obeys the outbound policy, the seccomp profile and the CI gates.
- **U4 household members**: after: DNS override and removing or wiping the Entware drive never happen without a warning naming the effect; migrations no longer copy Entware DNS settings to routers without Entware.
- **U5 maintainers/the worker**: everything testable without hardware; the owner runs live suites later.

| Row | Statement | Reason |
| --- | --- | --- |
| IS-1 | U1 sees per router: Entware possible or not (and why), OPKG/ext components installed or available, configured disk/initrc/timezone/chroot/dns-override, eligible drives, CPU architecture and the matching installer, and whether the DNS filter engine depends on Entware | visibility before any change |
| GAP-1 | No Entware read model, view, CLI or MCP read exists | U1 must use the router UI |
| IS-2 | U1 sets Entware up end to end from kcc: missing components installed by the commit routine inside the setup job, drive chosen (optionally initialized to ext4 beforehand), `opkg disk <drive>:/ <installer>` run, success proven from log lines of this attempt and a read-back, ending with "unsaved, save explicitly" | the core task |
| GAP-2 | No setup flow, no drive initialize action, no install verification | manual multi-tool procedure today |
| IS-3 | U1 changes chroot, timezone, initrc, dns-override and removes Entware with catalog validation, the correct risk class (Write / Management / Destructive), read-back and audit; never saved implicitly | project rules (b), (c), workflow |
| GAP-3 | No planners; the catalog classes `opkg disk`/`opkg initrc` and `media initialize` too low and `opkg dns-override` as Write | root code execution, data loss and household DNS are under-classified |
| IS-4 | U4 is protected: DNS override asks with a household-DNS warning and runs under the fail-safe (which protects kcc's access); eject and initialize of the Entware drive need a second, explicit acknowledgement on every surface; migrations and presets skip opkg lines | household DNS and data |
| GAP-4 | Migration copies unmatched `opkg` lines (default copy, `crates/kcc-migrate/src/rules.rs:460-469`, documented at `:236-238`); no warnings anywhere | DNS loss on targets |
| IS-5 | U2 gets Entware tools only in toolsets `entware` / `entware-ssh` (off by default); SSH tools are destructive-hinted, hidden in read-only mode, need `allow_destructive` + `confirm: true`, return parsed values only; no probe, bootstrap, re-pin or revoke over MCP | prompt-injection safety, password never through the model provider |
| GAP-5 | No Entware tools or gating tests | |
| IS-6 | (Option 2) U1 manages packages (list, upgradable, update, install, remove, upgrade) and services (list, status, start, stop, restart, log) only through a closed typed command set; every argument validated by a token grammar and router listings; SSH only to policy-admitted addresses, key auth only, pinned ed25519 host key, per-router opt-in, refused while chroot is on, Destructive for every operation, writes read back with Entware's real `check` semantics | root shell risk, owner decision D-SSHPERM |
| GAP-6 | kcc has no SSH transport or Entware operations | |
| IS-7 | (Option 2) Enrolment is robust: two-step bootstrap with a single-use probe ticket bound to router, port and actor, fingerprint confirmation enforced on the second connection, an `authorized_keys` rewrite that keeps every other line byte for byte, pending/active state, refused and audited host-key changes, explicit re-pin and revoke, local wipe and a notice on router removal, re-bootstrap after a router host change or a lost key | half-done states must never leave silent trust or delete the owner's keys |
| GAP-7 | No key, pin, ticket or enrolment state exists | |
| IS-8 | No password, private key or SSH output reaches logs (russh's own `log` records included), audit, errors, Debug, Web/CLI/MCP results or the model provider; package/service output is parsed into typed values | rule (d), D-H1 |
| GAP-8 | No secret handling exists for SSH material | |
| IS-9 | Every behaviour is tested without hardware (fake router opkg state, install log and media initialize; fake Entware SSH server faithful to `rc.func`, with faults; the rendered enrolment scripts executed by `/bin/sh` in a temp directory); owner-run live suites exist, `#[ignore]`d, behind the live env contract | rule (g); the worker never sets `KCC_LIVE_*` |
| GAP-9 | No fakes or live suites for Entware | |
| IS-10 | Docs, six locales, CHANGELOG, generated MCP docs, AGENTS crate map, project overlay, container/seccomp, CI and supply chain are correct and green, dependencies at the latest version past the 3-day cooldown | standing rules D-LATEST, D-VET |
| GAP-10 | None of it covers Entware or SSH today | |

### Must have
- **Read before any Rust change, in order:** `docs/rust-guidelines/RUST_GUIDELINES.md`, `overlays/domains/http-services.md`, `overlays/domains/mcp-servers.md`, `overlays/projects/keenetic-control-center.md` (AGENTS.md). No `#[allow]`; `#[expect(lint, reason = "...")]` on the narrowest item only.
- **Precondition:** the CI-fix task the owner already handed out (Windows compile error, arm64 seccomp, Ubuntu disk, macOS schedule, pins, Dependabot PRs) is finished and the latest CI and Container runs on `master` are green before todo 1 starts. If not, stop and report.
- **Owner decisions (binding):**
  - **D-SCOPE:** Option 1 (Entware over RCI) and Option 2 (packages/services over SSH), both in this plan.
  - **D-SSHLIB:** `russh` with `default-features = false, features = ["ring"]` (no aws-lc C build), resolved at intake to the newest version past the 3-day cooldown (on 2026-11-19 that is 0.65.1; 0.65.2, published 2026-11-16, becomes eligible three days after its publish time). Accept the required pre-release `ssh-key` 0.7.0-rc and a deny/clippy duplicate entry for `num-bigint` (0.4.8 via `x509-parser`/`der-parser`, 0.5.x via russh).
  - **D-BOOTSTRAP:** kcc generates one ed25519 key per router (sealed). Bootstrap: the admin types the Entware root password once (never stored); kcc shows the host key fingerprint, the admin confirms, kcc installs its public key and pins the host key; afterwards key-only; a changed host key is refused until an admin re-pins.
  - **D-SSHPERM:** every SSH operation, reads included, needs `Permission::Destructive` (Web/CLI confirmation; MCP `allow_destructive` + `confirm: true`).
  - **D-OVERLAY (follows from D-SCOPE):** the project overlay gains clauses (a') and (b') exactly as written in todo 1.
  - **D-LATEST / D-VET / D-DELIVERY / D-NODEPLOY:** as in previous plans: latest versions past the cooldown; `cargo vet` imports plus targeted `cargo vet add-exemption <crate> <version> --criteria safe-to-deploy`, never `certify`, never blanket `regenerate exemptions`; one commit per todo on `master`; no backward compatibility is required.
- **Adopted defaults (reversible):**
  - **Crate placement:** transport, admission use, host-key check, limits and the closed command set in the new crate `crates/kcc-ssh`; sealed key, enrolment record and probe tickets in `kcc-app` (the state layer; it stores the pin as strings and does not depend on kcc-ssh); enrolment and operation orchestration in `crates/kcc-domain/src/entware/ssh/` (kcc-domain already depends on kcc-app, `crates/kcc-domain/Cargo.toml:10`, and owns the RCI reads the SSH flows need); kcc-domain also gains the internal crates `kcc-ssh = { version = "0.1.0", path = "../kcc-ssh" }` and `kcc-telemetry = { version = "0.1.0", path = "../kcc-telemetry" }` (internal crates are never `{ workspace = true }`; pattern `crates/kcc-app/Cargo.toml:18`; kcc-telemetry depends only on kcc-app and kcc-rci, so no cycle); kcc-telemetry gains `pub fn parse_records_now(router: &str, response: &Value) -> Result<ParsedLog, ParseError>` in `crates/kcc-telemetry/src/logs/parser.rs` (path `kcc_telemetry::logs::parser::parse_records_now`; `logs.rs` has only `pub mod parser`, no re-exports) that calls `parse_records` with its own local `now` (`crates/kcc-telemetry/src/logs/service.rs:310` pattern), so kcc-domain needs no `chrono` (which stays used only by kcc-telemetry, as the `RUSTSEC-2026-0543` ignore reason in `deny.toml` and `.cargo/audit.toml` states); kcc-app never depends on kcc-domain or kcc-ssh.
  - Settings are read with `show_rc({"opkg":{}})` (pattern `crates/kcc-domain/src/dns.rs:389-399`); there is no `show opkg` command (CLI manual text `catalog/.cache/5.1/kn-1011.txt:30964-31200`).
  - **Installer table** (closed; HEAD 200 on 2026-11-19): `aarch64` -> `https://bin.entware.net/aarch64-k3.10/installer/aarch64-installer.tar.gz`, `mipsel` -> `https://bin.entware.net/mipselsf-k3.4/installer/mipsel-installer.tar.gz`, `mips` -> `https://bin.entware.net/mipssf-k3.4/installer/mips-installer.tar.gz`. `show version` `arch` = "aarch64" selects aarch64 automatically; "mips" (reported by little- and big-endian models alike, e.g. KN-1010 MT7621 reports "mips", `crates/kcc-testkit/fixtures/KN-1010/show.json:10`) requires an explicit `mipsel` or `mips` choice; any other value refuses. No free URL.
  - **Disk argument:** `<label>:/` when `show media` gives a non-empty label unique among media, else `<uuid>:/` when a `uuid` field exists, else refused; `storage:/` (internal UBIFS) only when the user explicitly chooses it, with the router's own warning text ("UBIFS partition is not tested").
  - **Drive preparation:** `media <name> initialize ext4` (manual 3.102: wipes the partition table and creates swap + ext4; runs in the background; 5.01+; present only in the 5.1 catalog). Offered only when the router's catalog has the path and `show media` lists `ext4` in `initialize-supported`; completion is polled from `show media` (ext4 partition present) for up to 10 minutes.
  - **Component ids** `opkg` and `ext` (unverified on hardware; the manual's only example is `ntfs`, `kn-1011.txt:3299`). If `components list` has no entry with that name, the setup refuses with a message naming "Open Package support" / "Ext filesystem support"; the live probe (todo 19) records the real names.
  - **Install verification:** `logging::read_log` (`crates/kcc-domain/src/logging.rs:74`) returns the router's JSON records keyed by id (`crates/kcc-domain/src/diagnostics.rs:164-190`); parse them with `kcc_telemetry::logs::parser::parse_records_now` (wrapping `parse_records`, `crates/kcc-telemetry/src/logs/parser.rs:44-64`; `LogRecord { id, component, process, message, .. }`, `types.rs:8-27`; `component` and `process` come only from the text prefixes `name[pid]: ` and `X::Y: `, `parser.rs:173-193`, and a record needs a `[Mon DD HH:MM:SS] ` text prefix or a `time` field, `parser.rs:71-99`). Before sending `opkg disk`, record the highest record id as the baseline; afterwards consider only records with a higher id whose `component` is `Opkg::Manager` or whose message contains `Opkg::Manager: ` (the real router may prefix `ndm: `, unverified); success when a message contains `[5/5] "Entware" installed!`; failure when a message contains `doinstall` and `Error`, `error` or `Exec format error`, or when no success marker arrives within 15 minutes; then read back only `opkg disk <disk>` (the URL is not compared).
  - **Risk classes:** `opkg disk`, `opkg initrc`, `media initialize` Destructive (root scripts from the drive; data wipe); `opkg dns-override` Management (fail-safe bracket protecting kcc's access; it disables port 53 of the DNS proxy, manual 3.141); `opkg chroot`, `opkg timezone` Write.
  - **Chroot:** `opkg chroot` makes init scripts run with root `/opt` (manual 3.139), so kcc's absolute paths would not exist in SSH sessions. Every flow that opens an SSH connection (probe, bootstrap, re-pin, revoke and every operation) reads `opkg chroot` over RCI first and refuses with `EntwareError::ChrootEnabled` while it is on; local-only flows (`disable`, `set_enabled`, `set_port`) never contact the router; enabling chroot warns that SSH management stops working.
  - **SSH:** default port 222 (Keenetic docs: 222 when the router's SSH server component is installed, else 22), configurable per router 1..=65535; connect 5 s, auth 10 s, read commands 30 s, mutations 600 s (all injectable through a `Timeouts` value for tests); at most one session per router and 4 in total; 256 KiB output cap per command (abort, report truncated); keepalive 15 s; inactivity timeout 60 s; preferred host-key algorithms `ssh-ed25519` only.
  - **Service actions follow Entware `rc.func`** (https://raw.githubusercontent.com/Entware/rtndev/master/entware-opt/files/rc.func): actions `start|stop|restart|check|kill|reconfigure`; any other prints usage and exits 1. kcc's "status" uses `check`: exit 0 with `alive.` in the output -> Running, exit 1 with `dead.` -> Stopped (match the words as substrings; rc.func wraps them in ANSI colour codes). Action exit codes: `start` 0 ok (also when already running), 8 `ServiceDisabled` (`ENABLED` is not `yes`), 255 failed; `stop` (= `check && stop`) 0 ok, 1 already stopped (ok); `restart` (= `check >/dev/null && stop; start`) 0 ok, 8 `ServiceDisabled` (the service is now stopped; report it), 255 failed; anything else `UnexpectedOutput`. After every action the `check` read-back decides the outcome.
  - **SSH state** for both profile sources lives in the state directory under `<state>/router-ssh/` and is NOT a `CredentialKind` (the router credential flows - `credential_path`, plaintext migration, edit rollback - stay untouched): private key `<id>.key.sealed` (AD `router:<id>:ssh-key`, OpenSSH private text as `SecretString`); enrolment record `<id>.sealed` (AD `router:<id>:ssh-state`) holding `{enabled, port, state: pending|active, router_host, host_key (OpenSSH public line), fingerprint (SHA256:base64), enrolled_at, enrolled_by}`; probe tickets `<id>.ticket.sealed` (AD `router:<id>:ssh-ticket`), single-use (consumed atomically by rename-then-read), 5-minute expiry, bound to router id, port and actor. Every use compares `router_host` with the router's current URL host; on a difference the record becomes `Pending` with the pin cleared and operations are refused until a new probe and bootstrap (covers both `kcc.toml` and stored routers without registry hooks). Router removal calls `entware_ssh::forget(state, id)`.
  - **Service log** = router `show log` records (parsed with `parse_records_now`) whose `process` equals the service's base name (`S51dropbear` -> `dropbear`), read over RCI in kcc-domain and passed through the shared masker unless the principal holds `RevealSecrets`; no file is read over SSH.
  - TDD for every behaviour; a regression test names the todo in a doc comment.
- **i18n:** every new user-visible string is a key in all six locales (en, ru, uk, de, be, kk); regenerate `crates/kcc-i18n/src/keys.rs` with `cargo xtask i18n-gen` after rebasing, never hand-merge it.
- **Generated artifacts:** `docs/MCP_TOOLS.md` (`cargo xtask gen-tool-docs`), `keys.rs`, the seccomp profile (two-trace union procedure, todo 18) are regenerated, never hand-edited.
- **Async:** every new or changed async fn carries a `// cancel-safe:` or `// NOT cancel-safe:` comment; `cargo xtask cancel-safety` passes. An SSH mutation dispatched to the router is never reported as stopped by cancellation.
- **Capacity:** 4 cores, 15 GB RAM: at most 2 cargo builds at once (a `podman build` counts as one), each worktree with its own target directory on `/`, never under `/tmp`. Track free space on `C:` as before.
- **Docs and CHANGELOG:** each behaviour-changing todo adds its `Unreleased` CHANGELOG line and fixes the docs it contradicts in the same commit; todo 20 sweeps and audits.

### Must NOT have (guardrails, anti-slop, scope boundaries)
- No raw shell, PTY, interactive session, port forwarding, agent forwarding, SFTP or free command text over SSH; no command text from any input.
- No file editing on the router other than kcc's single `kcc:<router-id>`-marked line in `/opt/etc/dropbear/authorized_keys` (every other line kept byte for byte) and the `chmod` of that file and its directory.
- No storing, logging or auditing of the Entware password; no change of the Entware root password by kcc.
- No package or service names outside the grammars in todo 7; no "list available packages"; no SSH log or file reading.
- No custom installer URL; no `opkg object-group fqdn` support (listed in docs/BACKLOG.md); no `media partition format` (whole-drive `initialize` only).
- No probe, bootstrap, re-pin or revoke over MCP.
- No automatic configuration save; no opening of port 222/22 on the WAN; no firewall changes.
- No new crate other than `russh` and what it brings; no `[patch]`, no git sources; no feature beyond `ring` on russh.
- No change to the audit entry format or hash rule; no weakening of any existing control.
- No edits to `docs/rust-guidelines/RUST_GUIDELINES.md`, `overlays/domains/*`, `.omo/plans/keenetic-control-center.md`, `.omo/plans/kcc-review-remediation.md`, `.omo/plans/kcc-review-fixes.md`, `.omo/reviews/**`.
- No `KCC_LIVE_*` by the worker; live suites are written and compiled, never run.
- No fixed sleeps in tests; await the observable event with a bounded timeout; time-dependent SSH tests inject short `Timeouts` instead of pausing tokio time over real sockets.

## Verification strategy
> Zero human intervention - all verification is agent-executed.
- Test decision: TDD (red test first, named in a doc comment with the todo number) with `cargo test` (unit in-module, integration in each crate's `tests/`), fake router `kcc-testkit::FakeRouter`, fake Entware SSH server `kcc-testkit::FakeEntwareSsh` (todos 6-7), `/bin/sh` execution of the rendered enrolment scripts (todo 7), Playwright for Web (F3).
- Evidence: `.omo/evidence/task-<N>-kcc-entware.log` (`set -o pipefail; { <cmds>; } 2>&1 | tee <file>`), screenshots `.omo/evidence/F3-entware-<area>.png`.
- **Gate G0 (every todo):** `cargo +nightly-2026-10-03 fmt --all -- --check`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`; `cargo xtask allow-gate`; `cargo xtask profile-eq`; plus `cargo xtask i18n-check` (strings), `cargo xtask cancel-safety` (async), `cargo xtask assets-check` (templates/assets).
- **Gate G1 (todo 21, F2):** G0 plus `cargo deny check`, `cargo deny --manifest-path xtask/Cargo.toml check`, `cargo audit`, `cargo audit -f xtask/Cargo.lock`, `cargo vet --locked`, `cargo vet --locked --manifest-path xtask/Cargo.toml`, `cargo machete crates xtask`, `cargo xtask lint-completeness`, `taplo fmt --check`, per-library default-feature clippy and test (including `kcc-ssh`), MSRV `cargo +1.100.0 build --workspace --all-features`, the xtask workspace commands, `python3 .omo/reviews/kcc-full-review-2026-11-15/check_dep_reqs.py`, `(cd docs/rust-guidelines && sha256sum -c SHA256SUMS)`.
- **Baseline:** record `cargo test --workspace --all-features` totals at the start commit in `.omo/evidence/task-0-kcc-entware.log`.
- **Web template changes (todos 12, 15):** capture golden HTML of the touched pages before and diff after; every difference is intended and named in the commit body.
- **Generated docs:** `cargo xtask gen-tool-docs` runs before staging; the check `git diff --exit-code HEAD -- docs/MCP_TOOLS.md` runs after the commit.

## Execution strategy
### Parallel execution waves
> Target 5-8 todos per wave. Fewer than 3 (except the final) means you under-split.

Todo numbers are identifiers, not order; execute by the dependency matrix. Parallel todos run in separate worktrees with at most 2 concurrent cargo builds. Todos that add message keys regenerate `keys.rs` after rebasing. Landing: rebase onto `master`, re-run G0 on the rebased tree, fast-forward `master` to the single commit, then push to `origin master` with `git -c credential.helper='!gh auth git-credential' push origin master` (no force, no token in any file).

| Wave | Todos | Theme |
| --- | --- | --- |
| W0 | 1 | policy and docs groundwork (no cargo) |
| W1 | 2, 3, 5, 6 | catalog risk classes, Entware read model + fake router state, migration skip rules, SSH dependency intake + admission API + fake Entware SSH server |
| W2 | 4, 7 | Entware write planners, drive initialize and guards; SSH transport and closed command set |
| W3 | 8, 10 | SSH key, enrolment and ticket state; guided setup job |
| W4 | 9, 12, 13, 14 | enrolment lifecycle; Option 1 surfaces (Web, CLI, MCP) |
| W5 | 11 | SSH package/service operations and service log |
| W6 | 15, 16, 17 | Option 2 surfaces (Web, CLI, MCP) |
| W7 | 18, 19 | e2e SSH leg + seccomp + container; owner-run live suites |
| W8 | 21 | latest-version recheck and G1 |
| W9 | 20 | docs sweep and CHANGELOG audit |
| Final | F1-F4 | verification wave |

Every wave holds fewer todos than the template's 5-8 target (W1 and W4 have 4, W6 has 3, W2, W3 and W7 have 2, W0, W5, W8 and W9 have 1) because each contains exactly the todos whose dependencies are met at that point; merging waves would break the dependency matrix, and splitting the todos further would sever work that shares one test setup.

### Dependency matrix
| Todo | Depends on | Blocks | Can parallelize with |
| --- | --- | --- | --- |
| 1 | - | 2, 3, 5, 6 | - |
| 2 | 1 | 4 | 3, 5, 6 |
| 3 | 1 | 4, 9 | 2, 5, 6 |
| 5 | 1 | 21 | 2, 3, 6 |
| 6 | 1 | 7 | 2, 3, 5 |
| 4 | 2, 3 | 10 | 7 |
| 7 | 6 | 8 | 4 |
| 8 | 7 | 9 | 10 |
| 10 | 4 | 11, 12, 13, 14 | 8 |
| 9 | 3, 8 | 11 | 12, 13, 14 |
| 12 | 10 | 15 | 9, 13, 14 |
| 13 | 10 | 16, 19 | 9, 12, 14 |
| 14 | 10 | 17 | 9, 12, 13 |
| 11 | 9, 10 | 15, 16, 17 | - |
| 15 | 11, 12 | 21 | 16, 17 |
| 16 | 11, 13 | 18, 19 | 15, 17 |
| 17 | 11, 14 | 19 | 15, 16 |
| 18 | 16 | 21 | 19 |
| 19 | 13, 16, 17 | 21 | 18 |
| 21 | 5, 15, 18, 19 | 20 | - |
| 20 | 21 | F1-F4 | - |

## Todos
> Implementation + Test = ONE todo. Never separate.
<!-- APPEND TASK BATCHES BELOW THIS LINE WITH edit/apply_patch - never rewrite the headers above. -->
- [ ] 1. Policy groundwork: overlay clauses for SSH to Entware, crate maps, backlog of unverified facts
  What to do / Must NOT do:
  - In `docs/rust-guidelines/overlays/projects/keenetic-control-center.md` (the project overlay; editable) add after rule (a) the clause **(a')**: "SSH to Entware connects only to an address the router profile's host resolves to and that the outbound policy admits for that host, on that router's configured SSH port. When the host is admitted only through `allowed_suffixes`, the address must also be inside `allowed_networks`. Host-key pinning is mandatory; no agent, jump host, port forwarding or SFTP." After rule (b) add **(b')**: "Every SSH command is one variant of a closed, typed Entware command set in `kcc-ssh`; arguments are validated by token grammars and by router listings from the same session; no command text comes from input." Note both with the date 2026-11-19 and the reason "owner decision D-SCOPE (Option 2)". Add `kcc-ssh` to the overlay's crate list ("The project" -> "Workspace", lines 12-15).
  - In `AGENTS.md` "Crate map" add `kcc-ssh`: "SSH transport to Entware: policy-admitted pinned TCP, pinned host key, closed typed command set".
  - In `docs/BACKLOG.md` add a section "Entware: unverified on hardware" listing: component ids `opkg`/`ext` and whether `components list` shows components that are not installed; real `show media` fields (label, uuid, `initialize-supported`); whether `show rc` returns `opkg` settings in the shape the fake uses; the install log markers on 5.x; SSH port 222 vs 22; `/opt/etc/dropbear/authorized_keys` path and permissions; availability of `grep`, `mv`, `chmod`, `touch`, `mkdir`, `printf` in the Entware exec environment (kcc sets PATH explicitly); init.d actions and exit codes per `rc.func` (`check`, 8 when disabled, 255 on failure); the raw `show log` record shape and the `component`/`process` prefixes Entware services and the installer produce (e.g. whether installer lines carry an `ndm: ` prefix); that `opkg chroot` breaks kcc's paths (kcc refuses while it is on); whether dropbear kills the command when the channel closes; NetcrazeOS parity. Each line names the live test in todo 19 that checks it.
  - Must NOT: edit vendored files or code.
  Closes: GAP-10 (policy part)
  Parallelization: Wave W0 | Blocked by: - | Blocks: 2, 3, 5, 6 | Can parallelize with: -
  References: `docs/rust-guidelines/overlays/projects/keenetic-control-center.md:6-60` (project, rules (a)-(i)); `AGENTS.md` crate map; `docs/BACKLOG.md`; `.omo/drafts/kcc-entware.md` (decisions, findings).
  Acceptance criteria (agent-executable): `(cd docs/rust-guidelines && sha256sum -c SHA256SUMS)` exits 0 (vendored files untouched); `cargo test -p kcc --test docs` passes; `git diff --name-only HEAD~1` lists exactly the overlay, `AGENTS.md` and `docs/BACKLOG.md`; F1 reads the clauses against this todo's text.
  QA scenarios: happy - `set -o pipefail; { (cd docs/rust-guidelines && sha256sum -c SHA256SUMS) && cargo test -p kcc --test docs && git diff --name-only HEAD~1; } 2>&1 | tee .omo/evidence/task-1-kcc-entware.log` (after the commit); failure - the docs test and checksum run before the edit are captured at the top (they must already pass, proving the edit changes only prose).
  Commit: Y | docs(policy): allow typed SSH to Entware under pinned, policy-admitted limits
  Recommended task executor category: writing - policy and documentation text only

- [ ] 2. Catalog risk classes for Entware and drive-initialize commands
  What to do / Must NOT do:
  - In `catalog/overlay.toml` `[[destructive]]` paths add `"opkg disk"`, `"opkg initrc"` and `"media initialize"` (two words: `path_matches` compares word counts, `crates/kcc-catalog/src/runtime.rs:449-457`) with the reason extended by: "opkg disk mounts a drive and runs its init scripts as root; opkg initrc chooses the root init script; media initialize wipes the partition table". Mirror them in `DESTRUCTIVE_PATHS` (`crates/kcc-catalog/src/runtime/data.rs:99-113`). Also add the two paths that `DESTRUCTIVE_PATHS` already has but `overlay.toml` lacks (`system configuration fail-safe timer`, `system configuration fail-safe keep-alive`, `data.rs:104-105`); `overlay.toml` is documentation, so no class changes.
  - Add `"opkg dns-override"` to `MANAGEMENT_PATHS` (`crates/kcc-catalog/src/runtime/data.rs:133`) with a doc comment: "disables TCP and UDP port 53 of the DNS proxy; clients and kcc may lose name resolution".
  - Tests in `crates/kcc-catalog/src/runtime/rule_tests.rs`: `risk("opkg disk") == Destructive`, `risk("opkg initrc") == Destructive`, `risk("opkg dns-override") == Management`, `risk("opkg chroot") == Write`, `risk("opkg timezone") == Write` for 5.1, 5.0 and 4.3; `risk("media initialize") == Destructive` for 5.1. Add a test that parses `catalog/overlay.toml` and compares its `[[destructive]]` paths with `DESTRUCTIVE_PATHS` as sets; the existing `every_safety_pattern_matches_an_embedded_command` (`rule_tests.rs:24-42`) must stay green (no dead pattern).
  - CHANGELOG `Unreleased`: raw and explorer `opkg disk`/`opkg initrc`/`media initialize` now need Destructive; `opkg dns-override` runs under the fail-safe.
  - Must NOT: change any other path's class.
  Closes: GAP-3
  Parallelization: Wave W1 | Blocked by: 1 | Blocks: 4 | Can parallelize with: 3, 5, 6
  References: `catalog/overlay.toml:5-7`; `crates/kcc-catalog/src/runtime.rs:120-140` (`risk`); `crates/kcc-catalog/src/runtime/data.rs:99-150`; `crates/kcc-catalog/src/runtime/rule_tests.rs:17-60`; CLI manual `catalog/.cache/5.1/kn-1011.txt` 3.102, 3.139-3.144; `catalog/5.1/media.json` (`media initialize`).
  Acceptance criteria: the new tests fail before and pass after; `cargo test -p kcc-catalog --all-features` and G0 pass.
  QA scenarios: happy - `set -o pipefail; { cargo test -p kcc-catalog --all-features; } 2>&1 | tee .omo/evidence/task-2-kcc-entware.log` (includes `every_safety_pattern_matches_an_embedded_command` and the new mirror test); failure - the red run of the new risk tests (opkg disk classed Write) at the top of the log.
  Commit: Y | fix(catalog): Entware disk, init script and drive initialize are destructive, DNS override is management
  Recommended task executor category: quick - data tables and their tests

- [ ] 3. Entware read model and fake router Entware state
  What to do / Must NOT do:
  - New module `crates/kcc-domain/src/entware.rs` (+ `entware/` submodules), registered in `crates/kcc-domain/src/lib.rs` (module, `DomainId::Entware`, `registry()` descriptor with `read_ops` only and `write_ops: &[]` - todo 13 registers the write ops together with their CLI coverage, `required_components: &["usb","storage"]`).
  - Models (all `#[non_exhaustive]`, tolerant serde with an `extra` map): `EntwareSettings { disk: Option<String>, initrc: Option<String>, timezone: Option<TimezoneSetting /* Auto | Named(String) */>, chroot: bool, dns_override: bool }`; `EntwareStatus { possible: Possibility /* Possible | NoUsbOrStorage | UnsupportedArch(String) */, opkg_component: ComponentPresence /* Installed | Available | Missing */, ext_component: ComponentPresence, settings: EntwareSettings, drives: Vec<EligibleDrive>, initializable: Vec<String> /* media names whose initialize-supported contains ext4 */, arch: ArchResolution /* Aarch64 | MipsAmbiguous | Unknown(String) */, dns_filter_uses_opkg: bool }`; `EligibleDrive { media_id, disk_arg /* "<label>:/" or "<uuid>:/" */, label, filesystem, free_bytes }`; `Installer { Aarch64, Mipsel, Mips }` with `fn url(self) -> &'static str` returning exactly the three URLs in "Adopted defaults".
  - `read_settings(router)` via `router.client.show_rc(json!({"opkg":{}}))` and `configuration_tree()` (pattern `crates/kcc-domain/src/dns.rs:389-399`); `read_status(router)` combines `components::read_components`, `read_settings`, `storage::read_media` (ext2/ext3/ext4 eligible; disk argument rule; `initialize-supported` from `MediaVolume.extra`), `system::read_version` (`arch` from `Version.extra["arch"]`), `show version` `ndw.components` for usb/storage presence, and `dns::read_configuration` for `FilterEngine::Opkg` (`crates/kcc-domain/src/dns.rs:83-94`).
  - Fake router: add `opkg` leaf rules to `crates/kcc-testkit/src/cli_engine/rules.rs` (`opkg disk <disk> [<url>]`, `no opkg disk`, `opkg chroot`, `opkg dns-override`, `opkg initrc <path>`, `opkg timezone auto|<tz>` and their `no` forms) so they render into running-config text and `show rc`; make the fake's `components list` (`crates/kcc-testkit/src/components.rs:133-140`) return `{"name","installed":false}` rows for an available set that contains `opkg` and `ext`; give the synthetic media a `uuid`, an ext4 filesystem and `initialize-supported: ["default","ext4","ntfs"]` (`crates/kcc-testkit/src/fixtures/synthetic.rs:36-43`); keep KN-3810 without `storage` and NC-3013 without `usb`/`storage` (`fixtures/*/show.json:20-21`).
  - Tests (in `crates/kcc-domain/tests/entware.rs`, against `FakeRouter`): KN-1811 status = Possible, arch Aarch64, opkg/ext Available, one eligible drive with `<label>:/`; KN-1010 arch MipsAmbiguous; NC-3013 and KN-3810 possible = NoUsbOrStorage; after the fake applies `opkg disk X:/` and `opkg dns-override`, `read_settings` reports them; a media without label and uuid is not eligible; `dns_filter_uses_opkg` true when the fake DNS config selects the opkg engine; components tests still pass with the new available rows.
  - Must NOT: write anything to the router; hard-code installer URLs outside `Installer::url`.
  Closes: GAP-1, GAP-9 (fake router part)
  Parallelization: Wave W1 | Blocked by: 1 | Blocks: 4, 9 | Can parallelize with: 2, 5, 6
  References: `crates/kcc-domain/src/storage.rs:19-61`; `crates/kcc-domain/src/components.rs:24-91`; `crates/kcc-domain/src/system/models.rs:12-24`; `crates/kcc-domain/src/lib.rs:40,112,353,383`; `crates/kcc-domain/src/dns.rs:83-94,389-399`; `crates/kcc-testkit/src/cli_engine/rules.rs`; `crates/kcc-testkit/src/components.rs`; `crates/kcc-testkit/fixtures/*/show.json`; installer URLs (Adopted defaults).
  Acceptance criteria: the tests above fail before and pass after; `cargo test -p kcc-domain -p kcc-testkit --all-features`, `cargo test -p kcc --test cli_domain_writes`, `cargo test -p kcc-domain --test verification_coverage` and G0 pass.
  QA scenarios: happy - `set -o pipefail; { cargo test -p kcc-domain -p kcc-testkit --all-features && cargo test -p kcc --test cli_domain_writes && cargo test -p kcc-domain --test verification_coverage; } 2>&1 | tee .omo/evidence/task-3-kcc-entware.log`; failure - red runs of the status tests (module absent) at the top.
  Commit: Y | feat(domain,testkit): read Entware status and settings; fake router Entware state
  Recommended task executor category: unspecified-high - new domain module plus fake router grammar

- [ ] 4. Entware write planners, drive initialize and Entware drive guard
  What to do / Must NOT do:
  - In `crates/kcc-domain/src/entware.rs`: `plan_chroot(router, name, role, enabled)` (Write; when enabling, the plan carries `EntwareWarning::ChrootStopsSshManagement` that surfaces must show), `plan_timezone(router, name, role, TimezoneSetting)` (Write; `Named` must match `^[A-Za-z0-9_+\-/.:,<>]{1,64}$`, else `InvalidCliToken`), `plan_initrc(router, name, role, path, confirmed)` (Destructive; path matches `^/opt/[A-Za-z0-9._/\-]{1,200}$`, no `..`), `plan_dns_override(router, name, role, enabled)` (Management; surfaces add the household-DNS warning), `plan_remove(router, name, role, confirmed)` (`no opkg disk`, Destructive). Each validates against the catalog (`validate`, `crates/kcc-domain/src/planning.rs:15`), renders `no` with `negated` (`crates/kcc-domain/src/request_words.rs:51`) and adds a `VerificationSpec` that re-reads `show rc` `opkg` and compares the changed field (rule (c)).
  - In `crates/kcc-domain/src/storage.rs`: `plan_initialize(router, name, role, media, confirmed, entware_media, entware_acknowledged)` for `media <name> initialize ext4` (Destructive), mirroring `plan_eject` (`storage.rs:115-170`) and its `change_request`; refuse when the router's catalog lacks the path (`Validation`) or `media` is not a single token; a `wait_initialized(router, media)` helper polls `show media` until an ext4 partition appears (10 minutes). Do not add `initialize` to the storage `WRITES` descriptor here (todo 13 registers it with its CLI coverage).
  - Entware drive guard: add `entware::configured_media(router) -> Result<Option<String>>`, which reads `opkg disk` and resolves `<label>:/` or `<uuid>:/` to a media id through `storage::read_media` (`None` when unset, `storage:/` or unresolvable). `plan_eject` and `plan_initialize` take `entware_media: Option<&str>` and `entware_acknowledged: bool`; when the target media id equals `entware_media`, they return `DomainError::EntwareDriveInUse` unless acknowledged (new localized key in `domains.ftl`, six locales). Update every existing `plan_eject` caller in this todo so G0 stays green and the guard is never off: `crates/kcc-web/src/system_pages/storage_actions.rs:110`, `crates/kcc/src/cli/dom_net.rs:87`, `crates/kcc-mcp/src/domains/write/housekeeping.rs:124` (each calls `configured_media` and passes `entware_acknowledged = false`, so ejecting the Entware drive is refused with the localized message until todos 12-14 add the acknowledgement), and the test call sites `crates/kcc-domain/tests/storage.rs:41` and `crates/kcc-domain/tests/readback/storage.rs:12`.
  - Fake router: add the `media <name> initialize <preset>` rule to `crates/kcc-testkit/src/cli_engine/rules.rs`; the fake reports the media as ext4 after the third following `show media` read (no time dependence).
  - Tests (`crates/kcc-domain/tests/entware_writes.rs`, storage tests, `FakeRouter`): each planner's rendered line and read-back; invalid timezone/initrc refused before any request (fake request log empty); dns-override plan risk = Management; chroot-on plan carries the warning; remove/initrc without confirmation -> `ConfirmationRequired`; without Destructive -> `PermissionDenied`; eject or initialize of the Entware drive without acknowledgement -> `EntwareDriveInUse` (once with a label-based and once with a uuid-based `opkg disk`), with it -> planned; initialize on a 5.0 router -> `Validation`; read-back failure when the fake ignores the line -> verification error naming the field; existing Web/CLI/MCP eject tests still pass.
  - Must NOT: save configuration; add a free-form CLI line path.
  Closes: GAP-2, GAP-3, GAP-4
  Parallelization: Wave W2 | Blocked by: 2, 3 | Blocks: 10 | Can parallelize with: 7
  References: `crates/kcc-domain/src/storage.rs:62-170`; `crates/kcc-domain/src/dns/change.rs:25-62,172-178`; `crates/kcc-domain/src/lib.rs:216-275` (`ChangeOp`); `catalog/5.1/media.json` (`media initialize`); manual 3.102; todo 2 risk classes.
  Acceptance criteria: listed tests fail before and pass after; `cargo test -p kcc-domain -p kcc-web -p kcc -p kcc-mcp --all-features`, `cargo test -p kcc --test cli_domain_writes`, `cargo test -p kcc-domain --test verification_coverage`, `cargo xtask i18n-check` and G0 pass.
  QA scenarios: happy - `set -o pipefail; { cargo test -p kcc-domain -p kcc-web -p kcc -p kcc-mcp --all-features && cargo test -p kcc --test cli_domain_writes && cargo test -p kcc-domain --test verification_coverage && cargo xtask i18n-check; } 2>&1 | tee .omo/evidence/task-4-kcc-entware.log`; failure - red runs at the top.
  Commit: Y | feat(domain): Entware settings planners, drive initialize and Entware drive guard
  Recommended task executor category: unspecified-high - several planners with read-back and guards across four crates

- [ ] 5. Migrations and presets skip Entware settings
  What to do / Must NOT do:
  - Add `Reason::HardwareEntware` (`#[serde(rename = "migration-reason-hardware-entware")]`, `key()` returning that id) to `crates/kcc-migrate/src/rules/reason.rs` (pattern of `HardwareLed`, `reason.rs:43,101`); map it in `localized_reason` (`crates/kcc-migrate/src/report.rs:248-279`) to `keys::MIGRATE_REASON_SKIP_HARDWARE` (no new Fluent key); add `Reason::HardwareEntware` to the hardware arm of the exhaustive match in `crates/kcc-web/src/migrate_wizard/reasons.rs:132-140` (next to `HardwareInterface`).
  - In `crates/kcc-migrate/rules/rules.toml` add `skip-hardware` rules (pattern `rules.toml:86-94`) `entware-disk` `opkg disk **`, `entware-chroot` `opkg chroot`, `entware-dns-override` `opkg dns-override`, `entware-initrc` `opkg initrc **`, `entware-timezone` `opkg timezone **`, `entware-object-group` `opkg object-group **`, each `reason_key = "migration-reason-hardware-entware"`.
  - Tests in `crates/kcc-migrate/tests/` (existing rule tests style): a source config with all six lines yields `skip-hardware` with the new reason for each and none in the planned commands; a preset capture excludes them; the rule file still loads (an unknown reason would fail with `RuleError::InvalidToml`).
  - CHANGELOG: migrations and presets no longer copy Entware settings. `docs/MIGRATION.md`: add the six lines to the skipped list.
  - Must NOT: change other rules' order or dispositions.
  Closes: GAP-4
  Parallelization: Wave W1 | Blocked by: 1 | Blocks: 21 | Can parallelize with: 2, 3, 6
  References: `crates/kcc-migrate/rules/rules.toml:1-120`; `crates/kcc-migrate/src/rules.rs:236-238,460-469`; `crates/kcc-migrate/src/rules/reason.rs:19-130`; `crates/kcc-migrate/src/report.rs:248-279`; `crates/kcc-web/src/migrate_wizard/reasons.rs`; `docs/MIGRATION.md`.
  Acceptance criteria: tests fail before (lines copied) and pass after; `cargo test -p kcc-migrate -p kcc-web --all-features`, G0 pass.
  QA scenarios: happy - `set -o pipefail; { cargo test -p kcc-migrate -p kcc-web --all-features; } 2>&1 | tee .omo/evidence/task-5-kcc-entware.log`; failure - red run showing `opkg dns-override` planned as copy.
  Commit: Y | fix(migrate): migrations and presets skip per-router Entware settings
  Recommended task executor category: quick - rule data, one reason variant, tests

- [ ] 6. SSH dependency intake, policy admission API and fake Entware SSH server
  What to do / Must NOT do:
  - Dependency: add `russh` to `[workspace.dependencies]` in the root `Cargo.toml` with `default-features = false, features = ["ring"]` at the newest version past the cooldown (plain `cargo add`/`cargo update` under `.cargo/config.toml`; never `CARGO_RESOLVER_INCOMPATIBLE_PUBLISH_AGE=allow`); write the requirement as the full locked version. Add `num-bigint` duplicate entries to `deny.toml` `skip` and `clippy.toml` `allowed-duplicate-crates` with reasons naming both dependents (`x509-parser`/`der-parser` and `russh`); add any other duplicate only if `cargo deny check` shows it, with a reason; update existing reasons that say `ring` comes only through rustls to name russh too. Run `cargo vet` with network: imported audits first, then targeted `cargo vet add-exemption <crate> <version> --criteria safe-to-deploy` for each crate no import covers (Windows-only crates included), named in the commit body; commit `supply-chain/imports.lock` changes; `cargo vet prune`.
  - kcc-rci: add `pub async fn admit_ssh(&self, router: &RouterUrl, port: u16) -> Result<Vec<SocketAddr>, RciError>` to `OutboundPolicy` (`crates/kcc-rci/src/outbound.rs`), reusing the private async resolution and `allows` (`outbound.rs:169-185,221`) and `never_admitted` (`outbound.rs:355`); when the host is admitted only through `allowed_suffixes`, keep only addresses inside `allowed_networks`; empty result -> `RciError::Policy`. Unit tests: IP in networks admitted; suffix-only public address refused; loopback refused unless `allow_loopback`; metadata addresses refused.
  - kcc-testkit: new module `crates/kcc-testkit/src/entware_ssh.rs` with `FakeEntwareSsh::spawn(config) -> (SocketAddr, Handle)` using `russh::server` (kcc-testkit must not depend on kcc-ssh): an ed25519 host key (replaceable through the handle to simulate a changed key), password `keenetic` by default (configurable), key auth against its in-memory `authorized_keys`, an `opkg` package database (installed, upgradable, installable), `/opt/etc/init.d/S*` services that follow `rc.func` exactly (actions `start|stop|restart|check|kill|reconfigure`; other actions print usage and exit 1; `check` -> exit 0 `alive.` / exit 1 `dead.`; `start` -> exit 8 when the service is disabled), counters (connections, auth attempts, commands), fault switches (hang, output > 256 KiB, no exit status, kill after N commands). In this todo the fake emulates the `opkg` and `init.d` command strings listed in todo 7 through a template matcher (fixed prefix, one POSIX-single-quoted argument where the template has one) and answers `127` for anything else; it prints `alive.`/`dead.` wrapped in the ANSI colour codes rc.func uses and returns the exit codes from "Adopted defaults" (start 0/8/255, stop 0/1, restart 0/8/255, check 0/1); todo 7 adds the enrolment commands. Expose it in the `kcc-fake-router` binary behind `--entware-ssh-port <port>` (`crates/kcc-testkit/src/bin/kcc-fake-router.rs`).
  - Tests: `crates/kcc-testkit/tests/entware_ssh.rs` drives the fake with a raw russh client: password auth, exec of `list-installed`, `check` semantics with ANSI output, start of a disabled service -> 8, stop of a stopped service -> 1, unknown command -> 127, host key swap visible.
  - Must NOT: enable russh default features; add `aws-lc-rs`; add any other new crate.
  Closes: GAP-6 (foundation), GAP-9 (fake SSH), GAP-10 (supply chain)
  Parallelization: Wave W1 | Blocked by: 1 | Blocks: 7 | Can parallelize with: 2, 3, 5
  References: scratch evidence `~/.cache/kcc-review/scratch-ssh` (67 new crates, `num-bigint` duplicate, licenses/sources ok); `deny.toml:25-60`; `clippy.toml:18-31`; `supply-chain/config.toml`; `crates/kcc-rci/src/outbound.rs:74-221,355`; `crates/kcc-rci/src/engine.rs:268-273`; russh `server` module, `client::connect_stream`; Entware `rc.func` URL (Adopted defaults).
  Acceptance criteria: `cargo deny check`, `cargo audit`, `cargo vet --locked`, `cargo machete crates xtask`, `python3 .omo/reviews/kcc-full-review-2026-11-15/check_dep_reqs.py` exit 0; `cargo tree -p russh -e features > .omo/evidence/task-6-russh-features.txt` then `! grep -q aws-lc .omo/evidence/task-6-russh-features.txt`; new tests pass; G0 passes; `cargo +1.100.0 build --workspace --all-features` passes.
  QA scenarios: happy - `set -o pipefail; { cargo deny check && cargo audit && cargo vet --locked && cargo machete crates xtask && python3 .omo/reviews/kcc-full-review-2026-11-15/check_dep_reqs.py && cargo tree -p russh -e features > .omo/evidence/task-6-russh-features.txt && ! grep -q aws-lc .omo/evidence/task-6-russh-features.txt && cargo test -p kcc-rci -p kcc-testkit --all-features && cargo +1.100.0 build --workspace --all-features; } 2>&1 | tee .omo/evidence/task-6-kcc-entware.log`; failure - before the deny entries, `cargo deny check` reports the `num-bigint` duplicate (captured at the top); the admission red tests.
  Commit: Y | build(deps,rci,testkit): russh intake, SSH address admission and fake Entware SSH server
  Recommended task executor category: deep-low - supply-chain intake plus a protocol fake, settled by reading the docs and the code

- [ ] 7. kcc-ssh: SSH transport and the closed Entware command set
  What to do / Must NOT do:
  - New crate `crates/kcc-ssh` (`publish = false`, `[lints] workspace = true`, workspace `rust-version`, crate docs) depending on `kcc-rci = { version = "0.1.0", path = "../kcc-rci" }` (internal crates use the path form, `crates/kcc-app/Cargo.toml:18`) and the external crates `russh`, `rand` (0.10, for key generation), `secrecy`, `zeroize`, `tokio`, `thiserror`, `tracing` as `{ workspace = true }`, with `tempfile = { workspace = true }` and `kcc-testkit = { version = "0.1.0", path = "../kcc-testkit" }` (the path form every other crate uses, e.g. `crates/kcc-app/Cargo.toml:37`; it is not a workspace dependency) as dev-dependencies.
  - Transport, pin enforced by type: `probe_host_key(addresses, Timeouts) -> HostKeyPin` connects and returns the ed25519 key without authenticating; `connect(PinnedTarget { addresses, pin: HostKeyPin, port }, Auth, Timeouts) -> Session` requires a pin in its signature (no `Option`); TCP connect to the admitted addresses with `tokio::net::TcpStream` then `russh::client::connect_stream`; `Config.preferred` host-key algorithms limited to `ssh-ed25519`; `check_server_key` compares the key byte for byte with the pin; non-ed25519 -> `SshError::UnsupportedHostKey`; mismatch -> `SshError::HostKeyMismatch { expected, actual }` (public fingerprints only); keepalive 15 s, inactivity 60 s; `Auth::Password(SecretString)` (exposed only at the russh call; rustdoc records russh's internal non-zeroized copy) and `Auth::Key(SecretString /* OpenSSH private */)`; `generate_ed25519() -> (SecretString, String /* "ssh-ed25519 <base64>" */)`.
  - Limits: `SshPool` with a per-router semaphore of 1 and a global semaphore of 4; per-command output cap 256 KiB (abort the channel, `SshError::OutputTruncated`); `Timeouts { connect: 5 s, auth: 10 s, read: 30 s, mutation: 600 s }` injectable; a missing exit status is `SshError::NoExitStatus`.
  - Closed command set `EntwareCommand`, the only way to build an exec string. Every rendered string starts with `PATH=/opt/bin:/opt/sbin:/bin:/sbin:/usr/bin:/usr/sbin; export PATH; ` and quotes every argument with POSIX single quotes (`'` -> `'\''`). With `A=/opt/etc/dropbear/authorized_keys`:
    - `ListInstalled` -> `/opt/bin/opkg list-installed`; `ListUpgradable` -> `/opt/bin/opkg list-upgradable`; `Update` -> `/opt/bin/opkg update`; `Install(p)` -> `/opt/bin/opkg install '<p>'`; `Remove(p)` -> `/opt/bin/opkg remove '<p>'`; `Upgrade(p)` -> `/opt/bin/opkg upgrade '<p>'`.
    - `ListServices` -> `for f in /opt/etc/init.d/S*; do if [ -f "$f" ]; then printf '%s\n' "${f##*/}"; fi; done` (exits 0 with an empty or unexpanded glob).
    - `Service(s, a)` -> `'/opt/etc/init.d/<s>' <a>` with `a` in `start|stop|restart|check`.
    - `AppendKey { line, router_id }` -> `umask 077 && mkdir -p /opt/etc/dropbear && touch A && { grep -v ' kcc:<router_id>$' A; [ $? -le 1 ] && printf '%s\n' '<line> kcc:<router_id>'; } > A.kcc && mv A.kcc A && chmod 700 /opt/etc/dropbear && chmod 600 A` (a `grep` failure other than "no lines" makes the group fail, so `A` is never replaced).
    - `RemoveKey { router_id }` -> `umask 077 && touch A && { grep -v ' kcc:<router_id>$' A; [ $? -le 1 ]; } > A.kcc && mv A.kcc A && chmod 600 A`.
    Both scripts end with ` || { rm -f A.kcc; false; }` so a failed run leaves no temp file. They use only POSIX sh features (verified under the CI hosts' `/bin/sh`; `printf` and `[` are shell builtins).
    The exact strings are `const` templates with unit tests comparing the rendered output.
  - Grammars: `PackageName` `^[a-z0-9][a-z0-9+._-]{0,63}$`; `ServiceName` `^S[0-9]{2}[A-Za-z0-9._-]{1,48}$`; `RouterId` the existing router id rule; the public key line must parse as `ssh-ed25519 <base64>`.
  - Parsers: `list-installed`/`list-upgradable` (`name - version[ - new]`; drop lines whose name fails `PackageName`), the service listing (keep only `ServiceName` matches), service `check` and action exit codes exactly as in "Adopted defaults" (substring match on `alive.`/`dead.`, ANSI codes ignored).
  - Errors carry no output text, password or key; `Debug` of key and password types is redacted.
  - Extend the fake (`crates/kcc-testkit/src/entware_ssh.rs`) to emulate `AppendKey`/`RemoveKey` semantics on its in-memory file in this todo's commit.
  - Tests in `crates/kcc-ssh/tests/` against `FakeEntwareSsh` (short injected `Timeouts`, no paused time over real sockets): probe returns the fake key; pinned connect succeeds; swapped host key -> `HostKeyMismatch` with zero auth attempts on the fake; package names `-f`, `a;b`, `a b`, `` `x` ``, `$(x)`, `'x'` refused before connecting (fake connection counter 0); unknown service name refused; output > 256 KiB -> `OutputTruncated`; hang -> read timeout; no exit status -> `NoExitStatus`; two concurrent sessions to one router serialize; `check` semantics and exit 8.
  - Script test: an inline `#[cfg(all(test, unix))] mod script_tests` in the command module (no public hook; the private renderer takes two crate-private parameters, the `/opt/etc/dropbear` prefix and the `PATH` value; production passes the fixed constants and the rendered-constant equality tests use them) renders `AppendKey`/`RemoveKey` with the prefix replaced by a temp directory and runs them with `/bin/sh -c` (`#[expect(clippy::disallowed_methods, reason = "test executes the rendered script under a real shell")]` on the one helper fn that both builds and runs the command - `Command::new("/bin/sh")...output()` inside it, returning the exit status and output - and nowhere else, because `clippy.toml` also disallows `.output()`/`.status()`): missing file -> created with one line, mode 600, dir 700; file with only the kcc line -> replaced, one line; file with two other keys -> both kept byte for byte plus the kcc line; re-run -> identical file; `RemoveKey` leaves the other keys byte for byte; `RemoveKey` on a missing file succeeds with an empty file; every case uses a hermetic `PATH` built from temp directories (never the host `PATH`, which can contain spaces or parentheses, e.g. WSL's `/mnt/c/Program Files (x86)/...`): the test creates the temp root with `tempfile::Builder` under a path without spaces (fail the test early with a clear message if the temp path contains whitespace or shell metacharacters), creates three directories, finding each host tool by checking the fixed absolute paths `/usr/bin/<tool>` then `/bin/<tool>` with `std::fs` (never through the host `PATH` or `which`): `<tmp>/tools` holds symlinks to the host's `mkdir`, `touch`, `mv`, `chmod` and `rm`; `<tmp>/grep` holds one symlink to the host's real `grep`; `<tmp>/stub` holds a file named `grep` containing `#!/bin/sh\nexit 2` with mode 0o755 set through `std::fs::set_permissions`. Happy cases run with `PATH=<tmp>/grep:<tmp>/tools`. Failure case 1 runs with `PATH=<tmp>/stub:<tmp>/tools` (grep exits 2); failure case 2 runs with `PATH=<tmp>/tools` (no grep, exit 127); in both failure cases, both scripts exit non-zero, `A` is byte-identical to before and no `A.kcc` remains. Fixture files end with a newline (`grep -v` adds one to a last line that lacks it). Windows CI compiles the crate without this module.
  - Must NOT: expose any function taking a command string; read files over SSH; use the system ssh binary.
  Closes: GAP-6, GAP-7, GAP-8, GAP-9
  Parallelization: Wave W2 | Blocked by: 6 | Blocks: 8 | Can parallelize with: 4
  References: todo 6 (`admit_ssh`, `FakeEntwareSsh`); russh `client::connect_stream`, `client::Handler::check_server_key`, `Config.preferred`, `Channel::exec`; `clippy.toml:16` (`disallowed-methods`); root `Cargo.toml` members/lints; Entware `rc.func`.
  Acceptance criteria: listed tests fail before and pass after; `cargo test -p kcc-ssh -p kcc-testkit --all-features`, `cargo clippy -p kcc-ssh --all-targets -- -D warnings`, `cargo xtask profile-eq`, `cargo xtask cancel-safety`, G0 pass; Windows compiles the test targets (`cargo check --target x86_64-pc-windows-gnu -p kcc-ssh --tests` when that target is installed, otherwise the F2 GitHub CI Windows job is the evidence).
  QA scenarios: happy - `set -o pipefail; { cargo test -p kcc-ssh -p kcc-testkit --all-features && cargo clippy -p kcc-ssh --all-targets -- -D warnings && cargo xtask profile-eq && cargo xtask cancel-safety; } 2>&1 | tee .omo/evidence/task-7-kcc-entware.log`; failure - red runs of the grammar, mismatch and script tests at the top.
  Commit: Y | feat(ssh): pinned SSH transport and closed Entware command set
  Recommended task executor category: deep-high - new trust boundary; correctness argued from invariants (pinning, grammar, scripts, limits)

- [ ] 8. SSH key, enrolment record and probe tickets in kcc-app
  What to do / Must NOT do:
  - New `crates/kcc-app/src/entware_ssh/` (kcc-app gains no dependency on kcc-ssh or kcc-domain; pins are strings): `state.rs` with `SshEnrolment { enabled, port, state: Pending|Active, router_host, host_key /* "ssh-ed25519 <base64>" */, fingerprint /* "SHA256:<base64>" */, enrolled_at, enrolled_by }` sealed at `<state>/router-ssh/<id>.sealed` (AD `router:<id>:ssh-state`, schema 1) and the private key at `<state>/router-ssh/<id>.key.sealed` (AD `router:<id>:ssh-key`, `SecretString`), using the existing seal/atomic-write helpers (`crates/kcc-app/src/secrets/`, `persist`); `load`/`save`/`load_key`/`save_key`; `set_port`/`set_enabled` create the record (Pending, no pin, port 222, enabled) when absent; `forget(state, id)` removes exactly `<id>.sealed`, `<id>.key.sealed`, `<id>.ticket.sealed` and any `<id>.ticket.redeem.*` (never by a bare `<id>*` prefix, which would also match router `<id>b`); `active(state, id) -> bool`.
  - `ticket.rs`: `TicketStore` at `<state>/router-ssh/<id>.ticket.sealed` (AD `router:<id>:ssh-ticket`) storing `{nonce, fingerprint, host_key, port, actor, expires_at}`; `issue(router, port, actor, host_key, fingerprint) -> nonce` (overwrites any older ticket); `redeem(router, port, actor, nonce, confirmed_fingerprint) -> (host_key, fingerprint)` consumes the ticket atomically (rename to `<id>.ticket.redeem.<random>`, then read and delete) and refuses when expired (5 minutes), when router, port or actor differ, when the nonce differs or when the fingerprint differs; a second redeem finds nothing.
  - Router removal: keep `RouterRegistry::delete`'s signature (`crates/kcc-app/src/registry.rs:674`). The two removal paths that wipe credentials also call `entware_ssh::forget`: Web `crates/kcc-web/src/router_delete.rs:63-75` and CLI `crates/kcc/src/cli/routers.rs:47-48` (the rollback deletes at `crates/kcc-web/src/routers.rs:126` and `crates/kcc/src/cli/router_secrets.rs:83` remove routers that never had SSH state and stay unchanged). Todos 15 and 16 call `active` before deleting to show the notice.
  - The router credential code (`CredentialKind`, `credential_path`, plaintext migration, edit rollback) stays unchanged.
  - Tests (`crates/kcc-app/tests/entware_ssh_state.rs` and existing Web/CLI removal tests): seal/open roundtrip of record and key; AD binding (a record sealed for router a cannot open as router b, as the key or as a ticket); `forget` removes all three; Web and CLI router removal remove exactly those names for the router and leave another router whose id starts with the same letters untouched; ticket: happy redeem, second redeem refused, expired refused, other actor refused, other port refused, other router refused, other nonce refused, wrong fingerprint refused; two concurrent redeems of one ticket -> exactly one succeeds.
  - Must NOT: store any password; put SSH settings in `kcc.toml` or `routers.json`; add a `CredentialKind`.
  Closes: GAP-7, GAP-8
  Parallelization: Wave W3 | Blocked by: 7 | Blocks: 9 | Can parallelize with: 10
  References: `crates/kcc-app/src/secrets/binding.rs`; `crates/kcc-app/src/persist.rs`; `crates/kcc-app/src/registry.rs:674`; `crates/kcc-web/src/router_delete.rs:49-80`; `crates/kcc/src/cli/routers.rs:40-55`; `crates/kcc/src/cli/principal.rs:56` (stable CLI actor).
  Acceptance criteria: tests fail before and pass after; `cargo test -p kcc-app -p kcc-web -p kcc --all-features` and G0 pass.
  QA scenarios: happy - `set -o pipefail; { cargo test -p kcc-app -p kcc-web -p kcc --all-features; } 2>&1 | tee .omo/evidence/task-8-kcc-entware.log`; failure - red runs at the top.
  Commit: Y | feat(app): sealed SSH key, enrolment record and single-use probe tickets
  Recommended task executor category: unspecified-high - state store, ticket store and removal hooks

- [ ] 9. Enrolment lifecycle: probe, bootstrap, re-pin, revoke, disable
  What to do / Must NOT do:
  - Add `kcc-ssh = { version = "0.1.0", path = "../kcc-ssh" }` to `crates/kcc-domain/Cargo.toml` `[dependencies]` in this todo (its first user).
  - `crates/kcc-domain/src/entware/ssh/enrol.rs` (kcc-domain depends on kcc-app and kcc-ssh), every function requiring `Permission::Destructive` on the router (`authorize`); the functions that open an SSH connection (`probe`, `bootstrap`, `repin`, `revoke`) first refuse with `EntwareError::ChrootEnabled` when `entware::read_settings` reports chroot on; mutating steps take the router write lease (`crates/kcc-app/src/workflow.rs:641-683`):
    - `probe(router, actor) -> ProbeTicket { nonce, fingerprint, host_key, expires_at }`: uses the record's port (222 when no record exists); `admit_ssh` + `probe_host_key`; `TicketStore::issue`; nothing is authenticated.
    - `bootstrap(router, actor, nonce, confirmed_fingerprint, password: SecretString)`: `TicketStore::redeem` (refuses on any mismatch); generates the key, saves the key (`save_key`) and the enrolment as `Pending` with the pin and `router_host` **before** contacting the router; connects with the pin, password auth, runs `AppendKey`; reconnects key-only with the pin and runs `ListInstalled` as a liveness check; saves `Active`. If the typed password equals `keenetic` and authentication succeeds, the result carries `default_password_in_use = true` (no extra login attempt is made).
    - Retry from `Pending` repeats the same idempotent steps (the marker replaces any old line).
    - `repin(router, actor, nonce, confirmed_fingerprint, password)`: same flow for a router whose host key changed.
    - `revoke(router, actor)`: key-only connect, `RemoveKey`, then local wipe; unreachable router -> refused with a message pointing at `disable`.
    - `disable(router, actor)`: local wipe only (`forget`), no RCI or SSH contact; result `entware_key_still_authorized = true`.
    - `set_port(router, actor, port)` and `set_enabled(router, actor, bool)`: local only.
    - Every SSH-opening use compares the enrolment's `router_host` with the current URL host; a difference sets the record to `Pending`, clears the pin and refuses until a new probe and bootstrap.
  - Audit events (existing audit API, no format change): `entware.ssh.probe`, `.bootstrap`, `.repin`, `.revoke`, `.disable`, `.hostkey_mismatch` with router, actor, outcome and public fingerprints only.
  - Tests (`crates/kcc-domain/tests/entware_enrol.rs`, both fakes, short injected timeouts): happy bootstrap -> one `kcc:<id>` line, state Active; second bootstrap -> still one line; kill after append (fake fault) -> state Pending; retry -> one line, Active; reused nonce, expired ticket, other actor, other port -> refused with zero password attempts on the fake; confirmed fingerprint differs -> refused with zero password attempts; host key swapped between probe and bootstrap -> `HostKeyMismatch`, zero password attempts, audit `hostkey_mismatch`; chroot on -> probe/bootstrap/repin/revoke refused before any connection, while `disable`, `set_port` and `set_enabled` still work locally; router unreachable -> `disable`, `set_port` and `set_enabled` still work locally; default password -> flag true; revoke removes the line; router host changed -> refused, record Pending, pin cleared; secrets: with a `tracing` subscriber at TRACE for all targets including `russh` (via the `log` bridge) capture output, then assert that the audit files, the captured log text and every error string contain neither the password bytes nor the private-key text.
  - Must NOT: accept the password from MCP; keep the password after the call (`SecretString`, zeroized).
  Closes: GAP-7, GAP-8
  Parallelization: Wave W4 | Blocked by: 3, 8 | Blocks: 11 | Can parallelize with: 12, 13, 14
  References: todos 3, 7, 8; `crates/kcc-app/src/audit.rs` (append API); `crates/kcc-app/src/permissions.rs:19-126`; `crates/kcc-app/src/workflow.rs:641-683`; `crates/kcc-web/Cargo.toml:44` (`tracing-log` bridge); Keenetic Entware docs (default `root`/`keenetic`, port 222/22).
  Acceptance criteria: tests fail before and pass after; `cargo test -p kcc-domain --all-features`, `cargo xtask cancel-safety`, G0 pass.
  QA scenarios: happy - `set -o pipefail; { cargo test -p kcc-domain --all-features && cargo xtask cancel-safety; } 2>&1 | tee .omo/evidence/task-9-kcc-entware.log`; failure - red runs of the half-done, ticket and mismatch tests at the top.
  Commit: Y | feat(domain): Entware SSH enrolment with confirmed host key, re-pin and revoke
  Recommended task executor category: deep-high - multi-step trust protocol with crash-safety invariants

- [ ] 10. Guided Entware setup job
  What to do / Must NOT do:
  - Add `parse_records_now` to `crates/kcc-telemetry/src/logs/parser.rs` (called as `kcc_telemetry::logs::parser::parse_records_now`, like `parse_records` in `crates/kcc-telemetry/tests/logs.rs:21`) with a unit test, and the `kcc-telemetry` dependency to `crates/kcc-domain/Cargo.toml`.
  - Extract the in-job body of `crates/kcc-domain/src/components/commit.rs:79-112` (apply the terminal request, wait in `restarted`, verify the staged components) into `pub(crate) async fn run_commit(context, registry, router, changes, request, staged, before: RouterInfo) -> Result<CommitProgress>` (`before` is the pre-restart router info the progress values need); `start` keeps its behaviour by calling it; existing components tests stay green.
  - `crates/kcc-domain/src/entware/setup.rs`: `start(jobs: &Arc<JobRunner>, registry: Arc<RouterRegistry>, workflow: Arc<Workflow>, router_name: String, actor: Actor, role: &Role, changes: ChangeSet, catalog: &Catalog, request: SetupRequest { drive: DriveChoice /* Media(disk_arg) | InternalStorage */, installer: Option<Installer>, confirmed })` (parameters mirror `components::start_commit_job`, `crates/kcc-domain/src/components.rs:299-318`, plus the workflow and actor) running as one write job (`JobTarget::Write`, pattern `commit.rs:45-117`), requiring Destructive.
  - Preflight (typed errors, before any request): Entware not possible; `configuration::read_last_change` (`crates/kcc-domain/src/configuration.rs:298-320`) reports `unsaved` or `fail_safe.active`; installer unresolved (`MipsAmbiguous` without a choice, `Unknown`); drive not eligible; `opkg disk` already set (remove first).
  - Steps with structured progress: (1) when `opkg` or `ext` is not installed, queue them and call `run_commit` inside this job, waiting for the restart (refuse when `components list` lacks the name); (2) only when step 1 ran a commit: after the restart drop the consumed set and call `workflow.begin(router, actor, role, false)` (`crates/kcc-app/src/workflow.rs:629-637`) for a fresh `ChangeSet`, and on `RouterBusy` fail with "components installed; run setup again"; when no commit was needed, keep using the passed `changes` (the lease is a file lock, `crates/kcc-app/src/persist.rs:311-315`, so a second `begin` while holding it would fail); record the `show log` baseline (highest record id, Adopted defaults); send `opkg disk <disk> <installer url>` as a NonRetryable request through the workflow (Destructive risk, backup, audit); (3) poll `logging::read_log` every 5 s for up to 15 minutes, considering only records with an id greater than the baseline (success and failure as in "Adopted defaults"); (4) read back `opkg disk` via `show rc`; (5) finish with `unsaved = true` and the message to save explicitly. Cancellation after step 2 never reports the install as stopped.
  - Fake router: on `opkg disk <d> <url>` with a known installer URL append log records through the fake's `insert_log` (`crates/kcc-testkit/src/lib.rs:740-744`) with increasing ids and the shape `{"message":{"label":"I","message":"[Nov 19 12:00:05] Opkg::Manager: /opt/etc/init.d/doinstall: [5/5] \"Entware\" installed!"}}` (one per subsequent `show log` read, `[1/5]`..`[5/5]`); service log fixtures use `"[Nov 19 12:00:05] dropbear[123]: ..."`; fault switches: no marker, an error record, `Exec format error`; a test helper to pre-seed stale marker and error records with lower ids.
  - Tests (`crates/kcc-domain/tests/entware_setup.rs`, `#[tokio::test(start_paused = true)]` as in `crates/kcc-domain/tests/diagnostics.rs:176`; progress driven by the fake's per-read appends): KN-1811 happy path (components commit with fake restart, fresh ChangeSet, install, read-back, `unsaved`); components already installed -> no commit; KN-1010 without installer choice -> refused before any request; with `Mipsel` -> URL equals the table; no marker -> verification error after the timeout; error line -> failure naming the step; stale `[5/5]` and stale error lines pre-seeded in the log -> ignored (the job waits for new lines and succeeds on the new marker); unsaved changes or an armed fail-safe -> refused; NC-3013 -> refused as not possible; another write lease taken during the restart -> "components installed; run setup again".
  - Must NOT: save the configuration; retry the install POST; accept any URL outside the table.
  Closes: GAP-2
  Parallelization: Wave W3 | Blocked by: 4 | Blocks: 11, 12, 13, 14 | Can parallelize with: 8
  References: `crates/kcc-domain/src/components/commit.rs:29-117`; `crates/kcc-domain/src/components.rs:299-318`; `crates/kcc-app/src/jobs.rs:413-443` (`RouterBusy` for a second write job); `crates/kcc-app/src/workflow.rs:629-683`; `crates/kcc-domain/src/configuration.rs:298-320`; `crates/kcc-domain/src/logging.rs:74`; `crates/kcc-domain/src/diagnostics.rs:164-190`; `crates/kcc-telemetry/src/logs/parser.rs:44`, `types.rs:8-27`; Keenetic install log (draft findings); todos 3, 4.
  Acceptance criteria: tests fail before and pass after; existing components tests pass; `cargo test -p kcc-domain -p kcc-testkit -p kcc-telemetry --all-features`, `cargo xtask cancel-safety`, G0 pass.
  QA scenarios: happy - `set -o pipefail; { cargo test -p kcc-domain -p kcc-testkit -p kcc-telemetry --all-features && cargo xtask cancel-safety; } 2>&1 | tee .omo/evidence/task-10-kcc-entware.log`; failure - red runs of the refusal, stale-line and no-marker tests at the top.
  Commit: Y | feat(domain,testkit): guided Entware setup job with per-attempt log verification
  Recommended task executor category: deep-low - job orchestration reusing the commit routine

- [ ] 11. Entware SSH operations and the service log
  What to do / Must NOT do:
  - `crates/kcc-domain/src/entware/ssh/ops.rs`: `packages_list`, `packages_upgradable`, `update`, `install(PackageName)`, `remove(PackageName)`, `upgrade(PackageName)`, `services_list`, `service_status(ServiceName)` (renders `check`), `service_action(ServiceName, Start|Stop|Restart)`.
  - Every operation: requires `Permission::Destructive` for the router (D-SSHPERM), an `Active` enrolment with SSH enabled and an unchanged router host, and chroot off (read over RCI); opens the key and pin, `admit_ssh`, connects with the pin; mutations take the router write lease and run as write jobs (mutation timeout); reads use the read timeout.
  - `remove`/`upgrade` targets must appear in `ListInstalled` of the same session; service names must appear in `ListServices` of the same session.
  - Read-back (rule (c)): after install/remove/upgrade re-run `ListInstalled` and check presence/version; action exit codes are interpreted per "Adopted defaults" (only 8 and 255 are errors by themselves); after start/restart require `check` = Running, after stop `check` = Stopped; mismatch -> verification error naming the package or service.
  - `crates/kcc-domain/src/entware/service_log.rs`: `service_log(router, role, ServiceName, max_lines)` reads `logging::read_log` (RCI), parses it with `kcc_telemetry::logs::parser::parse_records_now`, keeps records whose `process` equals the base name, and passes the messages through `kcc_config::mask::redact_text` unless the principal holds `RevealSecrets` (D-H1); needs Destructive like the rest of the service tools.
  - Audit each SSH operation: router, actor, operation, package/service name, outcome, output byte count and SHA-256 of the output (never the output).
  - Tests (`crates/kcc-domain/tests/entware_ops.rs`, `entware_service_log.rs`, both fakes): list/upgradable parse; install then read-back; remove of a package not installed -> refused with zero mutating commands; service start/stop with `check` read-back; disabled service start and restart -> `ServiceDisabled` (restart reports the service stopped); stop of a stopped service -> ok with `check` = Stopped; failed start (255) -> error; unknown service -> refused with zero commands; not enrolled, chroot on, host changed -> refused; without Destructive -> refused; host key changed -> refused and audited; log filtering and masking; audit entries contain no output text (assert bytes).
  - Must NOT: return raw SSH output to callers (only parsed values and counts).
  Closes: GAP-6, GAP-8
  Parallelization: Wave W5 | Blocked by: 9, 10 | Blocks: 15, 16, 17 | Can parallelize with: -
  References: todos 7, 9; `crates/kcc-app/src/jobs.rs` (write jobs); `crates/kcc-config/src/mask.rs` (shared masker); `crates/kcc-domain/src/logging.rs:74`.
  Acceptance criteria: tests fail before and pass after; `cargo test -p kcc-domain --all-features`, `cargo xtask cancel-safety`, G0 pass.
  QA scenarios: happy - `set -o pipefail; { cargo test -p kcc-domain --all-features && cargo xtask cancel-safety; } 2>&1 | tee .omo/evidence/task-11-kcc-entware.log`; failure - red runs at the top.
  Commit: Y | feat(domain): typed Entware package and service operations with read-back
  Recommended task executor category: unspecified-high - operations, leases, audit and parsing

- [ ] 12. Web: System > Entware (status, settings, setup, removal) and drive warnings
  What to do / Must NOT do:
  - New tab `Entware` in `crates/kcc-web/src/system_pages/tabs.rs`, page `crates/kcc-web/src/system_pages/entware.rs` + `entware_actions.rs`, template `crates/kcc-web/templates/pages/system_entware.html`, routes registered in `crates/kcc-web/src/system_pages.rs` next to `/ui/r/{router}/system/storage` (`system_pages.rs:114`).
  - Shows `EntwareStatus` (not-possible reason; components; settings; eligible and initializable drives; arch and installer; DNS filter dependency warning).
  - Forms: chroot (shows `ChrootStopsSshManagement` when enabling), timezone, initrc (Destructive), dns-override submitted with `.confirming(Risk::Management)` (pattern `crates/kcc-web/src/system_pages/keendns_access.rs:80`) plus the household-DNS warning text, remove (Destructive confirmation), setup wizard (drive select including internal storage with the router's warning; installer select shown only for `MipsAmbiguous`; Destructive confirmation; progress through the existing job feed and SSE, `crates/kcc-web/src/system_pages/job_feed.rs`; finish with a link to the existing save action).
  - Storage page: add the "Prepare for Entware (initialize ext4)" action (Destructive, typed confirmation) when the media is initializable; eject and initialize of the Entware drive show a second acknowledgement and pass `entware_acknowledged = true` only after it.
  - Permissions: page needs Read; each action its planner's permission. All strings from `kcc-i18n` (web.ftl, six locales). No inline script/style.
  - Tests (`crates/kcc-web/tests/system_entware.rs`, existing harness with `FakeRouter`): GET renders status for KN-1811 and the not-possible text for NC-3013; each POST changes the fake and re-renders; dns-override: the dialog appears without an up-front confirmation, and after confirming, the fake router's request log shows the fail-safe arm before `opkg dns-override` and the disarm after (pattern `crates/kcc-web/tests/system_pages/services.rs:193`); remove without confirmation -> dialog; setup happy path via the job feed; viewer sees no action buttons; eject and initialize of the Entware drive ask twice; golden HTML diff limited to intended pages.
  - Must NOT: auto-save; show installer URLs as editable.
  Closes: GAP-1, GAP-2, GAP-3, GAP-4
  Parallelization: Wave W4 | Blocked by: 10 | Blocks: 15 | Can parallelize with: 9, 13, 14
  References: `crates/kcc-web/src/system_pages.rs:114`; `crates/kcc-web/src/system_pages/storage.rs`, `storage_actions.rs`, `components.rs`, `component_commit.rs`, `job_feed.rs`, `tabs.rs`, `keendns_access.rs:80`; `crates/kcc-web/templates/pages/system_storage.html`, `system_components.html`; `crates/kcc-web/src/page_kit/`; `crates/kcc-web/tests/system_pages/services.rs:193`.
  Acceptance criteria: tests fail before and pass after; `cargo test -p kcc-web --all-features`, `cargo xtask i18n-check`, `cargo xtask assets-check`, G0 pass; golden diff file in evidence.
  QA scenarios: happy - `set -o pipefail; { cargo test -p kcc-web --all-features && cargo xtask i18n-check && cargo xtask assets-check; } 2>&1 | tee .omo/evidence/task-12-kcc-entware.log`; failure - red runs at the top.
  Commit: Y | feat(web): Entware page with setup wizard, settings and drive warnings
  Recommended task executor category: visual-engineering - new Web page, forms, wizard and templates

- [ ] 13. CLI: `kcc entware` (Option 1) and `kcc storage initialize`
  What to do / Must NOT do:
  - `crates/kcc/src/cli/args_dom_entware.rs` + `dom_entware.rs`, registered in `args_domains.rs`/`domains.rs`: `kcc entware status`; `kcc entware setup --drive <disk-arg|internal> [--arch aarch64|mipsel|mips] --confirm-destructive <router-id>` (job progress; ends with "unsaved; run `kcc config save`"); `kcc entware set chroot on|off` (prints the SSH warning when enabling), `set timezone auto|<tz>`, `set initrc <path> --confirm-destructive <router-id>`, `set dns-override on|off --yes` (the CLI's management bracket, `crates/kcc/src/cli/change.rs:70,82`, wraps it because the risk is Management), `kcc entware remove --confirm-destructive <router-id>`; `kcc storage initialize <media> --confirm-destructive <router-id> [--entware-ok]`; `kcc storage eject` gains `--entware-ok`. `--json` prints one document. Strings in `cli.ftl` (six locales).
  - Register the Entware write ops and the storage `initialize` op in the domain registry (`entware` descriptor `write_ops`, storage `WRITES`), add their rows to the CLI coverage tables (`crates/kcc/tests/cli_domain_writes/coverage.rs:40-70`, `exposed.rs`) and their arms to `crates/kcc-domain/tests/verification_coverage.rs:106-150`.
  - Tests (`crates/kcc/tests/cli_entware.rs` with `FakeRouter`): each command's effect and JSON shape; missing confirmation -> exit code and message; `--arch` required on KN-1010; dns-override without `--yes` refused, with `--yes` the fake request log shows the fail-safe arm before and the disarm after; eject/initialize of the Entware drive refused without `--entware-ok`.
  - Must NOT: add a raw URL option.
  Closes: GAP-1, GAP-2, GAP-3, GAP-4
  Parallelization: Wave W4 | Blocked by: 10 | Blocks: 16, 19 | Can parallelize with: 9, 12, 14
  References: `crates/kcc/src/cli/args_domains_net.rs:155-180`, `dom_net.rs:87`, `args_dom_jobs.rs`/`dom_jobs.rs`, `domains.rs:34-60`, `change.rs:60-90`, `closing.rs`.
  Acceptance criteria: tests fail before and pass after; `cargo test -p kcc --all-features`, `cargo test -p kcc --test cli_domain_writes`, `cargo test -p kcc-domain --test verification_coverage`, `cargo xtask i18n-check`, G0 pass; `kcc entware --help` diff contains only the new commands.
  QA scenarios: happy - `set -o pipefail; { cargo test -p kcc --all-features && cargo test -p kcc --test cli_domain_writes && cargo test -p kcc-domain --test verification_coverage && cargo xtask i18n-check; } 2>&1 | tee .omo/evidence/task-13-kcc-entware.log`; failure - red runs at the top.
  Commit: Y | feat(cli): kcc entware status, setup, settings, removal and storage initialize
  Recommended task executor category: unspecified-high - CLI commands across several files

- [ ] 14. MCP: toolset `entware` (Option 1) and storage initialize
  What to do / Must NOT do:
  - `crates/kcc-mcp/src/domains/write/entware.rs` + read support: tools `kcc_entware_read` (ops `status`, `settings`, `drives`; read-only) and `kcc_entware_write` (ops `setup`, `chroot`, `timezone`, `initrc`, `dns_override`, `remove`) in toolset `entware` (`crates/kcc-mcp/src/registry/definitions.rs`); every op passes `confirm_risk` (`crates/kcc-mcp/src/domains/write/common.rs:80-92`); `dns_override` also uses `preauthorize_management` and the management bracket (`common.rs:125-170`); `chroot` returns the `ChrootStopsSshManagement` warning in its result when enabling; `setup` starts through the long-job pattern of `crates/kcc-mcp/src/domains/write/jobs.rs`; `arch` required when the status says MipsAmbiguous. `kcc_storage_write` gains op `initialize` and the input field `acknowledge_entware_drive: bool` for `eject` and `initialize` (`housekeeping.rs` `STORAGE_OPS`). Regenerate `docs/MCP_TOOLS.md`; update `docs/CONFIG.md:81` toolset list.
  - Tests (`crates/kcc-mcp/tests/entware_tools.rs`): tools absent with default `toolsets`; present with `entware`; write tool absent in `read_only`; `setup`/`remove`/`initrc` need `allow_destructive` and `confirm`; `dns_override` needs `confirm` and the fake request log shows the fail-safe arm before and the disarm after; eject/initialize of the Entware drive refused without `acknowledge_entware_drive`; results within the cap.
  Closes: GAP-5, GAP-4
  Parallelization: Wave W4 | Blocked by: 10 | Blocks: 17 | Can parallelize with: 9, 12, 13
  References: `crates/kcc-mcp/src/domains/write/housekeeping.rs`, `write/dispatch.rs`, `write/common.rs:59-170`, `write/jobs.rs`, `domains/inventory.rs:254`, `domains/table.rs`, `registry/definitions.rs:17-45,165,184-190`, `support/access.rs:174-185`; `crates/kcc-mcp/tests/domain_tools.rs:174-181`.
  Acceptance criteria: tests fail before and pass after; `cargo test -p kcc-mcp --all-features`, G0 pass; after the commit `cargo xtask gen-tool-docs && git diff --exit-code HEAD -- docs/MCP_TOOLS.md` exits 0.
  QA scenarios: happy - `set -o pipefail; { cargo test -p kcc-mcp --all-features && cargo xtask gen-tool-docs && git diff --exit-code HEAD -- docs/MCP_TOOLS.md; } 2>&1 | tee .omo/evidence/task-14-kcc-entware.log` (run after the commit); failure - red runs of the gating tests at the top.
  Commit: Y | feat(mcp): Entware toolset and storage initialize
  Recommended task executor category: unspecified-high - MCP tools, schemas and gating

- [ ] 15. Web: SSH enrolment, packages, services and the removal notice
  What to do / Must NOT do:
  - On the Entware page add an "SSH access" section (Destructive): enable/disable, port, two-step enrolment (step 1 "Check router identity" runs `probe` and shows the fingerprint with the ticket nonce in a hidden field plus how to check it out of band; step 2 shows the fingerprint again, a password field and "I confirm this fingerprint"; submit runs `bootstrap`), state (Pending/Active), re-pin (same two steps), revoke, disable; a warning when the default password is still in use; a mismatch banner with both fingerprints; a notice when chroot is on.
  - "Packages" and "Services" sections (only when Active): lists, upgradable, update, install (name field), remove, upgrade, service start/stop/restart/status, service log view (masked). All actions Destructive with the kit's confirmation.
  - Router removal (dashboard router form, `crates/kcc-web/src/router_delete.rs`) shows "this router still authorizes kcc's SSH key line; revoke it first" in the confirmation dialog when `entware_ssh::active(state, id)` is true.
  - The password field is `autocomplete="off"`, posted only over TLS or loopback (existing listener rule), never re-rendered, never logged.
  - Tests (`crates/kcc-web/tests/entware_ssh_pages.rs`, both fakes): enrolment two steps; tampered fingerprint or reused nonce -> refused, zero password attempts; package install via form with read-back; service actions; viewer/operator without Destructive sees no SSH section; removal notice shown; response bodies never contain the password (assert); golden HTML.
  Closes: GAP-6, GAP-7
  Parallelization: Wave W6 | Blocked by: 11, 12 | Blocks: 21 | Can parallelize with: 16, 17
  References: todo 12 files; todos 8, 9, 11 APIs; router removal pages under `crates/kcc-web/src/` (dashboard router form); CSRF and session rules.
  Acceptance criteria: tests fail before and pass after; `cargo test -p kcc-web --all-features`, `cargo xtask i18n-check`, `cargo xtask assets-check`, G0 pass.
  QA scenarios: happy - `set -o pipefail; { cargo test -p kcc-web --all-features && cargo xtask i18n-check && cargo xtask assets-check; } 2>&1 | tee .omo/evidence/task-15-kcc-entware.log`; failure - red runs at the top.
  Commit: Y | feat(web): Entware SSH enrolment, packages and services
  Recommended task executor category: visual-engineering - Web forms and flows

- [ ] 16. CLI: `kcc entware ssh|packages|services` and the removal notice
  What to do / Must NOT do:
  - Commands (all `--confirm-destructive <router-id>`): `kcc entware ssh enable [--port N]`, `ssh disable`, `ssh probe` (prints the fingerprint, the ticket nonce and how to check the fingerprint out of band), `ssh bootstrap --ticket <nonce> --fingerprint <SHA256:...> [--password-file F]` (else `KCC_PASSWORD` or a hidden prompt, same sources as `router add`), `ssh repin ...` (same), `ssh revoke`; `kcc entware packages list|upgradable|update|install <name>|remove <name>|upgrade <name>`; `kcc entware services list|status <name>|start <name>|stop <name>|restart <name>|log <name> [--lines N]`. `--json` supported. The ticket comes from the shared `TicketStore` (todo 8), so two invocations by the same actor complete the bootstrap.
  - `kcc router remove` prints the notice before its confirmation when `entware_ssh::active(state, id)` is true.
  - Tests (`crates/kcc/tests/cli_entware_ssh.rs`, both fakes): full probe + bootstrap with a password file; wrong fingerprint and reused ticket refused; packages and services commands; removal notice; password never in stdout/stderr (assert); missing confirmation refused.
  Closes: GAP-6, GAP-7
  Parallelization: Wave W6 | Blocked by: 11, 13 | Blocks: 18, 19 | Can parallelize with: 15, 17
  References: todo 13 files; `crates/kcc/src/cli/secret.rs`, `router_secrets.rs`, `routers.rs`; todos 8, 9, 11.
  Acceptance criteria: tests fail before and pass after; `cargo test -p kcc --all-features`, `cargo xtask i18n-check`, G0 pass.
  QA scenarios: happy - `set -o pipefail; { cargo test -p kcc --all-features && cargo xtask i18n-check; } 2>&1 | tee .omo/evidence/task-16-kcc-entware.log`; failure - red runs at the top.
  Commit: Y | feat(cli): Entware SSH enrolment, packages and services
  Recommended task executor category: unspecified-high - CLI commands and secret input

- [ ] 17. MCP: toolset `entware-ssh`
  What to do / Must NOT do:
  - Tools `kcc_entware_packages` (ops `list`, `upgradable`, `update`, `install`, `remove`, `upgrade`) and `kcc_entware_services` (ops `list`, `status`, `start`, `stop`, `restart`, `log`) in toolset `entware-ssh`; both `readOnlyHint=false`, `destructiveHint=true`, permission Destructive, `confirm_risk(Risk::Destructive, confirm)` for every op (D-SSHPERM); results are parsed values only, paged with the existing cursor when over the result cap; reads return their result directly, mutations start a job through the `crates/kcc-mcp/src/domains/write/jobs.rs` pattern and return its id (tests poll the existing job-status tool until it is terminal). No probe, bootstrap, re-pin or revoke tool. Regenerate `docs/MCP_TOOLS.md`.
  - Tests (`crates/kcc-mcp/tests/entware_ssh_tools.rs`): absent by default; absent in `read_only` even with the toolset; `DestructiveDisabled` without `allow_destructive`; `ConfirmRequired` without `confirm`; happy install with read-back; every result is a JSON value whose strings come only from parsed names/versions/states (assert no raw-output marker strings from the fake, no password, no key bytes); no tool name contains `probe|bootstrap|repin|revoke` (assert the registry).
  Closes: GAP-5, GAP-8
  Parallelization: Wave W6 | Blocked by: 11, 14 | Blocks: 19 | Can parallelize with: 15, 16
  References: todo 14 files; `crates/kcc-mcp/src/support/access.rs:174-185`; `crates/kcc-mcp/src/support/route.rs:152`.
  Acceptance criteria: tests fail before and pass after; `cargo test -p kcc-mcp --all-features`, G0 pass; after the commit `cargo xtask gen-tool-docs && git diff --exit-code HEAD -- docs/MCP_TOOLS.md` exits 0.
  QA scenarios: happy - `set -o pipefail; { cargo test -p kcc-mcp --all-features && cargo xtask gen-tool-docs && git diff --exit-code HEAD -- docs/MCP_TOOLS.md; } 2>&1 | tee .omo/evidence/task-17-kcc-entware.log` (run after the commit); failure - red runs at the top.
  Commit: Y | feat(mcp): Entware SSH package and service tools, destructive-gated
  Recommended task executor category: unspecified-high - MCP tools and gating

- [ ] 18. e2e SSH leg, seccomp profile and container check
  What to do / Must NOT do:
  - `deploy/podman/e2e.sh`: start the fake router with `--entware-ssh-port` (port `KCC_E2E_SSH_PORT`, default 18422), add a pasta `-T` forward for it, and add steps: `kcc entware ssh probe`, `ssh bootstrap` with a password file, `packages list`, `packages install <fake package>`, `services restart <fake service>`, `ssh revoke`, for both `--native` and `--container`.
  - Regenerate the seccomp profile by the two-trace union procedure (build `kcc:test`, copy `/kcc` to `${CARGO_TARGET_DIR:-target}/kcc-musl`, two `cargo xtask seccomp trace` runs, union with `.1`/`.2` suffixes, `cargo xtask seccomp gen --check --traces <union>` unchained to list changes, `cargo xtask seccomp gen --traces <union>`); assign any unmapped syscall a group in `xtask/src/seccomp_groups.rs`; commit the profile naming added and removed syscalls.
  - Run `bash deploy/podman/e2e.sh --container --image kcc:test`, then `podman rmi kcc:test`. Update `deploy/podman/README.md` (SSH leg).
  - Must NOT: hand-edit the profile; touch a real router.
  Closes: GAP-10, GAP-9
  Parallelization: Wave W7 | Blocked by: 16 | Blocks: 21 | Can parallelize with: 19
  References: `deploy/podman/e2e.sh:1-130`; `deploy/podman/README.md:118-140`; `xtask/src/seccomp.rs`, `seccomp_gen.rs`, `seccomp_groups.rs`; `.github/workflows/container.yml`.
  Acceptance criteria: `shellcheck deploy/podman/e2e.sh` passes; `cargo xtask seccomp gen --check --traces <union>` and `--check-missing --traces <union>` exit 0 after the commit; container e2e passes; xtask clippy/test pass.
  QA scenarios: happy - `set -o pipefail; { shellcheck deploy/podman/e2e.sh && cargo xtask seccomp gen --check --traces "${CARGO_TARGET_DIR:-target}"/seccomp-trace-union && cargo xtask seccomp gen --check-missing --traces "${CARGO_TARGET_DIR:-target}"/seccomp-trace-union && podman build --format docker -t kcc:test . && bash deploy/podman/e2e.sh --container --image kcc:test && podman rmi kcc:test && cargo test --manifest-path xtask/Cargo.toml --all-features && cargo clippy --manifest-path xtask/Cargo.toml --all-targets --all-features -- -D warnings; } 2>&1 | tee .omo/evidence/task-18-kcc-entware.log`; failure - before the profile regeneration the container SSH leg's result (pass, or the blocked syscall) captured at the top.
  Commit: Y | build(e2e,seccomp): Entware SSH leg in e2e and a re-traced profile
  Recommended task executor category: deep-low - shell e2e and trace procedure

- [ ] 19. Owner-run live suites for Entware
  What to do / Must NOT do:
  - `crates/kcc/tests/live_entware.rs` + `crates/kcc/tests/live_entware/` (pattern `live_domains`): every test `#[ignore]`, gated by the live env contract (`KCC_LIVE_URL`, `_LOGIN`, `_PASSWORD_FILE`, `KCC_LIVE_TARGET_CONFIG` with `test_device = true`, `KCC_LIVE_ALLOW_SERIAL`), logging `live-skip:<reason>` when unset.
  - Read-only probe (no extra flag): records `show media` fields (label, uuid, `initialize-supported`), `components list` names (whether `opkg`/`ext` exist and whether not-installed components are listed), `show rc` `opkg`, `show version` `arch`, Entware status; writes the capture to `.omo/evidence/live-entware-probe.json` when run by the owner.
  - Write suite (`KCC_LIVE_ALLOW_WRITE=1` plus `KCC_LIVE_ENTWARE_SETUP=1` and `KCC_LIVE_ENTWARE_DRIVE`): runs the guided setup on a test router's spare drive and records the log markers seen.
  - SSH suite (`KCC_LIVE_ALLOW_WRITE=1`, `KCC_LIVE_ENTWARE_PASSWORD_FILE`): probe, bootstrap, `packages list`, install and remove `KCC_LIVE_ENTWARE_PACKAGE` (default `nano`), `services list` + `check` of one service, the enrolment script's tools (`grep`, `mv`, `chmod`, `touch`, `mkdir`, `printf`) present (implied by a successful bootstrap; on failure the test reports the exit code), the authorized_keys path, port 222/22, then revoke.
  - Add the new variables to AGENTS.md "Live env contract".
  - Hermetic tests (not ignored) prove the refusals: missing variables -> `live-skip`; a non-test profile -> refused.
  - Must NOT: run the live suites (the worker never sets `KCC_LIVE_*`).
  Closes: GAP-9
  Parallelization: Wave W7 | Blocked by: 13, 16, 17 | Blocks: 21 | Can parallelize with: 18
  References: `crates/kcc/tests/live_domains.rs`, `crates/kcc/tests/live_domains/gate.rs`, `harness.rs`, `refusal.rs`; AGENTS.md live env contract.
  Acceptance criteria: `cargo test -p kcc --test live_entware` (without `--ignored`) passes and runs only the hermetic refusal tests; `cargo test -p kcc --test live_entware -- --list --ignored` lists the probe, setup and SSH tests; G0 passes.
  QA scenarios: happy - `set -o pipefail; { cargo test -p kcc --test live_entware && cargo test -p kcc --test live_entware -- --list --ignored; } 2>&1 | tee .omo/evidence/task-19-kcc-entware.log`; failure - red run of the refusal test before the gate exists.
  Commit: Y | test(kcc): owner-run Entware live suites behind the live contract
  Recommended task executor category: unspecified-low - live suite scaffolding following an existing pattern

- [ ] 21. Latest-version recheck and gate G1
  What to do / Must NOT do:
  - Re-run D-LATEST for both workspaces: `cargo update --dry-run --verbose` (output to `.omo/evidence/task-21-dry-*.txt`, then `! grep -E '^\s+(Updating|Adding|Removing|Downgrading) [A-Za-z0-9_-]+ v'`); raise semver-incompatible direct requirements that passed the cooldown (russh included); plain `cargo update`; `check_dep_reqs.py` exit 0; vet with targeted exemptions; deny/clippy duplicate lists and reasons accurate.
  - Run G1 in full and fix anything it reports.
  - Must NOT: take versions inside the cooldown.
  Closes: GAP-10
  Parallelization: Wave W8 | Blocked by: 5, 15, 18, 19 | Blocks: 20 | Can parallelize with: -
  References: Verification strategy G1; `.omo/reviews/kcc-full-review-2026-11-15/check_dep_reqs.py`; `.cargo/config.toml`.
  Acceptance criteria: every G1 command exits 0; both dry-run files contain no package lines.
  QA scenarios: happy - `set -o pipefail; { python3 .omo/reviews/kcc-full-review-2026-11-15/check_dep_reqs.py && cargo update --dry-run --verbose > .omo/evidence/task-21-dry-root.txt 2>&1 && ! grep -E '^\s+(Updating|Adding|Removing|Downgrading) [A-Za-z0-9_-]+ v' .omo/evidence/task-21-dry-root.txt && cargo update --dry-run --verbose --manifest-path xtask/Cargo.toml > .omo/evidence/task-21-dry-xtask.txt 2>&1 && ! grep -E '^\s+(Updating|Adding|Removing|Downgrading) [A-Za-z0-9_-]+ v' .omo/evidence/task-21-dry-xtask.txt && cargo deny check && cargo audit && cargo vet --locked && cargo machete crates xtask && cargo +1.100.0 build --workspace --all-features && cargo xtask lint-completeness && taplo fmt --check; } 2>&1 | tee .omo/evidence/task-21-kcc-entware.log`; failure - the pre-change dry-run output at the top.
  Commit: Y | build(deps): latest versions past the cooldown after the Entware work
  Recommended task executor category: deep-low - supply-chain and gate fixes

- [ ] 20. Docs sweep and CHANGELOG audit
  What to do / Must NOT do:
  - Update README (features; Limitations: unverified hardware items, SSH opt-in, chroot), `docs/USER_GUIDE.md` (System > Entware, drive preparation, SSH access, packages, services), `docs/CONFIG.md` (toolsets `entware`, `entware-ssh`; no new `kcc.toml` keys), `docs/SECURITY.md` (SSH trust model: pinned ed25519 host key, single-use bound probe ticket, how to verify the fingerprint out of band (connect from a trusted LAN machine with `ssh -p <port> root@<router>` and compare, or read `/opt/etc/dropbear/dropbear_ed25519_host_key.pub` from the drive), key-only afterwards, the residual non-zeroized password copy inside russh, Destructive-only, no MCP enrolment; a probe ticket is consumed even by a failed redeem, so another Destructive user can make the owner repeat the probe (fails closed); the fail-safe protects kcc's access, the DNS warning protects the household), `docs/PRIVACY.md` (stored SSH key, enrolment record, tickets; package lists are not stored; MCP results may contain package names), `docs/ARCHITECTURE.md` (kcc-ssh crate, data flow), `docs/MIGRATION.md` (verify todo 5), `docs/BACKLOG.md` (remaining unverified items from todo 1, updated), `deploy/podman/README.md` (verify todo 18).
  - Audit that every behaviour-changing todo added its CHANGELOG line; add only what is missing.
  - Run `cargo test -p kcc --test docs`.
  Closes: GAP-10
  Parallelization: Wave W9 | Blocked by: 21 | Blocks: F1-F4 | Can parallelize with: -
  References: all todos; README.md; docs/*.md.
  Acceptance criteria: `cargo test -p kcc --test docs` passes; `cargo xtask gen-tool-docs && git diff --exit-code HEAD -- docs/MCP_TOOLS.md` exits 0 after the commit; F1 reads each listed document against this todo's list.
  QA scenarios: happy - `set -o pipefail; { cargo test -p kcc --test docs && cargo xtask gen-tool-docs && git diff --exit-code HEAD -- docs/MCP_TOOLS.md && git diff --stat HEAD~1; } 2>&1 | tee .omo/evidence/task-20-kcc-entware.log` (after the commit); failure - the docs test run before the edit captured at the top (it must already pass, showing the change is prose).
  Commit: Y | docs: Entware management, SSH trust model and limits
  Recommended task executor category: writing - documentation

## Final verification wave
> Runs in parallel after ALL todos. ALL must APPROVE. Surface results and wait for the user's explicit okay before declaring complete.

> **Convergence rule.** A finding becomes a new `- [ ] N.` row only when it gives a reproduction and is one of: (a) a secret (password, private key, SSH output) reaching a log, audit entry, error, Debug output, MCP result or a principal without the permission; (b) a wrong router command, an SSH command outside the closed set, an `authorized_keys` change beyond kcc's line, a connection to an unpinned host key or an unadmitted address; (c) a violated Must have, Must NOT have, IS row or owner decision (D-SCOPE, D-SSHLIB, D-BOOTSTRAP, D-SSHPERM, D-OVERLAY, D-LATEST, D-VET, D-DELIVERY); (d) a reproducible failure of a main flow; (e) a G0/G1 or GitHub CI failure; (f) a behaviour change versus the start commit that no todo lists. Everything else goes to docs/BACKLOG.md. At most two finding rounds; the second round's list is frozen; then one confirmation round and a report to the owner. A dependency version that passed the cooldown after todo 21 is not a finding.

- [ ] F1. Plan compliance audit
  Recommended task executor category: unspecified-high.
  - For every todo 1-21 confirm each instruction exists in code (file:line) and its evidence log has red and green runs.
  - Must NOTs: `cargo xtask allow-gate`; `git diff <start> -- '**/Cargo.toml'` adds only `russh` and the new `kcc-ssh` crate (whose dependencies are existing workspace crates), plus kcc-domain's new edges to the existing crates `kcc-ssh` and `kcc-telemetry` (no `chrono` edge outside kcc-telemetry); no public fn in `kcc-ssh` takes a command string (read the public API); the rendered command constants equal the strings in todo 7; vendored files unchanged (`sha256sum -c`); audit format unchanged.
  - Output `.omo/evidence/F1-kcc-entware.md`, APPROVE/REJECT per todo.
- [ ] F2. Code quality review
  Recommended task executor category: unspecified-high.
  - G1 in full on a clean checkout (`cargo clean`, target on `/`, gate tools at the `ci.yml` pins); capture `.omo/evidence/F2-kcc-entware.log`.
  - After pushing, the latest GitHub CI and Container runs on `master` are green (`gh run list`, `gh run view --log-failed`).
  - Review against the vendored core checklist (§11), http-services, mcp-servers and the overlay (including (a') and (b')); `cargo mutants` on `crates/kcc-ssh/src` command rendering and grammar modules (install with `cargo install cargo-mutants --locked` if missing, else a non-blocking note).
- [ ] F3. Real manual QA
  Recommended task executor category: unspecified-high (load skills `playwright`, `visual-qa`).
  - Start `cargo run -p kcc-testkit --bin kcc-fake-router -- --model KN-1811 --bind 127.0.0.1:18080 --password-file <file> --entware-ssh-port 18422` and `kcc serve` against it; with Playwright and the CLI: status; drive preparation; setup wizard to "installed, unsaved"; dns-override dialog and household warning; eject of the Entware drive asks twice; SSH two-step enrolment; a tampered fingerprint is refused; packages install/remove; service restart and status; chroot-on refusal; viewer sees no actions; MCP with default toolsets lists no Entware tool; screenshots `.omo/evidence/F3-entware-<area>.png` in light/dark, phone/desktop.
- [ ] F4. Ideal-state fidelity
  Recommended task executor category: unspecified-high.
  - For IS-1..IS-10 re-run the proving scenario in `## Success criteria`; PASS/FAIL with evidence in `.omo/evidence/F4-kcc-entware.md`; classify a FAIL by the convergence rule.

## Commit strategy
- **First commit, before todo 1:** `docs(plan): add the Entware management plan` with `.omo/plans/kcc-entware.md` and `.omo/drafts/kcc-entware.md` exactly as reviewed.
- Then one commit per todo with its Commit line (Conventional Commits, crate scopes) on `master`; no force, no history rewrite; repo-local git identity as configured.
- Each commit leaves G0 green; push to `origin master` after each landed todo with `git -c credential.helper='!gh auth git-credential' push origin master`; never write a token anywhere.
- Generated artifacts are committed with the change that produced them.
- A commit that changes an existing test's expectation names that test in its body.

## Success criteria
> One row per IS row. The plan is complete only when every IS row has a delivering todo and a proving QA scenario; F4 checks the delivered behavior against these rows 1:1, and a shortfall becomes new `- [ ] N.` rows, never a note.
| IS | Delivering todo(s) | Proving QA scenario | Evidence |
| --- | --- | --- | --- |
| IS-1 | 3, 12, 13, 14 | KN-1811 status Possible with an eligible drive and aarch64 installer; NC-3013 not possible; KN-1010 asks for mipsel/mips; Web/CLI/MCP show the same | `task-3-...log`, `task-12-...log`, `task-13-...log`, `task-14-...log` |
| IS-2 | 4, 10, 12, 13, 14 | Setup on the fake runs components commit inside the job, install, new log marker, read-back, ends unsaved; stale lines ignored; no-marker and error-line cases fail with the step named; drive initialize works on 5.1 and is refused on 5.0 | `task-4-...log`, `task-10-...log`, `task-12-...log` |
| IS-3 | 2, 4, 12, 13, 14 | Each planner's line, risk class and read-back; invalid values refused before any request | `task-2-...log`, `task-4-...log` |
| IS-4 | 2, 4, 5, 12, 13, 14 | dns-override on Web, CLI and MCP shows the warning, and the fake request log shows the fail-safe arm before and the disarm after; Entware drive eject/initialize needs the acknowledgement on every surface; migration skips all six opkg lines | `task-4-...log`, `task-5-...log`, `task-12-...log`, `task-13-...log`, `task-14-...log` |
| IS-5 | 14, 17 | Default toolsets show no Entware tool; read-only hides SSH tools; DestructiveDisabled/ConfirmRequired; parsed-values-only results; no probe/bootstrap/repin/revoke tool | `task-14-...log`, `task-17-...log` |
| IS-6 | 6, 7, 11, 15, 16, 17 | Grammar refusals with zero connections; pinned connect; install/remove/service actions read back with `check` semantics; disabled service and unknown service refused; chroot on refused | `task-7-...log`, `task-11-...log` |
| IS-7 | 7, 8, 9, 15, 16 | Enrolment scripts under `/bin/sh` keep other keys byte for byte and leave the file untouched when `grep` fails; two runs leave one marker line; kill after append -> Pending -> retry Active; reused/expired/foreign tickets and host key swaps refused with zero password attempts and audited; revoke removes the line; removal wipes key, record and ticket and shows the notice; `disable` works with chroot on or the router unreachable | `task-7-...log`, `task-8-...log`, `task-9-...log`, `task-15-...log`, `task-16-...log` |
| IS-8 | 7, 9, 11, 15, 16, 17 | Audit files, TRACE log capture including russh, errors, Web/CLI output and MCP results contain neither the password nor the private key nor raw SSH output (byte assertions) | `task-9-...log`, `task-11-...log`, `task-15-...log`, `task-16-...log`, `task-17-...log` |
| IS-9 | 3, 6, 7, 10, 18, 19 | Fake router install log and media initialize, rc.func-faithful fake SSH with faults drive the tests; enrolment scripts run under `/bin/sh`; e2e SSH leg passes natively and in the container; live suites listed as ignored and refusal tests pass | `task-6-...log`, `task-7-...log`, `task-18-...log`, `task-19-...log` |
| IS-10 | 1, 6, 18, 20, 21 | G1 green; seccomp check-missing passes; docs tests pass; MCP docs fresh; GitHub CI green | `task-21-...log`, `task-20-...log`, `F2-kcc-entware.log` |
