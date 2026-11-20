---
slug: kcc-entware
status: superseded
superseded_by: .omo/plans/kcc-entware-mcp.md (owner decision D-MERGE 2026-11-20; do NOT run `$ulw-execute kcc-entware`)
intent: clear
review_required: true
plan_path: .omo/plans/kcc-entware.md
plan_sha256: 25bcdf1b1ffb1d0c3d770570bbf166252530c7284997a254fa4dc0a6e26b3e57
review_round_id: round-0a563425618a
round_status: complete
pending-action: none - approved by Metis, Momus and the Oracle on 25bcdf1b; worker runs `$ulw-execute kcc-entware` after the CI-fix task
review:
  metis: {status: done, session: ses_e0d987ea5ffe53X9h3S7E1Yo6F, result: READY (no notes)}
  momus: {status: done, round_id: round-0a563425618a, plan_sha256: 25bcdf1b1ffb1d0c3d770570bbf166252530c7284997a254fa4dc0a6e26b3e57, session: ses_e0d7a4e31ffey6o7TghmiQeu3p, result: OKAY (two informational remarks, considered: todo 3 already requires available rows in the fake; line-length truncation is a reader limit)}
  independent: {status: done, round_id: round-0a563425618a, plan_sha256: 25bcdf1b1ffb1d0c3d770570bbf166252530c7284997a254fa4dc0a6e26b3e57, launch_id: launch-0df3ce27ab28, session: ses_e0d7a33b4ffep0FE682boKxUNE, result: OKAY (no notes)}
approach: Option 1 (Entware setup/status/OPKG settings over existing RCI) then Option 2 (opt-in, typed package/service management over SSH to Entware: key auth, host-key pinning, Destructive, off by default, no raw shell)
---

# Draft: kcc-entware

## Affected user and ideal state
<!-- Who this output touches (a customer, another programmer, a program or agent consuming it - often more than one) and how each uses it today and will use it after. -->
<!-- IS-n | property of the ideal state: nothing snags, feels odd, regresses, or degrades for them | reason -->
<!-- GAP-n | difference between IS-n and today | reason | closed by todo(s) -->
Users: U1 router owner/admin (Web main, CLI); U2 AI assistant over MCP (possibly prompt-injected); U3 operator of kcc serve/container; U4 maintainers/worker.
- IS-1 | U1 sees per router whether Entware can run and is configured: OPKG + ext components installed, configured drive/URL/initrc/timezone/chroot/dns-override, suitable ext4 drives, CPU architecture/installer | today invisible in kcc
- IS-2 | U1 sets up Entware end to end from kcc (components, optional format, online install via `opkg disk <drive>:/ <url>`, verification) with the right installer for the router's CPU, and changes/removes OPKG settings with read-back and warnings | today only raw CLI
- IS-3 | Every Entware write uses the existing safety model: catalog validation, audit, permissions, confirmation for Destructive/DNS-affecting changes, never saved implicitly | project rules
- IS-4 | U2 gets the same capability over MCP only when the toolset is enabled; destructive steps need allow_destructive + confirm | prompt-injection safety
- IS-5 | (Option 2) U1 manages Entware packages and services over SSH with typed operations only; kcc never runs a raw shell line; host key pinned; key auth only; per-router opt-in, off by default | root shell risk
- IS-6 | (Option 2) SSH credentials and pins are sealed like router credentials; nothing secret in logs/audit/errors | rule (d)
- IS-7 | Everything is testable without hardware (fake router opkg state, fake Entware SSH server) and verifiable later on hardware via owner-run live suites | rule (g), worker has no KCC_LIVE_*
- IS-8 | Docs, i18n (6 locales), CHANGELOG, MCP tool docs, container/seccomp, CI and supply chain stay green and latest (D-LATEST, D-VET) | standing rules
- GAP-1..8 | none of IS-1..IS-8 exists today (no opkg domain/surface/fake state, no SSH transport) | inventory bg_5dc37bd8

## Components (topology ledger)
- C1 | OPKG settings domain over RCI: read status (components installed, opkg settings, candidate drives) and write disk/chroot/dns-override/initrc/timezone with read-back | active | catalog/5.1/opkg.json, crates/kcc-domain/src/storage.rs, components.rs
- C2 | Guided Entware setup over RCI: components install (opkg + ext fs) via existing commit job, drive choice (+ optional format), `opkg disk <drive>:/ <installer-url>` online install, verification | active | crates/kcc-domain/src/components/commit.rs
- C3 | Surfaces for C1/C2: Web System > Entware tab, CLI `kcc entware`, MCP `kcc_entware_read/_write` toolset (off by default), i18n x6, docs, fake router | active | crates/kcc-web/src/system_pages/, crates/kcc-mcp/src/domains/
- C4 | SSH transport to Entware: new dependency, sealed key per router, host-key pinning, outbound policy, timeouts | active (Option 2) | research pending
- C5 | Typed Entware operations over SSH: packages list/update/install/remove/upgradable, services list/start/stop/restart/status, logs; permissions, audit, surfaces | active (Option 2) | research pending
<!-- Lock the SHAPE before depth. One row per top-level component that can succeed or fail independently. -->
<!-- id | outcome (one line) | status: active|deferred | evidence path -->

## Open assumptions (announced defaults)
<!-- Record any default you adopt instead of asking, so the user can veto it at the gate. -->
<!-- assumption | adopted default | rationale | reversible? -->

## Findings (cited - path:lines)
- Vendored CLI manual text catalog/.cache/5.1/kn-1011.txt:30964-31200 (5.1, pages 541-544): `opkg disk <disk> [<url>]` "Partition label or UUID", url since 4.02, example `opkg disk storage:/ https://bin.entware.net/aarch64-k3.10/installer/aarch64-installer.tar.gz`; `no opkg disk` disables opkg; mounting runs initrc immediately; `opkg dns-override` = "Disable TCP and UDP 53 port for DNS proxy"; `opkg initrc <path>` default /opt/etc/initrc; `opkg timezone (auto|<tz>)`; `opkg chroot`. No `show opkg` anywhere in the manual. `components install <component>` example `install ntfs` (:3274-3300).
- Keenetic support 20980 (fetched 2026-11-19): install log lines `Opkg::Manager: disk is set to: OPKG:/.` ... `doinstall: [1/5]`..`[5/5] "Entware" installed!`, `Log on to start an SSH session using login - root, password - keenetic`; dropbear installed, ed25519 host key generated; SSH port 222 if the router SSH server component is installed, else 22. Support 18482: internal storage `opkg disk storage:/ <url>`, "UBIFS partition is not tested". Support 42407: disk identified by UUID or volume label, `/opt/etc/ndm/*.d` hooks.
- Installer URLs (HEAD 200, 2026-11-19): https://bin.entware.net/aarch64-k3.10/installer/aarch64-installer.tar.gz, https://bin.entware.net/mipselsf-k3.4/installer/mipsel-installer.tar.gz, https://bin.entware.net/mipssf-k3.4/installer/mips-installer.tar.gz.
- Reading config subtree: `router.client.show_rc(json!({...}))` + `configuration_tree()` (crates/kcc-domain/src/dns.rs:389-399) -> opkg settings via `show_rc({"opkg":{}})`.
- `RciClient::pinned_addresses()` (crates/kcc-rci/src/engine.rs:268-273) gives the policy-checked addresses -> SSH connects only to those.
- `logging::read_log(router, max_lines)` (crates/kcc-domain/src/logging.rs:74) -> install progress via `Opkg::Manager` / `doinstall: [n/5]` lines.
- MCP toolsets: core, network-write, vpn, dns, system-admin, migration, presets, raw (docs/CONFIG.md:81); tool->toolset in crates/kcc-mcp/src/registry/definitions.rs:17-45,186-188.
- Migration dispositions incl. skip-hardware (crates/kcc-migrate/rules/rules.toml:86-94).
- Component ids for OPKG/Ext not verifiable offline (manual example only `ntfs`).
- `opkg disk` synopsis: `opkg disk <disk:String> [<url:String>]` (catalog/5.1/opkg.json) -> online install over RCI is a documented CLI form; `opkg initrc <path:Filename>`; `opkg timezone auto|<tz>`; chroot/dns-override flags; all prefix_no.
- `show version` fixtures carry `arch`: KN-1811/KN-3810 "aarch64", KN-1010/NC-3013 "mips" (crates/kcc-testkit/fixtures/*/show.json:10). KN-1010 (Giga, MT7621) is little-endian but reports "mips" -> `arch` alone cannot pick mips vs mipsel installer; need a model table (Keenetic docs) for "mips".
- Domain pattern: read_show (crates/kcc-domain/src/lib.rs:353), validate (planning.rs:15), negated `no` (request_words.rs:51), ChangeOp (lib.rs:216-275), VerificationSpec (dns/change.rs:50-62); template storage.rs + Web system_pages/storage.rs; credentials CredentialKind (crates/kcc-app/src/credentials.rs:78-104); OutboundPolicy::allows (crates/kcc-rci/src/outbound.rs:112); McpConfig toolsets default ["core"] (crates/kcc-app/src/settings.rs:179-209); seccomp allows connect (no change for SSH).
- No `opkg` migrate rule (crates/kcc-migrate/rules/rules.toml).
- SSH crate check (scratch copy ~/.cache/kcc-review/scratch-ssh, `cargo add russh@0.65.1 --no-default-features -F ring -p kcc-app`): russh latest past cooldown 0.65.1 (2026-11-03; 0.65.2 is 2026-11-16, inside cooldown), MSRV 1.89; adds 67 crates incl. pre-release `ssh-key 0.7.0-rc.11` (required dep) and windows/pageant crates; ONE new duplicate `num-bigint` 0.4.8 (x509-parser/der-parser) vs 0.5.1 (russh) -> deny skip needed; cargo deny licenses ok, sources ok; cargo audit clean; russh advisory history: RUSTSEC-2024-0450, 2026-0154, -0492..-0496, all patched <= 0.65.0. Default features pull aws-lc-rs (C/cmake) -> use ring feature (ring already in tree, no aws-lc-sys).
- Entware SSH (librarian, partly unverified): dropbear, port 222 when the Keenetic SSH component holds 22, authorized_keys /opt/etc/dropbear/authorized_keys, ed25519 host key supported; opkg list-installed format `name - version`; services /opt/etc/init.d/S<NN><name> start|stop|restart|status.
- Catalog 5.1/5.0/4.3 has `opkg chroot|disk|dns-override|initrc|timezone|object-group fqdn enable` (kind Setting, prefix_no, change_settings, not persists_immediately; catalog/5.1/opkg.json pages 541-544). No `show opkg`, no exec/shell/ndmc command in any catalog.
- Existing: components domain + commit job (crates/kcc-domain/src/components.rs, components/commit.rs), storage domain `show media`/`show usb`/`system eject` (crates/kcc-domain/src/storage.rs), Web System>Components and >Storage pages, MCP kcc_components_read/_write and kcc_storage_write, CLI components/storage; overlay: `components commit`, `media * format`, `system eject` Destructive (catalog/overlay.toml).
- No opkg domain module, page, CLI, MCP tool or fake-router state.
- kcc is RCI/HTTP only; no SSH client.
- External (librarian 1): Entware install = OPKG component + ext fs component + ext4 drive (or internal storage since 3.7); online install `opkg disk <disk> <url>` since KeeneticOS 4.2; packages/services only via SSH into Entware (root; default root/keenetic; port 222 or 22); hooks /opt/etc/ndm/*.d; Netcraze same. `show opkg` unverified.

## Decisions (with rationale)
- Round 11 (sha 25bcdf1b): ALL APPROVE, no actionable notes. FINAL.
- Round 10 (sha f25cd315): ALL APPROVE - Oracle OKAY no notes (ses_e0d7bccebffeAnYQoXFGD1XOCA), Metis READY no notes, Momus OKAY (ses_e0d7be658ffeoTEfXXXfX8aF4J; notes: GAP-4 cites doc comment not code; todo 9 should add the kcc-ssh dep) -> both applied.
- Round 9 (sha 54809558): ALL APPROVE - Momus OKAY (ses_e0d7d280effez4Pa7Vtpm1yMS2; notes informational, considered, no change), Metis READY, Oracle OKAY (ses_e0d7d0c7affen01PlR2lbzK1cy; wave count wrong) -> count fixed.
- Round 8 (sha bc063207): ALL APPROVE - Momus OKAY (ses_e0d7f6525ffe0SNe0740C6mz9v; notes overlay lines 12-15, todo 7 sentence clarity), Metis READY (wave wording nit), Oracle OKAY (ses_e0d7f4950ffeThGtUegQ0mTZLC; same wave nit) -> all three wording edits applied.
- Round 7 (sha 574eb6f8): ALL APPROVE - Momus OKAY (ses_e0d80baf7ffeZTKCNaZCSLuGCE; note small waves), Metis READY (P2 internal crate path form), Oracle OKAY no notes (ses_e0d80a0feffeNHTi2wl75bmSLu) -> path forms applied; small waves explained under the wave table.
- Round 6 (sha 33a1f1c2): ALL APPROVE - Momus OKAY (ses_e0d8247a1ffepLyUZ7tjEBvS60), Metis READY (no notes), Oracle OKAY (ses_e0d8228a5ffesg3vcLVhi4EMnp; note: kcc-testkit dev-dep path form) -> applied.
- Round 5 (sha b58c8317): ALL APPROVE - Momus OKAY (ses_e0d83cbb9ffeur5MaNrG8emYOr), Metis READY (P2 helper builds+runs Command), Oracle OKAY (ses_e0d83a8d0ffe9ITa7RxCekh1vK; notes tempfile dev-dep, fixed absolute tool paths, stub grep content/mode) -> notes applied.
- Round 4 (sha 97926442): Momus OKAY (ses_e0d868c59ffeyeJ7y3SplcsgWd); Metis READY (P2 import path); Oracle REJECT N2 host PATH with spaces/parens breaks happy-case script tests on WSL -> hermetic PATH for every case, temp root without spaces; notes applied (parse_records_now path, #[expect] on the Command::new helper only, unquoted temp path guarded).
- Round 3 (sha c97b6f29): Momus OKAY (ses_e0d8a2879ffeBQdAcEXK9UocMZ); Oracle REJECT N1 stub-grep test defeated by the PATH preamble -> renderer takes PATH param, tools symlink dir, 127 case; notes applied (set_port/set_enabled/repin chroot tests, SECURITY ticket burn, exact forget names + redeem rename name, RemoveKey umask + cleanup + newline fixtures). Metis NOT READY: P0 stub test (same fix); P0 chrono -> parse_records_now helper in kcc-telemetry so kcc-domain needs no chrono; P1 fake log record shape spelled out, records with id > baseline, Opkg::Manager matched by component or message text; P2 no-commit path keeps passed changes, temp-file cleanup, POSIX wording; 11 now depends on 10 (parse_records_now).
- Round 2 (sha 94192d5d): Momus OKAY (ses_e0d98e607ffemS2TzYgqiMhdrB); Oracle REJECT (ses_e0d98b477ffeeo1miOzw8vajXa): B1/B2 closed; R1 grep failure deletes keys -> `[ $? -le 1 ]` guards + stub-grep test; R2 chroot refusal blocked local disable -> only SSH-opening flows check chroot; notes applied (full rc.func exit table + ANSI, record-id log baseline via parse_records, ListServices if-form, atomic ticket redeem + pins as strings, MCP chroot warning, run_commit before). Metis NOT READY (ses_e0d987ea5ffe53X9h3S7E1Yo6F): P0 `media * initialize` dead pattern -> `media initialize`; P1 overlay mirror (add fail-safe timer/keep-alive to overlay.toml), registry write ops registered with CLI coverage in todo 13, script test inline cfg(unix) no public hook, exit-code table, ListServices, log records + parse_records (kcc-domain -> kcc-telemetry), configured_media for the drive guard, setup start signature + fresh ChangeSet + RouterBusy, removal via forget hook in delete callers (SSH key moved out of CredentialKind into router-ssh store), start_paused with per-read fake appends; P2 all applied.
- Round 1 (sha 6b7b8a0e): Momus OKAY (ses_e0da8a91effeUAtOSxBmSN6bEH); Metis NOT READY: P0-1 service_log/ops in kcc-app would need kcc-domain (cycle) -> orchestration moved to kcc-domain/src/entware/ssh, state stays in kcc-app; P0-2 nested write job -> run_commit extraction, fresh ChangeSet, read_last_change preflight; P1-1 fake emulation split + verbatim scripts; P1-2 single TicketStore; P1-3 dns-override fail-safe wiring+tests per surface; P1-4 todo 4 updates eject callers; P2 all applied. Oracle REJECT (ses_e0da88007ffewrs0TA4QPcQrCV): B1 rc.func has no status -> check + exit 8; B2 stale log markers -> per-attempt baseline; B3 chroot breaks paths -> refusal + warning; B4 authorized_keys script specified and executed under /bin/sh in tests; notes 1-12 applied (Reason variant, eject ack per surface, pin by type + ed25519-only, ticket bound + single-use + SECURITY out-of-band, russh log capture at TRACE, glob listing + parsed-name validation + installed-only remove/upgrade, injectable timeouts, admit_ssh async, mirror test/initialize instead of partition format/route registration/jobs pattern, QA ordering/grep -q/overlay crate list, host compare at use, wording + deny reasons).
- Metis pre-plan gap analysis (ses_e0db6aef1ffeRlhGaBfyb8556a) folded in: P0-1 overlay clauses (a')/(b') adopted as D-OVERLAY (follows from owner's Option 2 choice; recorded, announced); P0-2 admit_ssh API + connect_stream on pinned addresses + suffix-only refused; P0-3 two-step probe ticket bound fingerprint; P0-4 no MCP bootstrap; P0-5 enrolment lifecycle (C4b); P1-1 migrate skip rules; P1-2 household (dns-override Management/fail-safe, Entware drive guard, DNS filter flag); P1-3 setup preflight/order/explicit save; P1-4 install as job with log marker; P1-5 tolerant unverified defaults; P1-6 grammars + POSIX quoting + absolute paths; P1-7 read-back, no raw output, service log via show log (keeps the owner-approved log feature without SSH file reads); P1-8 limits; P1-9 two toolsets, destructive hints; P1-10 resolve russh at intake; P1-11 crate kcc-ssh; P1-12 e2e SSH leg + seccomp. Extra: `opkg disk`/`opkg initrc` Destructive in the catalog.
- Owner 2026-11-18: scope = Option 1 then Option 2 (both in this plan); CI fixes go to the worker first via a separate note (not in this plan).
- Owner 2026-11-19 D-SSHLIB: russh 0.65.1, `default-features = false`, features ["ring"] (no aws-lc C build); accept pre-release ssh-key 0.7.0-rc.11 and a deny skip for num-bigint 0.4/0.5; take newer russh only past the 3-day cooldown.
- Owner 2026-11-19 D-BOOTSTRAP: kcc generates an ed25519 key per router (sealed, AD `router:<id>:ssh`); one-time bootstrap with the Entware root password typed by the admin (never stored, zeroized); kcc shows the host key fingerprint, admin confirms, kcc appends its public key to /opt/etc/dropbear/authorized_keys and pins the host key (sealed/stored with the router); afterwards key-only; changed host key refused until an admin re-pins.
- Owner 2026-11-19 D-SSHPERM: every SSH operation (reads included) requires Destructive (Web/CLI confirmation; MCP allow_destructive + confirm: true); log/status text additionally goes through the shared masker unless RevealSecrets (D-H1).
- Defaults announced (not vetoed): TDD; opkg settings excluded from migration/presets; settings read from running-config; dns-override warning dialog; removing the drive needs confirmation; SSH port 222 default, per-router configurable; per-router SSH opt-in off by default; MCP Entware toolsets off by default; Entware arch from `show version` arch (aarch64) + model table from Keenetic docs for "mips" (mips vs mipsel), unknown model -> explicit choice.
- Owner standing rules: plan validated by Metis + Momus + Oracle on one sha, every critic note applied; latest versions past the 3-day cooldown (D-LATEST); one commit per todo; no KCC_LIVE_* by the worker.

## Scope IN

## Scope OUT (Must NOT have)

## Open questions

## Approval gate
status: approved (owner 2026-11-19: "talk to critics, create detailed plan - fully validated and confirmed by critics")
next: on okay -> scaffold plan, Metis, todos, TL;DR, then Momus + Oracle rounds until all approve one sha with every note applied
<!-- When exploration is exhausted and unknowns are answered, set status: awaiting-approval. -->
<!-- That durable record is the loop guard: on a later turn read it and resume at the gate instead of re-running exploration. -->
