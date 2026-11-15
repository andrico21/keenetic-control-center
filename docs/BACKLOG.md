# Backlog

Open items that do not block a release. One line each: where it is (`file:line`) and why
it stays open. Line numbers are those of the tree at the time of writing.

## Not proven on hardware

No live suite has run against a real router yet: every `live_*` test logs `live-skip` and
returns, and `docs/FIRMWARE.md:10` still says "live verification not yet run" for 5.1 (the
firmware doc test accepts that text). Until a test router is available, these behaviors
rest on the manuals and the fake router only:

- The Windows path for sealed credentials and key files (owner-only ACLs, `crates/kcc-app/src/persist.rs:559-608`) has only been built, not run, on Windows. The macOS, Windows and aarch64 CI legs are likewise unproven.
- Whether a real router answers 404 to `GET /rci/system/reboot`, and whether the scheduled-reboot fallback (extender, access-point and repeater modes) and the native fail-safe timer behave as the manual describes (`spikes/live-router/RESULT.md:21-23`, probes 7, 7b and 8, are marked NOT-RUN).
- Whether a real router executes a space-joined root key such as `{"system reboot":{}}`, and whether it accepts an empty object at a namespace (the raw request rules in `docs/SECURITY.md` are written to be safe either way).
- Whether the members of a real LAN bridge are `include` or `inherit` lines, and whether a real `show interface` answer is keyed by interface id (`crates/kcc-migrate/src/rules.rs`).
- Whether a real router refuses an `include` of an unknown member, accepts WireGuard leaves on a bridge, or deletes `Bridge0` (`crates/kcc-domain/src/interfaces/guard.rs`).
- The shape of a real `show running-config` answer (`crates/kcc-domain/src/firewall/read.rs:45-60` reads it as text) and whether the router accepts every abbreviation the catalog allows.
- `crates/kcc-migrate/src/interface_names.rs:4` decides whether an interface name is physical or logical with a name-shape heuristic taken from the documentation. The unit test pins the documented shapes only.
- `crates/kcc-domain/src/configuration.rs:112-117`: the recovery mode for a router that reports no system mode assumes that 4.3 and 5.0 report a boolean `fail-safe.active` in `show last-change`. This is from the documentation. If it is wrong, kcc refuses the change with `router_mode_unknown`, which is the safe direction.

## Upstream (rmcp-server-kit)

- `crates/kcc/src/server.rs:139` builds the server configuration without `max_concurrent_requests`, and the kit logs that it is unset. A bound would cap held requests besides the per-router lease. The setting is the kit's to expose or default.
- The kit's HTTP listener has no header read timeout, so a connection that sends a request line and then goes silent stays open for more than 70 seconds. It cannot be set from `crates/kcc/src/server.rs:139`.
- The kit logs a transport-level 403 (an MCP request refused before any tool runs) itself; it is not written to `audit.jsonl` (`crates/kcc-mcp/src/support/audit.rs:11` audits tool-level refusals only).
- `docs/rust-guidelines/UPSTREAM.md` lists the guideline changes the owner still has to propose by hand.

## Known gaps

- `crates/kcc/src/server.rs:203-206`: on SIGTERM with nothing in flight, `kcc serve` exits about 4.4 s after it logs "jobs drained". The cause has not been traced.
- The CLI has no SIGINT or SIGTERM handling during a safety bracket (`crates/kcc/src/cli/change.rs:228`). If the process is killed, the router's own timer restores the saved configuration; `kcc serve` and `kcc mcp stdio` do wait for their brackets.
- The Web standalone rollback is not mode-aware (`crates/kcc-web/src/config_page/safety.rs:121,170-188`): on a router in scheduled-reboot mode it refuses ("not armed") instead of rebooting like the CLI does.
- `crates/kcc-web/src/page_kit/facts.rs:14`: the Web facts cache holds a router's catalog for 600 s, so a firmware change is noticed up to ten minutes late.
- `crates/kcc-web/src/dns_vpn/dns_checks.rs:82` builds its change with a fixed `Risk::Write`; it is the only Web page that does not take its risk from the domain planner.
- A 403 pre-check was dropped from two Web paths that now run through the shared submit step (`crates/kcc-web/src/dns_vpn/vpn_import.rs:76` and the VPN dialog in `vpn_forms.rs`): a role with `Write` but not the planned risk's permission sees the kit's forbidden outcome instead of the 403 page, and reboot, reset and mesh-restart ask for confirmation only after the context is read.
- The wizard finish routes still have three entry handlers for the migration (`/commit`, `/rollback`, `/{way}` in `crates/kcc-web/src/migrate_wizard/routes.rs:52-57`) and one for presets (`/{way}`, `presets_page/routes.rs:82-84`). Making them one changes edge behavior (the content type of commit, the order of dialogs, the order of the unknown-way 404), so it needs a decision.
- The firewall page reads rules as running-config text (`crates/kcc-domain/src/firewall/read.rs:60`), while the CLI still uses `configured_rules` (`read.rs:45`: JSON, three requests, IPv4 only). Two readers of the same data remain; unifying them would change the CLI's request count.
- `crates/kcc-domain/src/firewall/lists.rs:197-198` skips an interface binding whose direction is not `in` or `out`. The firmware only writes those two.
- The master key (`crates/kcc-app/src/secrets.rs:336`) is the plaintext root of trust: anyone who can read that file can open the state store. Podman's default file secret driver also keeps the deployed secrets unencrypted on the host (`deploy/podman/README.md:51`). Wrapping the key with `systemd-creds` or a TPM is a possible future step.
- `ApplyNeeds::raw_restore` (`crates/kcc-domain/src/configuration/apply_needs.rs:13,31`), the flag that adds `Destructive` for a raw restore, has no production caller yet; the Web raw restore holds `Destructive` through its own constant.
- One CLI refusal has no machine-readable handle: an absent firewall rule property prints a sentence with exit code 4 and no code (`crates/kcc/tests/cli_domain_writes/admin.rs:99` pins the exit code only).

## Decisions kept on purpose

- The session keepalive was removed. It was code in `crates/kcc-rci/src/session.rs` meant to send a periodic request so an idle router session would not expire, but nothing ever started it. If a long-lived server needs idle sessions kept open, it has to be rebuilt and wired in.
- The Argon2 budget for the ndw4 sign-in math is fixed at one derivation at a time (`crates/kcc-rci/src/ndw4_keys.rs:17`); the setter for it was removed because nothing called it. A fleet that signs in to many routers at once therefore derives their keys one after another.
- Two small helpers were not replaced by crates: the edit-distance function (`crates/kcc-catalog/src/validate.rs:380`, instead of `strsim`) and the router network check (`crates/kcc-rci/src/outbound.rs:44`, instead of `ipnet`). Both are short, tested and need no new dependency.
- Two glob matchers with different semantics exist, and neither is shared: `crates/kcc-migrate/src/rules.rs:766-800` (rule globs: case-sensitive, a segment may end in `*`) and `crates/kcc-migrate/src/presets/glob.rs:4-52` (preset group patterns: case-insensitive, a segment may have a `*` in the middle, plus a catalog-path matcher). Merging them would change what existing rules and presets match.

## Cleanup

- `crates/kcc-web/src/secret_pages/dialog.rs:177` (`SecretDialog`) stays a second dialog engine: its typed-twice password pair has its own markup (autocapitalize, rules on both fields, help under the first only, ids `secret-new` and `secret-repeat`) that the shared form engine's secret kind does not reproduce byte for byte.
- `crates/kcc-web/src/routing_page/route_remove.rs:217` runs through `Action::run_planned` outside the shared submit step, because the route-wipe guard needs reads and an extra audit entry after the run.
- `crates/kcc-app/src/workflow.rs` is still about 1500 lines. It should split by responsibility (leases, receipts, batch, replay).
- Five tables are still hand-written instead of using `kit_table.html`: `partials/migrate_mapping.html`, `partials/presets_macros.html`, `partials/migrate_review.html`, `partials/presets_review.html` (rename grids and review grids with checkboxes and radios) and `pages/config_diff.html` (side-by-side diff). A form-control cell kind and a multi-body view would let them join; each serves only one or two pages.
- The Web consolidation saved less than the line count suggests: the two wizards' directories shrank by about 2600 lines, but `crates/kcc-web/src/wizard/` holds almost all of them. The real net saving is about 26 lines of Rust and three templates; the rest is moved code. The converted pages' Rust also grew while their templates shrank, because the markup moved into typed builders.
- `crates/kcc-web/src/migrate_wizard/maps.rs` is at 248 pure lines, two under the ceiling.
- `crates/kcc-web/src/brackets.rs:135` maps an aborted, unheld request to 503. The client has gone, so nobody can observe it.
- The evidence log of the preset-port fix has no separate "before" line for its second mutation check (`.omo/evidence/task-138-keenetic-control-center.log:19`). Cosmetic.
- `xtask/` is a separate workspace, outside `cargo fmt --all`; `cd xtask && cargo +nightly-2026-10-03 fmt -- --check` fails in the untouched `xtask/src/seccomp.rs`, `seccomp_gen.rs` and `seccomp_groups.rs`, and no CI job checks it.

## Tests

- The golden-page harness does not cover everything. On the KN-1811 fake, created PPPoE and PPTP connections are not listed back, so its `internet/password` and `vpn/credential` submits answer 404. Later steps of the migration wizard and preset runs, SSE streams, raw restore and one-time API keys are not captured.
- Some tests still wait in real time: `crates/kcc-telemetry/tests/logs.rs:239,257,290,292`, `crates/kcc/tests/metrics_serve/runtime.rs:249` (a 500 ms poll loop), `crates/kcc-web/tests/dashboard.rs:249,251`, `crates/kcc-web/tests/explorer_pages/bracket_ordinary.rs:54`, `bracket_budget.rs:39`, and the finish-recovery tests `preset_finish_recovery.rs:240` and `wizard_finish_recovery.rs:261`. Each should wait on the exact state change or a paused clock.
