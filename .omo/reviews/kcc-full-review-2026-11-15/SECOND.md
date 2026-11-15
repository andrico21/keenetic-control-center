# Second-pass validation set

Each item below was raised by a first-pass critic (not by the lane reviewer) or is a
finding still rated HIGH after the first critic. The full original text is in the cited
file under /home/andrico/.cache/kcc-review/ (findings/<LANE>.md for findings, critics/<LANE>.md
"## Summary" / NEW sections for new issues).

## HIGH findings needing a second, independent critic

- H1 Read role gets router secrets: findings/SEC1.md SEC1-01, findings/E.md E-01,
  findings/W4.md W4-01 (+ critics/W4.md NEW: `page_kit/secret.rs` `mask` passes a
  secret-named member through when its value is an object, e.g. `{"password":{"ns3":..}}`
  from `show interface`). Decide: reachable for a Read-only role on MCP and Web, and
  whether secrets (ns3 blobs are keyless-reversible, `kcc-config/src/ns3.rs`) leave.
- H2 Unauthenticated audit-log disk fill via 1 MiB usernames: findings/SEC1.md SEC1-02.
- H3 Clearing a firewall rule description/schedule sends `no ... disable` (re-enables a
  disabled rule): findings/D.md D-01, plus critics/D.md NEW-1 (Web dialog saved empty
  re-enables silently and is audited as success).
- H4 Secret-bearing lines (ns3, WireGuard keys) ignore interface/port/radio mappings in
  migration/presets: findings/G.md G-01, plus critics/G.md NEW-1 (radio mappings never
  rewrite `WifiMaster0/AccessPoint0` tokens).
- H5 Migration management phase reconnects with the new password before it is sent:
  findings/G.md G-03.
- H6 Preset capture overwrites a preset outside the caller's router scope (MCP
  `kcc_preset_capture`, and CLI `kcc preset capture` per critics/E.md NEW-2): findings/E.md
  E-02 and findings/G.md G-02. The two first critics disagree (high vs medium): decide.
- H7 CLI `apikey revoke` / `user disable` / password reset do not reach a running
  `kcc serve` (keys stay valid until SIGHUP/restart; Web sessions survive): findings/F.md
  F-01 (related: SEC1-05, W1-01).

## NEW issues raised by critics (validate each from scratch)

- N1 critics/B.md NEW-1: the "stale read" conflict check never runs in production; every
  caller of `ChangeWorkflow::begin*` passes `last_read = None`.
- N2 critics/C.md NEW: `ChangeSet::apply_cli` returns from `dispatch_cli(...)?`
  (`crates/kcc-app/src/workflow.rs` ~1125) before `audit_cli` (~1151): a batch whose first
  lines applied and a later line failed gets no `router.change_cli` workflow entry.
- N3 critics/SEC2.md NEW: `crates/kcc/src/cli/dom_core.rs:231-233` `label()` passes a
  router-reported client name (possibly a LAN device's DHCP hostname) unsanitized into
  `known host {name} {mac}`; the Web sanitizes it (`client_act.rs:225-245`).
- N4 critics/SEC2.md NEW (info): Web login answers "locked" distinctly; only existing
  accounts can be locked, so bad passwords enumerate usernames and can lock out an admin.
- N5 critics/A.md NEW: `crates/kcc-rci/src/session.rs:771-772` `parse_set_cookie` calls
  `raw.to_str()` and returns `Err(Transport)` before checking the cookie name, so any
  unrelated `Set-Cookie` with a non-visible-ASCII byte fails every response, including
  POSTs the router already applied.
- N7 critics/D.md NEW-2: `firewall/management.rs:38-56` `list_risk` matches bindings by the
  exact `acl` string; an MCP `acl` with spaces matches no binding, so the change is
  classified Write and skips the fail-safe bracket.
- N8 critics/D.md NEW-3: `vpn_clients/wireguard/parser.rs:173-176,194-197` `UnknownField.field`
  (text before the first `=`) can contain key material and is printed by Display.
- N9 critics/D.md NEW-4: the catalog lacks `new-index` for `access-list rule ... order`
  (4.3, 5.0, 5.1), so no catalog-validated reorder is possible.
- N11 critics/W2.md NEW-1: Wi-Fi schedule edit (`net_wifi_edit.rs:85`, `wifi::plan_schedule`
  management-classified) submits with no confirmation dialog.
- N12 critics/W2.md NEW-2: `crates/kcc-web/tests/network_pages/wifi.rs:106-112` sends
  `confirm=yes&confirm_name=home` up front, so a missing prompt cannot fail it.
- N13 critics/W3.md NEW-1: DHCP pool writes are never read back (empty verify lists in
  `kcc-domain/src/dhcp/command.rs:23-29,44-49`; `dhcp::apply` verifies only `ip dhcp host`).
- N15 critics/W5.md NEW-1: the missing session re-check lives in the shared
  `overview::guarded` (`overview.rs:215-227`), so router log, job and interface-traffic
  streams also outlive logout/disable/role change.
- N16 critics/W5.md NEW-2: runs of saved presets (`Origin::Preset`) abandoned before the last
  step keep `passwords.sealed` forever (`presets_page/saved.rs:129-141` sweeps only
  `Origin::Copy`).
- N17 critics/W1.md NEW: CLI `router edit` seals new secrets before the registry update and
  never restores them on failure (`crates/kcc/src/cli/router_secrets.rs:120-122`).
