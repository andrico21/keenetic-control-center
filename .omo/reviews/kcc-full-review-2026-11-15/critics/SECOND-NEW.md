I checked all 14 new issues against the code at HEAD 349b7fb. One is refuted (N13), one duplicates W5-02 (N15), and the other twelve hold up but are at most low severity. Three of them are narrower or broader than first described. I made no edits and ran no cargo commands.

### N1 ADJUSTED
- checked: `crates/kcc-app/src/workflow.rs:575-586,638-724,855-867,1336-1346`, every production `.begin(` call (`kcc-web/src/save.rs:64`, `page_kit/change.rs:405`, `system_pages/component_commit.rs:83`, `kcc/src/cli/change.rs:220`, `cli/dom_jobs.rs:219`, `kcc-mcp/src/support/access.rs:109`), `docs/ARCHITECTURE.md:60-71`
- reasoning: The claim is true. Every production caller passes `last_read = None`, and the migration paths hard-code `None`, so the branch at `workflow.rs:692-700` only runs in `kcc-app/tests/workflow.rs`. However, the documented conflict check still runs. ARCHITECTURE step 6 promises "refuse if someone else changed the router since the baseline", and that is `check_conflict` comparing against `expected`, which is set from the baseline read in `begin_with_client`. What is missing is an optional, undocumented check for the window between the caller's earlier read and `begin`. No front end ever had that state to pass in, so this is a dead parameter, not a broken control.
- severity: low
- correction: The `last_read` parameter of `begin` is unused in production. Either remove it or thread a last-change marker from the page or plan read. The documented conflict check is unaffected.

### N2 ADJUSTED
- checked: `crates/kcc-app/src/workflow.rs:1117-1159,1273-1306,1310-1332,971-1025`; `kcc-rci/src/engine.rs:471-486`; `kcc-mcp/src/support/audit.rs:1-70`; `kcc/src/cli/change.rs:217-262`; `kcc-web/src/page_kit/audit.rs:100-131`, `page_kit/change.rs:259-283`
- reasoning: The code says what the finding claims. `dispatch_cli` collects per-line results into a `Result<Vec<_>>`, so the first rejected line returns `Err` at `:1125` before `audit_cli` at `:1151`, and the workflow writes no `router.change_cli` entry. But the attempt is not unaudited: MCP (`support/audit.rs`, `Attempt::Failed`), the CLI (`cli/change.rs:253-260`, `cli.change` failed) and the Web (`page_kit/audit.rs:append_outcome`) each record a failed entry. What is lost is fidelity. The entry says "failed / router_rejected" and does not say that earlier lines were applied, unlike `apply_batch`, which records `succeeded`/`failed` counts at `:1080-1088`. `apply` (`:993-995`) has the same shape for a failure after send.
- severity: low
- correction: A partial CLI batch is audited as a plain failure by the front end, with no record of which lines were applied. The fix is to record partial completion the way `apply_batch` does.

### N3 ADJUSTED
- checked: `crates/kcc/src/cli/dom_core.rs:146-176,231-233`; `kcc-domain/src/clients.rs:146-189,251-277`; `kcc-domain/src/clients/command.rs:16-33,121-171`; `catalog/5.1/known.json` (`known host`: `name` is type `String`); `kcc-catalog/src/validate.rs:301`; `kcc-app/src/workflow_cli/command.rs:122-133`; `kcc-web/src/clients_pages/client_act.rs:213-245`
- reasoning: The claim is confirmed. `label()` returns `client.name` from `show ip hotspot` unchanged. It only matters for an unregistered client (`registration()` skips registered ones), whose name is device-reported. The catalog `String` check is just `value.is_string()`, and `cli_line` formats `known host {name} {mac}`. The Web replaces everything except alphanumerics, `_` and `.` precisely "so it stays one word". Two things bound the impact. First, `CliCommand::expose_for_send` refuses control characters, so a device cannot inject a newline or a second line. Second, any space splits words inside one `known host` line, which most likely makes the router reject it, so a Write user's `kcc clients access/schedule/policy/priority` fails. An extra-MAC argument injection is only possible if the firmware ignores trailing tokens, and that is unverified. The trigger is a CLI Write operator acting on an unregistered device whose name contains spaces or quotes.
- severity: low
- correction: Reuse the Web `registration_name` sanitizer in the CLI and the domain, or validate `name` as a single CLI token in `plan_host_field`. The severity would rise to medium if a live router were shown to accept trailing tokens.

### N4 ADJUSTED
- checked: `crates/kcc-app/src/accounts.rs:371-421`; `crates/kcc-web/src/auth.rs:228-236,356-393`; `docs/SECURITY.md:110-111`
- reasoning: The HTTP answer is not distinct. `Invalid`, `Disabled` and `Locked` all go to `login_failure`, which renders the same 401 page with `ERRORS_AUTH_FAILED`; only the audit outcome string differs ("invalid" or "locked"). Locking out an existing account (including an admin) with 5 bad passwords is documented behaviour (`SECURITY.md:110`). There is a real side channel, though: `Disabled` and `Locked` return before any Argon2 work, while unknown users run `verify_dummy_password` and known users run a real verify. After 5 attempts, an existing account answers measurably faster than a non-existent one, so timing enumerates usernames.
- severity: low
- correction: There is no visible enumeration. A timing oracle exists for locked and disabled accounts; fix it by running the dummy verify on those paths too.

### N5 CONFIRMED
- checked: `crates/kcc-rci/src/session.rs:422-440,538-551,599-605,694-702,767-797`; `auth_ndw4.rs:86,170,191`
- reasoning: `parse_set_cookie` runs `raw.to_str()?` (`:772`) on every `Set-Cookie` before the name filter (`:777`). One non-visible-ASCII cookie therefore makes `refresh_session` fail after `send_with_session` has already returned. A POST the router applied is then reported as `RciError::Transport`, and the front ends audit it as a failure. The trigger needs the router, or a proxy in front of it, to send such a cookie. Nothing in the repo shows Keenetic doing this, so the path is reachable but unlikely.
- severity: low

### N7 ADJUSTED
- checked: `crates/kcc-domain/src/firewall/management.rs:37-56`; `firewall/change.rs:40-60,75-83,180-227,258-271`; `firewall/change/render.rs:40-75`; `firewall/change/verify.rs:62-104`; `kcc-mcp/src/domains/write/filtering.rs:188-262`; `kcc-domain/src/interfaces/membership.rs:59-76`; `kcc-config/src/config_text.rs:307-316`; catalog `access-list`/`interface ip access-group` (`name`/`acl` are `String` in 4.3/5.0/5.1)
- reasoning: The mechanism is real. The MCP `acl` passes only `valid_text` (any non-control text), and `list_risk` compares it exactly with unquoted config words, so a mismatch yields `Risk::Write`. That skips both the confirm requirement and the fail-safe bracket. The finding overstates the scope in three ways:
  - The config tokenizer unquotes, so a genuinely bound list named "My ACL" does match.
  - `Remove` and `Property` run `preflight`, which requires the rule under that exact list name, so a mismatched name sends nothing.
  - Only `Add` is exposed, and only if the firmware resolves a non-canonical spelling (for example a quoted `"WAN_IN"`) to the bound list. That is unverified.

  The actor is an authenticated MCP Write caller, so this weakens a safety net against mistakes, not an access control.
- severity: low
- correction: Validate MCP `acl` as a single CLI token (`ObjectName`) before planning.

### N8 CONFIRMED
- checked: `crates/kcc-domain/src/vpn_clients/wireguard/parser.rs:48-75,162-199`; `vpn_clients/wireguard.rs:119-126`; `kcc/src/cli/dom_vpn.rs:68-74`; `kcc/src/cli/exit.rs:189-191`; `kcc-web/src/dns_vpn/vpn_conf.rs:85-128`; `kcc-mcp/src/domains/write/vpn.rs:22-24`
- reasoning: The field name is the text before the first `=`. A bare base64 key line (`<key>=`) therefore becomes `UnknownField { field: <43 key chars> }`. `Malformed` similarly carries the whole line, and Display prints both. The CLI prints Display via `Failure::text`. The Web drops `field` (`vpn_conf.rs` uses only `line`), and MCP offers no import. The secret goes only to the importing operator's own stderr, who already holds the file, though terminal scrollback and CI logs are the cost.
- severity: low

### N9 ADJUSTED
- checked: `catalog/{4.3,5.0,5.1}/access-list.json` (`access-list rule` arguments: `description`, `index`, `schedule`; synopsis has `order <new-index>`); `catalog/untyped-arguments.json:2-5`; `kcc-domain/src/firewall/change.rs:85-114`; `kcc-web/src/firewall_page/lines.rs:75-84`; `firewall_page/rule_actions.rs:237`
- reasoning: `new-index` is untyped in all three catalogs, but it is listed on purpose in `untyped-arguments.json`, the tracked allowlist that a unit test pins. Reorder still works: the Web builds `access-list {list} rule {index} order {to}` with `to: usize` after validating the list and the index, so there is no injection surface. The only concrete defect is in the domain: `RuleProperty::Order` produces `{"order": ...}`, which the catalog would refuse as an unknown field, but it has no production caller.
- severity: info
- correction: This is already tracked through the untyped-argument allowlist. The only cleanup is to remove `RuleProperty::Order` or type `new-index`.

### N11 ADJUSTED
- checked: `crates/kcc-web/src/net_wifi_edit.rs:56-99`; `net_wifi_settings.rs:209-245`; `page_kit/submit.rs:141-153,286-326`; `page_kit/action.rs:183-193`; `kcc-domain/src/wifi.rs:164-205`; `net_interface_actions.rs:84-95`; `docs/USER_GUIDE.md:20-25`
- reasoning: The claim is confirmed and the issue is broader. The Web asks for confirmation only when a handler calls `.confirming`/`.confirming_planned`, and `field` (the schedule edit) does not. `toggle` doesn't either, and it runs `wifi::plan_up(.., false)`, which is classified as management when it disables a management-bridge access point: one click, no prompt. Compare the interface "down", which confirms at `Risk::Management`. USER_GUIDE says risky changes "ask first". The fail-safe bracket still runs for the immediate change, so this skips the confirmation step, not the recovery.
- severity: low
- correction: Add `.confirming_planned(resubmit)` to `net_wifi_edit::field` and `net_wifi_settings::toggle`.

### N12 CONFIRMED
- checked: `crates/kcc-web/tests/network_pages/wifi.rs:73-125`; `net_wifi_settings.rs:209-245`
- reasoning: The operator POST sends `confirm=yes&confirm_name=home` up front, and the handler never asks, so the test passes with or without a prompt. It is the witness for the toggle part of N11.
- severity: low

### N13 REFUTED
- checked: `crates/kcc-domain/src/dhcp/command.rs:13-51`; `kcc-domain/src/dhcp.rs:161-193`; `kcc-domain/src/verification.rs:92-143`
- reasoning: `command::request` wraps the request in `verification::complete(...)`. With an empty `verify` list, that adds a running-config `ConfigCommand`/`ConfigCommandAbsent` presence spec for every non-stateless command. So `ip dhcp pool`, `range`, `default-router` and `dns-server` are all read back by `apply_cli` (`workflow.rs:1138-1140`). An empty list at construction time means "fill in the generic read-back", not "no read-back". `dhcp::apply`'s extra `ip dhcp host` check is on top of that.

### N15 DUPLICATE-OF W5-02
- checked: `crates/kcc-web/src/overview.rs:214-227`; `system_pages/logs.rs:144-175`; `net_interface_traffic.rs:50-67`; `system_pages/jobs.rs:153`; `advanced/job_stream.rs:87`; `wizard/events.rs:154`; `sse.rs:78-99`
- reasoning: Same root cause and same fix as W5-02. `guarded` only holds the `StreamPermit`, which is a concurrency slot keyed by session string, not a validity check. The new information is scope: log, job, wizard and interface-traffic streams also check the session once at open. W5-02's affected list should name them, and the log stream is the most revealing.

### N16 CONFIRMED
- checked: `crates/kcc-web/src/presets_page/saved.rs:108-141`; `presets_page/finish.rs:69`; `wizard/finishing.rs:87`; `wizard/store.rs:46,264`; `docs/PRIVACY.md:24`
- reasoning: `sweep` expires only `Origin::Copy` records, and `discard` runs only on finish. A saved-preset run abandoned midway therefore keeps `passwords.sealed` indefinitely. It is encrypted under the master key, so exposure needs that key, and PRIVACY.md promises cleanup only for copy runs. This is the same class as W5-03 (migrations) but a separate code path.
- severity: low

### N17 CONFIRMED
- checked: `crates/kcc/src/cli/router_secrets.rs:62-80,104-136`; `kcc/src/cli/router_edit.rs:69-140`; `kcc/src/cli/routers.rs:151-153`; `kcc-app/src/registry.rs:108-134,554-592`
- reasoning: `edit` runs `seal()` (overwriting `<id>.sealed` and the others, whose paths depend only on the id) before `registry().update()`, with no restore. `add` does it the other way and rolls back. `update` can fail after sealing on `profile.validate()`: `parse_url` accepts any URL, so a typo such as `--url http://host/ui --new-password` fails "url must be an http(s) origin". It can also fail on `NotFound` (concurrent delete) or a state I/O error. The old profile then signs in with the new secret, and the edit's own doc comment says "a refused change writes nothing". Re-running with the corrected input recovers.
- severity: low

## Summary
- CONFIRMED: 6 (N5, N8, N12, N16, N17, and N15's underlying defect via W5-02)
- ADJUSTED: 6 (N1, N2, N3, N4, N7, N9, N11; seven ids, with N11 broadened in scope and the rest narrowed or downgraded)
- REFUTED: 1 (N13)
- DUPLICATE: 1 (N15 → W5-02)

Correction to the counts above: by id the totals are CONFIRMED 5 (N5, N8, N12, N16, N17), ADJUSTED 7 (N1, N2, N3, N4, N7, N9, N11), REFUTED 1 (N13), DUPLICATE 1 (N15), for 14 in total.

NEW issues noticed while checking, for separate validation:
- **NEW-A (low):** MCP client `access`/`schedule`/`policy`/`priority` on an unregistered client use `input.value.as_deref().unwrap_or_default()` as the registration name (`kcc-mcp/src/domains/write/clients.rs:155`). An omitted `value` therefore plans `known host` with `name: ""`, which the catalog accepts because `String` is just `is_string()` (`kcc-catalog/src/validate.rs:301`). The rendered line is `known host  <mac>` (`clients/command.rs:133`), a malformed command. A caller-supplied name with spaces is also not checked as one token.
- **NEW-B (low; also part of N11):** `/ui/r/{router}/wifi/toggle` with `setting=enabled&value=no` disables an access point that may be classified as management without any confirmation (`net_wifi_settings.rs:229-245`).
- **NEW-C (info; also part of N9):** `RuleProperty::Order` (`kcc-domain/src/firewall/change.rs:107`) would always be refused by catalog validation and has no production caller.