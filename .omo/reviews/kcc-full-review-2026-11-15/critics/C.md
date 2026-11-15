I checked all 25 findings in lane C against the code at HEAD `349b7fb`; I did not edit anything or run cargo. 12 are CONFIRMED, 13 are ADJUSTED and none are REFUTED. The biggest change is C-01: it is real, but I lowered it from high to medium because only MCP can reach it and it cannot add a separate command.

### C-01 ADJUSTED
- checked: `kcc-domain/src/dhcp/command.rs:13-105`, `dhcp.rs:86-159,164-196`, `clients/command.rs:121-171`, `clients.rs:136-189,251-276`, `kcc-mcp/src/domains/write/clients.rs:138-182,224-253`, `kcc-mcp/src/domains/write/common.rs:48-62,177-181`, `kcc-mcp/src/support/validate.rs:39-45`, `kcc-catalog/src/validate.rs:278-305`, `kcc-catalog/src/runtime/data.rs:204`, `catalog/5.1/ip.json` (`ip dhcp pool`/`host`/`option`/`wpad`/`bootfile`), `catalog/5.1/known.json`, `kcc-app/src/workflow_cli/command.rs:38-48,128-139`, `workflow.rs:1117-1159,1273-1306`, `kcc-domain/src/verification.rs:99-140`, `kcc-web/src/clients_pages/dhcp_forms.rs:100-123,280-285`, `client_act.rs:135-146,215-220`, `dhcp_lease.rs:119,184-191`, `kcc-mcp/src/domains/write/dns.rs:13`, `kcc-domain/src/dns.rs:341-352`.
- reasoning:
  - **How the value travels.** MCP `dhcp` op `pool` takes `name` through `text()`. That check only refuses empty values, control characters and more than 256 characters, so spaces and quotes pass. The catalog types `ip dhcp pool name`, `ip dhcp host host` and `known host name` as `String`, and `valid_argument` only checks `is_string()` for that type. `cli_line` then pastes the value unquoted. `CliCommand::new` checks no grammar, and `expose_for_send` refuses only control characters. `verification::complete` accepts the line because it still parses as one row. `dispatch_cli` sends it.
  - **What an attacker can do.** A name like `_WEBADMIN wpad http://x/wpad.dat` makes the first line `ip dhcp pool _WEBADMIN wpad …`. The domain's own `ip dhcp pool {pool} range …` rendering shows the router takes subcommands on the same line. That reaches catalogued pool subcommands no curated op offers (`wpad`, `option`, `bootfile`, `next-server`), which otherwise need `RawRci`. The attacker needs `Write` on the router, with the `dhcp` toolset enabled. No `confirm` is needed because the risk is `Write`.
  - **Where it stops.** It cannot start a new command: newlines and control characters are refused, and nothing shows `;` works. The `known host` and `ip dhcp host` tails can only add arguments to those commands.
  - **Why it is not high.** The Web UI is not affected: pool names go through `is_word`, client names through `is_name`, and MACs through `mac_address`. The CLI runs as the operator's configured role. A `Write` principal can already redirect LAN DNS through the curated DNS writes (`name_server`, `static_host`, upstreams), so the WPAD man-in-the-middle example is not a new kind of capability. What it does add is a bypass of the curated/RawRci boundary within one command's arguments.
- severity: medium
- correction: Reachable only through MCP (and through the CLI by its own operator). It adds arguments inside the pool/host/known-host commands, not separate commands. Two more MCP holes have the same root cause: `plan_client` passes `input.value` as the registration name with no check at all (`clients.rs:156`), and the static-lease `mac` is a plain `text()`. Fix as proposed: `cli_token::quoted` or `validate`, plus a typed MAC.

### C-02 CONFIRMED
- checked: `configuration.rs:235-293`, `configuration/bracket.rs:94-137`, `recovery.rs:104-120`, `workflow.rs:1117-1125,1265-1269,1336-1384`, `common.ftl:44`, `kcc-mcp/src/support/raw_change.rs:52-77`.
- reasoning: Arm, disarm and keep-alive all go through `apply_cli`, so each one runs `prepare_cli` (authorize, then `check_conflict`, then `ensure_backup`). If the arm is refused locally (a Conflict, or a startup download or backup write that fails), the disarm hits the same refusal before sending anything. `arm_failed` then returns `ArmedFate::NotSent`, whose message says "may still be counting down" although nothing was sent. That breaks the invariant documented at `bracket.rs:19-23`. Separately, a foreign edit during the work makes the disarm fail `check_conflict`. The timer then fires and discards every unsaved change, including the other admin's. That case is at least reported as armed. Neither case is in the BACKLOG.
- severity: medium

### C-03 CONFIRMED
- checked: `bracket.rs:107-137`, `configuration.rs:103-121,235-274`, grep for any read of `fail_safe` before arming (none besides `decide` and the migration's `settle.rs:79`), `docs/SECURITY.md:139-143`, `docs/ARCHITECTURE.md:80-100`.
- reasoning: `guarded` never checks whether `baseline().fail_safe.active` is `true`. It arms for 300 s and always sends `no system configuration fail-safe timer` (or `no system reboot`). The cancellation is certain whatever the router does with a second arm. It also crosses a permission line: a timer that needs `Destructive` to arm (`kcc config failsafe arm`, SECURITY.md:141) is silently cancelled by a bracket authorized only by `Write`.
- severity: medium

### C-04 ADJUSTED
- checked: `interfaces/models.rs:9-38`, `wan/models.rs:60-91`, `wifi/models.rs:30-46`, `wan.rs:168-192`, `wifi/plan.rs:55-85`, `interfaces.rs:101-117`, `lib.rs:321-330`, `kcc/src/cli/dom_wire.rs:135-153`, `kcc/src/cli/domains.rs:187-200`, `kcc-mcp/src/support/shape.rs:206-237`, `kcc/src/cli/rci.rs:43-110`, Web users of `Interface.extra`.
- reasoning:
  - **The leak is real.** `Interface` flattens every unknown field into `extra`, and the WAN and Wi-Fi models drop `authentication` on purpose. The planners' own read-back (`MarkerOrLengthRange{24,256}` on `show interface …/authentication/…/ns3`) expects a real router may return the blob. `kcc interfaces list|show` prints it with only `Read`.
  - **The impact is smaller than claimed.** MCP redacts by key name (`ns3`, `password`, `psk`). The Web UI renders only modelled keys (`mac`, `mtu`, `mask`). Calling it a `RevealSecrets` bypass overstates it: the CLI role comes from `kcc.toml` and is used by the same OS user who can read `master.key` and the sealed credentials.
- severity: medium
- correction: The real issue is a rule-(d) secret in CLI output (`--json` or a terminal paste), conditional on the firmware returning the blob. It is not a privilege escalation. The fix stands: drop `authentication` at the read boundary.

### C-05 CONFIRMED
- checked: `interfaces/management.rs:26-37,41-121,182-210`, `kcc-rci/src/outbound.rs:177-206`, `RUST_GUIDELINES.md:1112-1115`.
- reasoning: `router_hosts` calls the blocking `ToSocketAddrs::to_socket_addrs` inside `async fn detect`, once for each name `classify_generated` finds. kcc-rci itself resolves inside `spawn_blocking` and pins the result (`outbound.rs:195`), so the domain code is inconsistent and can use different addresses. With no resolved hosts and no ARP or hotspot evidence, the verdict is `Unknown`, which counts as `Write` for any bridge other than `Bridge0`.
- severity: medium

### C-06 CONFIRMED
- checked: `wan.rs:109-237,240-258,276-307`.
- reasoning: `plan_identity`, `plan_password`, `plan_connect_via`, `plan_mtu` and `plan_default_route` fix `Risk::Write`. In the same module, `plan_dhcp`/`plan_static_address` use `verdict.risk(name)`, and `plan_priority`/`create`/`delete` use `classify_generated`. Callers take the risk from the plan, so no guard elsewhere raises it. The failure needs kcc to manage the router over that interface, an uncommon but supported path.
- severity: medium

### C-07 ADJUSTED
- checked: `keendns.rs:146-193,196-260`, `services.rs:207-217`, `cli_token.rs:9-19`, `catalog/5.1` (`ip http proxy upstream`, `* security-level`), `kcc-catalog/src/request.rs:14-20`, `kcc-mcp/.../services.rs:126-140`, `kcc-web/.../keendns_access.rs:140-150`, `RUST_GUIDELINES.md:424-428`.
- reasoning: The pattern is real: the code validates `{}` and then overwrites `ValidatedRequest.value`, which is a public field. But the security-level values come from typed enums (`level.name()`), so nothing can be injected there. For the proxy upstream, `protocol` and `host` must each pass `cli_token::validate` (one token with no whitespace or quotes), and the router parses them. The real leftover is that MCP and CLI accept any single-token host, while the Web UI requires an IPv4 address and the docs say "one LAN host".
- severity: low
- correction: This is a weakened catalog check with single-token inputs, not a route to arbitrary router input.

### C-08 CONFIRMED
- checked: `dhcp/model.rs:170-210`, `dhcp.rs:121-137`, catalog grep for indented `bind`/`enable`/`range`/`dns-server` contexts (`ipv6 subnet bind`, `ipv6 subnet dns-server`, `crypto map enable`, `mws wlan bind|enable`, …), callers of `read_pools` (Web, MCP, CLI, `segment_known.rs`).
- reasoning: A top-level line never closes the current pool, and the field match only needs the line to start with a space. Any later block with an indented `bind X`, `enable` or `dns-server …` overwrites the last pool. `ipv6 subnet Default` with `bind Bridge0` is the likely case. Whether such blocks really come after the pools on a real router is inferred; no fixture contains pool blocks.
- severity: medium

### C-09 ADJUSTED
- checked: `dhcp.rs:86-117`, `dhcp/model.rs:137-143`, `kcc-web/.../dhcp_forms.rs:109-113`, `kcc/src/cli/dom_lan.rs:94-121`, `kcc/src/cli/args_dom_lan.rs:61-64`.
- reasoning: `plan_pool` renders only `dns_servers.first()`. The cited Web form cannot trigger this, because it wraps a single address (`vec![server]`), and MCP sets no DNS servers at all. The CLI does trigger it: `--dns` is a `Vec<Ipv4Addr>` documented as "repeat for several", and every server after the first is silently dropped. The read-back then passes.
- severity: medium
- correction: The reachable path is `kcc dhcp pool … --dns A --dns B`, not the Web UI.

### C-10 ADJUSTED
- checked: `storage.rs:120-131,176-204`, every `catalog/*/*.json` (only 5.1 has `media partition check|format|mount`, none has `system partition`), `verification.rs:28-31`, `tests/readback/storage.rs:1-37`, `tests/verification_coverage.rs:90-102`, `kcc-web/src/system_pages/storage.rs:1-8`, `storage_tables.rs:35-36`.
- reasoning: The paths are wrong, so the operations can never run. But the Web UI does not offer them: the availability filter hides them, by documented choice (`storage.rs:5-8`), and their routes refuse through catalog validation. MCP and CLI still expose ops that always fail. The module doc's premise is half wrong, because 5.1 does have `media partition check|format`. The test pins the refusal on purpose, not by accident.
- severity: low
- correction: This is dead code under a wrong path name. Only MCP and CLI expose it; the Web UI hides it.

### C-11 CONFIRMED
- checked: `components/commit.rs:20-109`, `tests/components.rs:50-76`.
- reasoning: The first successful `poll_info` after `components commit` ends the job as `completed`, with `after` taken from a router that has not rebooted yet. Nothing waits for a down→up transition or compares the components with what was staged. The probe window is also only 40 × 250 ms = 10 s, so even a quick reboot would make the job fail instead of waiting. The test checks a fresh `poll_info`, not the job's payload.
- severity: medium

### C-12 ADJUSTED
- checked: `services.rs:197-231,258-273`, `workflow.rs:1117-1159`, `bracket.rs:94-137`, `recovery.rs:140-165`, callers (`kcc-mcp/.../services.rs:94,105`, `kcc/src/cli/dom_mgmt.rs:58,80`; none in the Web UI).
- reasoning: If the router applies the change at once, the read-back and disarm over the old endpoint fail. The timer then restores the saved configuration and the failure is reported as armed (`Failure::armed` or `ArmedFate::Unknown`). That is the bracket doing its documented job for a change that cuts kcc off, not a misreport. Other claims overreach: it is not "always" (it only applies when the change hits the listener kcc uses), and whether open keep-alive connections survive the change is unverified.
- severity: low
- correction: This is a usability gap. A planner pre-check against the profile URL would avoid a rollback the user can predict; correctness is not broken.

### C-13 ADJUSTED
- checked: `configuration.rs:242-292,346-396`, `system.rs:196-210`, `clients.rs:220-229`, `dhcp.rs:164-170`, `clients/command.rs:36-48,121-171`, `catalog/{4.3,5.0,5.1}/system.json` (all have `fail-safe timer` and `system reboot`), BACKLOG:85.
- reasoning: The `map_err(|_| InvalidResponse)` pattern is there. In practice, though, the lost errors are almost always `InvalidResponse` already: the `cli_line` and `complete` errors are themselves `InvalidResponse`, and every catalog has the arm and reboot paths, so `Validation{issues}` is lost only in theory. The format-then-reparse of `seconds` is ugly but correct; BACKLOG:85 tracks its missing test.
- severity: low

### C-14 ADJUSTED
- checked: `lib.rs:1-12`, `system.rs:1-8,170-190,283-290`, `interfaces.rs:1-8`, `wan.rs:276-285`, 34 files in kcc-domain with `#![expect`, `RUST_GUIDELINES.md:1650-1661,2050-2057,2090`, project overlay "Deviations" (not listed there).
- reasoning: Module- and crate-level `missing_errors_doc` and `missing_inline_in_public_items` expects go against "narrowest item" and "Production code … writes the sections". The parameters `_rci_path: Vec<&str>` and `_name` really are dead. But the link to the expects is weak: underscore-prefixed parameters are already hidden from the unused-variable lints, whatever the expects say.
- severity: low

### C-15 CONFIRMED
- checked: `configuration/close.rs:81-85`, `workflow.rs:1167-1189,1388-1406`, `kcc/src/cli/closing.rs:22-47`, `migrate.ftl:25`.
- reasoning: `commit()` already waits until `unsaved == false` before returning. The following `save()` repeats its own conflict check and a request. If that save fails, the result is `Failure::committed`, which the CLI reports as `MIGRATE_COMMITTED_NOT_SAVED` ("startup configuration was not saved") although the commit already saved it. The behaviour is documented in `close.rs:56-57`, but the wording is still false.
- severity: low

### C-16 ADJUSTED
- checked: `close.rs:52-80`, `recovery.rs:122-165`, `kcc/src/cli/closing.rs:22-47`, `kcc-migrate/src/apply/finish.rs:40-72`, `kcc/src/cli/preset/finish.rs:80-104`.
- reasoning: The doc is wrong: a failed keep-unsaved disarm gives `ArmedFate::Applied`, not `Saved`. But every caller branches on `fate()`/`applied()` (CLI `(_, true, true)` gives Applied; migrate gives `DisarmFailed`), so nothing shows "saved". The impact claim is hypothetical.
- severity: info

### C-17 CONFIRMED
- checked: grep: 10 copies of `replace('~', "~0")`, local `validate_token` in `storage.rs:290`, `logging.rs:241`, `schedules.rs:260` (all identical to `cli_token::validate`), 8 copies of `fn validate(`, `map_domain_error` in `clients/command.rs:204` and `dhcp.rs:245`.
- severity: low

### C-18 CONFIRMED
- checked: `interfaces/guard.rs:13-72`, grep for production callers of `is_fail_safe_unarmed`/`ns3_presence` (tests only), `workflow.rs:1141`.
- reasoning: The functions are used only by tests, and `guard::apply` repeats a `show last-change` that `apply_cli` has already done. One correction: `is_fail_safe_unarmed` could be true in production (an arm verification failure converts through `From<WorkflowError>`); it is simply never called.
- severity: low

### C-19 CONFIRMED
- checked: `diagnostics.rs:201-225`, `kcc-rci/src/engine/background.rs:99-135`.
- reasoning: The diagnostics job polls every 10 ms (plus the round trip) instead of the 1 s default, for the whole iperf3 or traceroute run.
- severity: low

### C-20 ADJUSTED
- checked: `schedules.rs:137-148,170-190`, `catalog/5.1/schedule.json` (`description: String`), `kcc-web/src/system_pages/schedule_forms.rs:1-4,59-64,97-120,136-142`, `interfaces.rs` (`quoted_text`).
- reasoning: Refusing spaces is a documented, tested choice ("The router's CLI takes a schedule's … description as one word each"). It is only a bug if that premise is wrong. The catalog types it as `String`, and interface descriptions are sent quoted, so the premise looks doubtful but is not disproven.
- severity: info

### C-21 CONFIRMED
- checked: `bracket.rs:107-122`, `kcc-web/src/brackets.rs:117-160`.
- reasoning: An unheld request is reported as `AuditError::WriterUnavailable`. It is mostly unobservable, because the client is gone (BACKLOG:74 covers the matching 503). On the arm-failure path, the `settle_audit` error is dropped. The arm error is still returned, but an audit writer failure in that window is never reported.
- severity: low

### C-22 CONFIRMED
- checked: `router_users.rs:145-176`, `wan.rs:168-192`, `wifi/plan.rs:55-85`, `web.ftl:1914`.
- reasoning: Every secret write is checked for presence only. For Wi-Fi and WAN the user is told so ("kcc checks only that it is there"). Comparing the hash or marker before and after the write would catch an ignored write without revealing the value.
- severity: low

### C-23 ADJUSTED
- checked: `clients.rs:220-229`, `clients/command.rs:36-118`, `dhcp.rs:164-196`, `dhcp/command.rs:33-51`, `verification.rs:99-140`, `workflow.rs:1126-1153,1489-1495`.
- reasoning: The audit outcome for these change-settings commands is `applied_unsaved`, not `success`. Also, `verification::complete` adds running-config presence checks before the audit for DHCP always, and for clients unless a policy command is in the batch. So the gap is only the extra post-audit read-back (`show rc ip dhcp host` / `show ip hotspot`), plus client host lines that are batched with a policy command, which get no check before the audit.
- severity: low

### C-24 CONFIRMED
- checked: `router_users.rs:127-143,145-189,271-279`, callers in Web, MCP and CLI.
- reasoning: `plan_tag` protects only the literal `admin` against losing `cli`; `plan_password` and `plan_delete` protect the profile's login. The plan is `Risk::Management`, so if kcc locks itself out, the bracket's timer reverts it. The cost is losing unsaved work, not a permanent lockout. Which tags actually gate RCI access was not verified.
- severity: low

### C-25 CONFIRMED
- checked: `tests/system.rs:118-130`, `tests/components.rs:50-76`, `verification_coverage.rs:90-102`, `verification_coverage/tests/administration.rs:135-147`.
- reasoning: The `FakeRouter` in `system.rs` is built but never spawned or used, and the test checks a pure function, so `request_count() == 0` cannot fail. The other three examples hold as stated.
- severity: low

## Summary
- **CONFIRMED (12):** C-02, C-03, C-05, C-06, C-08, C-11, C-15, C-17, C-18, C-19, C-21, C-22, C-24, C-25. That is 14 ids; the true count is in the next line.
- **Corrected counts:** CONFIRMED 14 (C-02, C-03, C-05, C-06, C-08, C-11, C-15, C-17, C-18, C-19, C-21, C-22, C-24, C-25). ADJUSTED 11 (C-01 high→medium, C-04 medium with narrower impact, C-07→low, C-09 medium with the path corrected to the CLI, C-10→low, C-12→low, C-13→low, C-14→low, C-16→info, C-20→info, C-23 low with narrower scope). REFUTED 0. DUPLICATE 0.
- **NEW (not in this review's scope):** `ChangeSet::apply_cli` returns from `dispatch_cli(...)?` (`workflow.rs:1125`) before `audit_cli` (`:1151`). A batch whose first lines applied and a later line failed (for example the C-01 pool batch, where the injected first line applies and the following `ip dhcp pool <name> range …` lines likely fail) gets no `router.change_cli` workflow entry. I did not check whether MCP, Web or CLI write a separate failure entry.