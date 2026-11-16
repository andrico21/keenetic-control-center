# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

The first release, `0.1.0`, is in preparation and contains:

- **RCI client** with ndw2, ndw4 and HTTP digest sign-in, an outbound policy with DNS
  pinning and no redirects, certificate verification or public-key pinning, and
  firmware, model and capability detection.
- **Command catalogs** for KeeneticOS 4.3, 5.0 and 5.1 generated from the official
  manuals, with validation of every request and CLI line before it is sent.
- **Web UI**: fleet dashboard with live status and traffic, clients, DHCP, segments,
  interfaces, internet connections, Wi-Fi, mesh, static routes, routing table,
  connection policies, NAT, firewall, DNS, VPN clients and servers, system pages
  (general, router users, services, components, storage, schedules, KeenDNS, log,
  diagnostics), configuration and backups with diff and raw restore, presets and
  settings copy, a nine-step migration wizard, a command explorer with RCI and CLI
  consoles, and administration of users, roles, API keys, the audit log and the
  server. Six languages and light and dark themes.
- **MCP server** over Streamable HTTP with API keys and over stdio: 68 tools in eight
  toolsets, role and router-scope checks, destructive-operation gates, secret
  redaction and optional client pseudonymization.
- **CLI** covering router profiles, reads and writes of every domain, raw validated
  RCI, configuration state and saving, backups, presets, settings copy, migration,
  users, API keys, the audit log, TLS certificates and health checks.
- **Change workflow**: per-router lease, automatic encrypted backup, conflict check,
  read-back verification, hash-chained audit log with a cross-process append lock, and
  the router's fail-safe timer around risky changes.
- **Migration and presets**: classification rules, mapping, realm-bound password
  handling, management-phase reconnect, fail-safe apply with rollback, Merge and
  Mirror presets, and WireGuard key regeneration.
- **Monitoring**: a Prometheus exporter, Grafana dashboard and alert rules, and router
  log forwarding to Loki, Elasticsearch, OpenSearch and stdout.
- **Security**: encrypted state, Argon2id account and API-key hashes, CSRF and
  session hardening, and a privilege floor that refuses root.
- **Packaging**: static release archives for Linux, macOS and Windows with
  `SHA256SUMS`, and a distroless OCI image with a rootless Podman deployment and a
  traced seccomp profile.
- **Documentation**: user guide, configuration reference, migration, security,
  privacy and architecture documents, with executable checks.

- **MCP error code `router_mode_unknown`**: a management change is refused, with nothing
  sent, when the router reports neither a system mode kcc knows nor a `fail-safe`
  timer in `show last-change`. Every surface now picks the recovery mechanism with the same
  rule, so a router that reports no system mode (KeeneticOS 4.3 and 5.0) is protected
  by the fail-safe timer on the CLI and MCP too, instead of a scheduled reboot.

- **MCP error code `management_not_sent_fail_safe_armed`**: the router refused the
  recovery arm of a management change and then refused its disarm, so nothing else was
  sent but the timer may be armed. Such a failure used to read as
  `management_outcome_unknown_fail_safe_armed`. A refused arm whose disarm was accepted
  keeps the original error code and adds a `message` saying nothing was applied and the
  timer is off. MCP management changes now run through the same bracket as the other
  surfaces, and the timer kcc arms around a management change is authorized by the
  change's own permission (`Write` or `RawRci`) instead of `Destructive`; raw management
  changes still need `[mcp] allow_destructive = true` and `confirm: true`.

- **Migration failure name `ArmUnconfirmed`**: a migration or preset run whose recovery
  arm could not be confirmed and whose cleanup was refused reports this name (Web run
  state) and the MCP code `management_not_sent_fail_safe_armed`: nothing was sent, but
  the timer may be armed. A run that fails after arming now disarms the timer
  or reports `FinishFailed` (MCP `management_outcome_unknown_fail_safe_armed`), and a
  component install ends with `ReplanRequired` and no timer armed.

- **MCP error code `migration_rollback_restarting`**: `kcc_migration_finish` answers a
  scheduled-reboot rollback that the router accepted before it stopped answering with
  this code (it used to be `router_unreachable`) and closes the migration, so a retry
  cannot reboot the router again. The Web wizard and the preset page close the run the
  same way.

- **MCP error code `management_saved_fail_safe_armed`**: the configuration was saved but
  the recovery timer could not be disarmed, so the router may restart with the saved
  configuration, which includes the change. Such a failure used to read as
  `management_applied_fail_safe_armed` (bracketed changes) or
  `management_outcome_unknown_fail_safe_armed` (migration finish).

- **Every router credential the CLI takes is sealed**: `kcc router add` and
  `kcc router edit` read `--password-file` as input only and seal the password into
  `<state>/router-credentials/<id>.sealed` (the file can be deleted afterwards); new
  options `--auth <auto|ndw2|ndw4|token|digest>`, `--token-file` (sealed into
  `<id>.token.sealed`, accepted only with `--auth token`), `--read-login` with
  `--read-password-file` (sealed into `<id>.read.sealed`), and on edit `--new-token`,
  `--new-read-password` and `--clear-read-login`. Changing a router's URL, login or TLS
  pin needs the password or token again and clears the read-only login unless it is
  given again, on the CLI and in the Web UI. A migration that changes the management
  password of a Web UI or CLI router seals it instead of writing the profile's external
  file. Router add/edit audit entries list the credential kinds that changed
  (`"credentials": ["password", "token", "read"]`), never values. A state router that
  still names an external password file is warned about once per CLI run and at
  `kcc serve` startup.

- **The Web UI router form sets every credential kind**: a sign-in mode select (`auto`,
  `ndw2`, `ndw4`, `digest`, `token`), an API token field shown only for mode `token`, and
  an optional read-only polling login and password with "Remove read-only login" on
  edit. Each secret is sealed into `<id>.sealed`, `<id>.token.sealed` or
  `<id>.read.sealed`, never shown again (the form only notes that one is stored), and
  follows the CLI's rule: a new address, login or TLS pin, or a switch between password
  and token sign-in, needs the new primary credential. The `router.profile_create`,
  `router.profile_update` and `router.profile_delete` audit entries name the credential
  kinds in `"credentials"` instead of the former `credentials_changed` flag.

- **One message per migration failure**: the CLI, the Web UI, MCP and the engine report
  each migration failure with the same sentence. `ReplanRequired` asks to review the plan
  again everywhere (the preset page used to show the drift text), and the MCP migration
  finish reports a failed disarm by what it left (`management_applied_fail_safe_armed`
  or `management_saved_fail_safe_armed`) instead of always
  `management_outcome_unknown_fail_safe_armed`.

### Changed

- **A management change is refused while somebody else's recovery timer runs.** When the
  router's fail-safe timer is already active (armed with `kcc config failsafe arm`, the
  Web UI or a migration), a management change on any surface is refused before anything
  is sent, with the message `management-timer-in-use` (CLI exit 5, MCP `conflict`, Web
  audit outcome `conflict`). Before, the change's own 300-second bracket replaced that
  timer and then disarmed it, so the operator's safety net was silently gone. A request
  the Web no longer holds is now reported as unowned instead of as a dead audit writer.
- **A component commit job completes only after the router restarted.** It waits (at
  most 15 minutes) until the router went down and came back, reports progress 60 once it
  went down, and completes only when the restarted router has every queued installation
  and none of the queued removals; otherwise it fails. Before, it completed on the first
  answer after the commit, while the router was still flashing, and reported the old
  components.

- **The conflict check refuses a change by any other client.** A write, save or commit
  is now refused when the router's configuration checksum differs from the state kcc last
  observed after its own writes, whoever changed it. It used to require a different
  last-changing agent as well, but every RCI client (another kcc, a script, the router's
  web interface) reports the same agent as kcc, so such changes went unnoticed. kcc's own
  earlier writes in the same change are never a conflict.
- **Wizard runs are bounded.** A user keeps at most 10 unfinished runs of the migration
  wizard and 10 of presets and copy settings; another start is refused (422, audited as
  `refused` with `reason: "limit"`). A run unchanged for a day counts as abandoned and no
  longer counts. Runs of either wizard unchanged for 30 days are deleted when the wizard's
  page is next opened, preset runs included (before, only a copy run's sealed settings
  were dropped after a day). The run lists read a per-wizard owner index
  (`<state>/migrations/index-wizard.json`, `index-preset.json`), rebuilt from the runs when
  missing or unreadable, instead of every run.
- **An unfinished apply lets the router go when its recovery timer ends.** A Web wizard
  apply or an MCP migration or preset apply that nobody commits, keeps or rolls back
  releases the router's write lease once the armed fail-safe interval has passed since the
  last renewal; the Web run ends as rolled back by the router, the MCP record is closed.
  MCP keeps a record without a lease for an hour and at most 64 unapplied plans (oldest
  forgotten first); a plan is refused with `conflict` while an apply on its target runs.

- **The Web audit page and export respect the viewer's router scope.** A role scoped to
  some routers no longer sees entries of other routers, and entries that name no router
  are shown only to roles scoped to all routers (empty scope or `*`). The page verifies the
  chain once and reuses the result until an audit file's length or modification time
  changes, formats only the shown page, and the export is streamed.

- **Audit request ids are unique.** Every `request_id` in the audit log (and the one MCP
  returns with a tool result) is now `<prefix>-<nonce>-<n>`: a random 64-bit nonce per
  process in hex and a counter, for example `web-3f9c0a1e5b7d2468-12`. Workflow entries
  used `change-<unix-ts>` and `save-<unix-ts>`, CLI entries `cli-<unix-ts>` and credential
  migrations `startup-<unix-ts>`, so entries from the same second shared an id; Web and
  MCP ids (`web-<n>`, `mcp-<n>`) restarted with every process. All entries of one change
  set now share the set's id (a library caller can pass its own with
  `ChangeSet::with_request_id`), and all entries of one CLI run share the run's id. A
  reboot or factory reset result (`TerminalCliChangeResult`) keeps its audit receipt and
  serializes `"audit_pending": true` while its entry is still queued.
- **Router URLs with an IPv6 literal work.** A router URL such as `http://[fd00::1]` was
  always refused as outside the outbound policy, because kcc looked the bracketed text up
  as a host name. A literal IPv4 or IPv6 address is now checked as an address.
- **Unused VPN-server secret gate removed**: `kcc_domain::vpn_servers::secrets::RevealSecrets`
  (and its `read_stored`) had no caller, recorded no audit entry and did not bind its
  router-scope check to the router it read.
- **Unused library entry points removed**: `kcc_migrate::source::MigrationSource`,
  `LiveRouterProfile`, `load_source` and `SourceConfig::from_live`,
  `kcc_migrate::inventory::InventoryClient::connect` and `kcc_rci::RciClient::connect`.
  They connected with a built-in policy instead of `[outbound]`; kcc reaches routers
  only through the registry's policy-checked clients (`InventoryClient::from_client`).
- **Sealed state is bound to its record type.** Every value sealed with the master key
  carries its record type and owner as associated data: `router:<id>`,
  `router:<id>:token` and `router:<id>:read` for router credentials, and
  `account:<username>` for web account password hashes (backups, presets and migration
  parts already had their own prefixes and keep them). A router password and an account
  of the same name can no longer be swapped. Router credential records are now schema 2.
  State written by earlier builds is not readable and there is no upgrade path (kcc has no
  deployments): a schema-1 router credential record is refused as an invalid record, and
  signing in to an account whose hash an earlier build sealed fails with an error (the
  Web UI answers 500) instead of "invalid username or password".
- **Credential store paths check the router id.** `CredentialStore::open`, `exists`,
  `manages`, `sealed_path`, `legacy_path` and `remove` refuse an invalid router id with
  `CredentialError::Record` before they build a path, as their documentation said; they
  used to build the path from it.
- **One slow router no longer holds up the others.** The shared client of each router
  is built on its own, and its credential files are read off the async workers, so a
  router whose name resolves slowly or whose credential read stalls delays only requests
  to that router.

- **One error vocabulary for changes**: a domain failure met inside a change is worded the
  same way on the Web UI, MCP and the CLI. On MCP, `kcc_interfaces_write` failures now
  carry their own code (`verification_failed` with its `field`, `forbidden`,
  `router_unreachable`, `router_rejected`, `validation_failed`, ...) instead of always
  `conflict`; a CLI line that cannot carry its request (ports on an `icmp`, `esp`, `gre`,
  `ipip` or `ip` rule, a DNS route with neither gateway nor interface) answers
  `validation_failed` instead of `internal`, and so does removing a firewall rule that is
  absent. `resources/read` answers `router_unreachable` (was `internal`) for a router that
  does not answer and for a name no router profile has, without polling it, and audits a
  read outside the caller's scope as a `forbidden` attempt of `mcp.resources_read`.
  `kcc_migration_plan` reports a system mode kcc does not know by the router's own name
  (was `other("<name>")`). On the Web UI, a change the role may not make is answered
  403 on every page. Logs and CLI messages name an unsupported firmware, an undecodable
  configuration and an unexpected response body instead of "invalid last-change
  response"; the CLI exit classes are unchanged.

- **Rust 1.100.0**: the minimum supported Rust version (`rust-version`) and the pinned
  toolchain of CI, the release and container builds and the `Containerfile` builder
  are now 1.100.0.

- **Audit format of refused and failed attempts**: every surface records them the same
  way: outcome `forbidden` with `reason: "forbidden"`, `refused` with a `reason` code,
  or `failed` with an `error` code, plus `fail_safe_armed: true` only when the recovery
  timer may still be armed. A Web change that left the timer armed used to be audited
  with the outcome `fail_safe_armed`; it is now `failed` with `fail_safe_armed: true`
  next to the page's own parameters. Web migration and preset finishes add
  `error: "router"`, CLI permission refusals add `reason: "forbidden"`, and a CLI
  failure with no timer armed no longer writes `fail_safe_armed: false`. The CLI now
  audits a missing confirmation as `cli.refused` with outcome `refused` and
  `reason: "confirm_required"`. The hash chain and success entries are unchanged.

- **Operators can apply migrations, presets and settings copies**: an apply needs `Read`,
  `Migrate`, `Write` and `Save` on every surface, so the built-in `operator` role can
  apply and finish by keeping or saving. The recovery timer around the run is armed,
  kept alive and disarmed under the run's `Migrate` instead of `Destructive`, and
  rolling back a failed run needs nothing more. `Destructive` is still checked before
  any router request for a rollback finish (`--finish rollback`, `migrate finish
  rollback`, `preset finish <run> rollback`, the Web rollback buttons and
  `kcc_migration_finish` with `rollback`, which now answers `forbidden` without it), a
  plan that installs components, a raw restore, and explicit timer control
  (`kcc config failsafe arm|rollback`, `kcc config keep-alive`, the Web standalone
  rollback). Finishing a kept migration or preset in scheduled-reboot mode no longer
  needs `Destructive`. MCP raw management changes still need
  `[mcp] allow_destructive = true`.

- **Management changes need only their own permission**: on the CLI, the Web UI and MCP,
  a role that holds a change's own permission (`Write`, `RawRci`, `Migrate`) can make a
  management change and arm and disarm the recovery timer around it. `Destructive` is
  checked only for a destructive risk (removals, deletions, the raw timer commands) and
  for explicit timer control. Interface changes no longer arm a timer of their own: they
  run in the same bracket as every other management change, which uses the scheduled
  reboot on an extender, access point or repeater and the native timer in router mode.
  The server switch is unchanged: raw management changes over MCP still need
  `[mcp] allow_destructive = true` and `confirm: true`.

- **Every Web change asks for the confirmation its planned risk needs**: the Web kit
  derives the dialog from the risk the domain planned, so no page can run a management
  or destructive change without one. A management change shows the dialog explaining the
  fail-safe timer and sends nothing until confirmed; a destructive one asks for the
  router name typed, unless the page's own dialog already asked for a name. Newly asked:
  disabling the access point kcc reaches the router through, its Wi-Fi schedule, a
  segment created on the interface or access point kcc uses, internet connection
  settings and priority order when the domain plans them as management changes, and
  releasing the KeenDNS name kcc reaches the router by (now a management change, run
  inside the fail-safe timer). A role that may not take the planned risk is refused
  without a dialog. A destructive change that also changes how kcc reaches the router
  keeps the fail-safe timer.

- **Firewall pages follow the shared permission rule**: a management firewall change
  (a list applied to, or a rule of a list on, the interface kcc reaches the router
  through) needs only the change's own `Write`, as on every other page; it no longer
  needs `Destructive`. It still asks first and runs inside the fail-safe timer.

- **The recovery mode comes from fresh router facts**: every surface chooses the native
  fail-safe timer or the scheduled reboot with one rule (see `router_mode_unknown`
  above). A router whose mode is unknown is refused before anything is sent: the CLI
  exits 10, the Web UI shows a message saying so, and MCP answers `router_mode_unknown`.

- **Finishing a bracket is one step**: `kcc config failsafe commit` in router mode now
  sends the native commit and then saves, as migration and preset finishes do.
  `kcc config failsafe rollback` and `kcc preset finish <run> rollback` on a router in
  extender, access-point or repeater mode reboot it at once instead of sending the native
  rollback, and say so (`failsafe-rollback-rebooting`).

- **Web changes end even when the browser leaves**: every Web write is owned by the server
  from the moment it reaches the router, so an ordinary write the router applied is
  audited and a management change is disarmed whatever the browser does. The migration
  and preset finish routes use the same budget (they no longer answer 408 at 30 s and
  drop the rollback). `kcc serve` and `kcc mcp stdio` wait for the open brackets of every
  surface (at most 10 s) before they exit. A write the server could not own is refused
  before anything is sent, with its own message.

- **`kcc migrate apply` asks before it touches the router**: it asks for confirmation on
  the terminal, or takes `--yes`. A refusal exits 10, sends nothing and is audited as
  `cli.refused` with `reason: "confirm_required"`. Scripts that call `kcc migrate apply`
  without a terminal must add `--yes`.

- **The CLI says "Done." or "not saved yet" by what happened**: a command that sends no
  configuration (for example `kcc components check-update`) prints `Done.`, and the
  "not saved yet" line appears only when the router reports unsaved configuration. CLI
  apply refusals name the missing permission, or say the role is not allowed on this
  router.

- **Control characters in names and descriptions are refused**: `kcc` no longer sends a
  tab, newline, NUL or other control character in an interface description, firewall rule
  description, Wi-Fi name, mesh member or similar text to the router CLI. It used to turn
  them into escapes the router read as letters. Quoting of ordinary text, quotes,
  backslashes and Unicode is unchanged.

- **`StopTimeout=80` in the Quadlet unit** (`deploy/podman/kcc.container`): the stop timeout
  now covers the whole shutdown budget (server shutdown 30 s, open brackets 10 s, job
  drain 30 s, audit flush 5 s, margin 5 s).

- **Toolchain gates**: the CI gate tools (cargo-deny, cargo-audit, cargo-vet,
  cargo-machete, taplo) are pinned, and Cargo ignores crate versions published less than
  three days ago (`.cargo/config.toml`).

- **Maintenance**: the Web UI's pages share one submit pipeline, form, confirmation and
  table kit and one wizard engine for migrations and presets (routes, HTML ids and form
  field names are unchanged); the workspace takes shared dependency versions from
  `[workspace.dependencies]` and `Cargo.lock` is unchanged; unused code and unused
  message keys were deleted.

- **KeenDNS proxy upstream is checked as sent**: the upstream line
  (`ip http proxy <name> upstream <protocol> <host> <port>`) is validated against the
  catalog before it is planned, on the Web, MCP and CLI alike. The protocol must be
  `http`, `https` or `connect`, the host an IP address, a MAC address or a host name
  (the catalog now types the command's `fqdn` form as a host name instead of the
  literal word `FQDN`), and the port 1 to 65535. Before, the protocol and host were
  checked only as one CLI word each, and MCP and the CLI accepted port 0.

- **Free text is quoted and identifiers are single words in router command lines**, on
  the Web, MCP and CLI alike:
  - Client registration names, connection-policy descriptions, DNS filter-profile and
    FQDN-group descriptions, and schedule descriptions are sent as one quoted word, so a
    name or description with spaces (for example `Anna phone`) is kept whole. Schedule
    descriptions with spaces are now accepted by MCP and the CLI.
  - An empty registration name is refused. Before, an MCP `access`, `schedule`, `policy`
    or `priority` change on an unregistered client with no `value` sent
    `known host  <mac>`.
  - DHCP pool names and access-list names (firewall rules and bindings) must be router
    object names: letters, digits and `_ . / : -`, up to 64 characters. A name with
    spaces is refused.
  - DNS names, upstream fields and NextDNS tokens, VPN client interface names, WireGuard
    peer keys and other VPN client fields, and crypto-map names must each be one word.
  - The static-lease and client-registration MAC must be a MAC address
    (`kcc_dhcp_write`, `kcc_clients_write`, `kcc dhcp static-lease`,
    `kcc clients register`).
  - The CLI registers an unregistered client under its router-reported name with every
    character other than letters, digits, `_` and `.` replaced by `-`, like the Web
    clients page; before, it used the reported name unchanged.

- **A router command line is sent only with the request it was checked as**: every CLI
  line kcc sends (Web, MCP, CLI, migration) must render the catalog request that was
  planned, previewed and audited for it: the same command and the same argument values,
  a quoted word read as its text, and for an unvalidated raw line exactly the line that
  was authorized. Any other pairing is refused before anything is sent. Lines that did
  not follow the catalog grammar now do:
  - An IPv6 static route names the interface before the gateway
    (`ipv6 route <prefix> <interface> <gateway>`), as the manual documents.
  - A DNS filter-profile description is sent as
    `dns-proxy filter profile <name> description <text>`.
  - Disabling an interface or an access point is planned and audited as `interface down`
    (was `interface up` with `no`); the line sent is unchanged.
  - Deleting a segment is planned and audited as the `no` commands it sends
    (`interface`, `interface include`, `ip dhcp pool`, `ip nat`, `ip hotspot policy`,
    `ip policy`, `interface switchport trunk`), and creating its VLAN interface as
    `interface vlan-id`.
  - A static lease is validated with its host and its address as separate arguments.
  - Moving a firewall rule validates the new position (`order <new-index>`).
  - Refused while planning: a DNS route with neither a gateway nor an interface, and a
    firewall rule with ports on a protocol other than `tcp` or `udp`; the manuals
    document neither.

- **The command catalogs read more of the manuals' syntax**, so the CLI console, the MCP
  `kcc_cli_parse` tool and migration accept these documented forms: commands whose
  synopsis starts with their own group (`vpn-server`, `sstp-server`, `oc-server`, `ndns`,
  `nextdns`, `system`, `show` commands), commands documented with several synopsis lines
  (the `icmp`, `esp`, `gre`, `ipip` and `ip` forms of `access-list permit` and `deny`),
  `<address>:<port>` arguments (`system log server`, `interface wireguard peer endpoint`)
  written as one word or as two, optional arguments the manuals print without argument
  markers (for example `ip dhcp host <host> [<mac>] [<ip>]`, `no known host <mac>`,
  `no interface <port> switchport trunk vlan <vid>`, and the `ip route` metric, now also
  on 4.3), and the `order <new-index>` argument of `access-list rule`. Synopsis errata in
  `catalog/synopsis-errata.json` correct `nextdns assign` and `oc-server pool-range` and
  add the undocumented `interface <name> vlan-id <vid>` that segments send; migration
  still does not replay `vlan-id` lines.
- **`--from` takes the same sources everywhere.** `kcc migrate plan|report|apply`,
  `kcc preset capture` and `kcc copy` accept `<router-id>` or `router:<id>`,
  `backup:<router>/<name>` and `file:<path>`; `migrate` now also takes a bare router id.
  An unknown `<scheme>:` prefix or an empty router, backup or path is a usage error
  (exit 2) in every command.

### Fixed

- **Finish outcomes tell when the recovery timer is still armed.** A migration or preset
  commit or keep-unsaved that finds the target changed since verification, or cannot
  detect the target, now fails as `FinishFailed` (timer still armed; MCP
  `management_outcome_unknown_fail_safe_armed`) instead of `Drift` or `Unreachable`
  with the timer reported off, and so does a rollback that cannot detect the target.
- **A router-mode save sends the fail-safe commit alone.** The commit already saves the
  startup configuration; the second `system configuration save` after it is gone, so a
  refused second save can no longer report a saved configuration as "committed but not
  saved".
- **An audit writer failure after a failed recovery arm is reported** as the bracket's
  failure instead of being dropped.

- **A recovery timer's disarm, keep-alive and rollback are always sent.** They no longer
  run the conflict check and the automatic backup of a configuration change (they still
  need the change's permission and router scope). Before, a change by another client during a
  management change, or a failed backup, kept the disarm from being sent: the timer then
  fired and discarded all unsaved changes. A management change whose preflight is refused
  before its arm now sends nothing and reports that nothing was applied, instead of "the
  router may still be counting down".
- **Wizard Apply and sessions.** An Apply whose request ends (the browser went away, the
  request budget ran out) before its job starts no longer keeps the router claimed until
  kcc restarts: the target is read first and reserved only right before the job starts.
  A wizard run's in-memory session is created only after the run's owner is checked, and
  is never forgotten while a request, its turn or its apply uses it, so other users' visits
  can no longer break one-request-at-a-time on a run or lose an apply's result.
- **MCP migration finish no longer holds every migration.** A commit or rollback waiting on
  its router (a reboot wait included) locks only its own record; other migrations' plans,
  applies and reports go on.

- **Every successful or partial action is audited, with the request id the client got.**
  - MCP `kcc_backup_create`, `kcc_preset_capture`, `kcc_preset_delete`, `kcc_job_cancel`
    and the diagnostic start of `kcc_diagnostics_write` now append a `success` entry
    (action `mcp.<tool>`, the same action as the tool's failures; params hold only ids
    such as the preset id and groups or the job id). Their result carries
    `"audit_pending": true` while the entry is still queued behind another process's
    append lock.
  - MCP `kcc_system_write` (`reboot`, `factory_reset`), the credential operations of
    `kcc_vpn_clients_write` and `kcc_vpn_servers_write` (`ike_psk`, `ipsec_psk`,
    `ppp_password`, `profile_psk`, `profile_xauth`) and `kcc_segments_write` now report
    `"audit_pending": true` like every other write. `kcc_domain::vpn_clients::secrets::apply`
    and `kcc_domain::vpn_servers::secrets::apply_ike_psk` return the change's
    `CliChangeResult` (with its audit receipt) instead of `()`; `ChangeSet::queued_audit`
    returns the handles of a set's entries still queued.
  - Every MCP tool call now runs in an `mcp_tool` tracing span with fields `request_id`
    and `tool`, so a logged failure cause carries the `request_id` the client receives,
    and the workflow entries of the call's change set carry that id too (`mcp-...`
    instead of the set's own `change-...`).
  - A change of several CLI lines (`ChangeSet::apply_cli`, behind the curated writes of
    every front end) whose later line the router refuses now writes its
    `router.change_cli` entry with outcome
    `partially_applied_unsaved` or `partially_applied_persisted` and params
    `{"error": "router_rejected", "succeeded": n, "failed": m}`, like a partly refused
    root batch; it used to record nothing of the lines already applied.
  - A Web migration or preset finish the router carried out (commit, keep, rollback) is
    audited before its record is saved, so the `web.migrate_commit`/`web.preset_save`
    entry stays when the save fails (HTTP 500). A finish with no apply waiting for it
    (HTTP 409) is audited as `refused` with `reason: "conflict"`, and one refused for
    having no server owner (HTTP 500) as `failed` with `error: "internal"`. A request on a
    run that names a router outside the user's `Migrate` scope (HTTP 403) is audited as
    `web.migrate_run` or `web.preset_run` with outcome `forbidden`, the run id as target
    and the refused router.
  - The CLI audits the permission and scope refusals of `kcc backup list|get|diff|delete`
    and `kcc router add|edit|remove|test` as `cli.refused` with outcome `forbidden`, like
    refused router commands (exit 10 as before).
- **Audit waits are bounded, and nothing waits for room in the audit queue.** Once 128
  audit entries were queued behind another process's append lock, every further action
  waited without limit for room: a management change inside its recovery bracket never
  reached its disarm, and a Web sign-in hung despite its 5 s bound. The queue to the
  audit writer is now unbounded, so queuing never waits and no entry is dropped (while the
  lock is held the queue grows in memory). The Web sign-in, sign-out and password change
  take one of 128 queue slots within their own wait instead; **a sign-in whose entry finds
  no slot within 5 s is now refused (HTTP 500, no session)** rather than signed in
  without an entry, and a failed sign-in, sign-out or password change answers HTTP 500
  after 30 s, as it did when its entry could not be written.
- **A torn audit line no longer stops kcc.** A crash or a full disk in the middle of an
  audit append left a last line without its newline, after which every append failed,
  the audit writer stopped and `kcc serve` and every audited CLI command refused to start
  until `audit.jsonl` was edited by hand. The incomplete line is now moved to
  `audit.jsonl.torn-<unix-ts>` in the state directory (owner-only, the bytes unchanged;
  `-2`, `-3`... are added when the name is taken) when the writer starts or before its
  next append, a warning is logged and a new `audit.repair` entry (actor `system`,
  outcome `success`, params `file` and `bytes`, never the content) continues the chain.
  `kcc audit verify` and the Web audit page skip an unterminated last line of the active
  file. A complete line that does not verify is still refused as tampering.
- **Audit appends no longer re-read the retained log.** Each append used to parse and
  re-hash every retained entry under the cross-process lock, so its cost grew with up to
  a year of log. It now reads only the last line of the newest file and checks that
  entry's own hash; the whole chain is still verified when a writer starts, by
  `kcc audit verify` and on the Web audit page.
- **A change whose existence check cannot read the router no longer takes the object as
  absent.** "Add account" used to go ahead (and could rewrite an existing account) when
  the router's account list could not be read; component install or removal, the storage
  Eject, Check and Format actions, dropping the KeenDNS name and the router-account tag
  and delete dialogs answered "not found". Each now answers that the router did not
  answer, audited as `unreachable`, and sends nothing.
- **A failed Web sign-in shows its error.** A wrong password or a locked account used to
  answer 401, which the page never displays, so the form stayed as it was with no
  message. The refused sign-in now answers 422 with the same uniform "invalid username
  or password" text, in the sign-in page's language (it used the server's default
  language). The "UTC" after times and the parentheses around the "(you)" marker of the
  accounts table are now part of the translated messages.
- **The Web router form's Test connection honours the sign-in mode.** It used the default
  mode whatever the form said and never used a typed API token (on the add form in mode
  token it answered with the id or password error). It now signs in with the selected
  mode and the typed password or token, and nothing is stored.
- **Test connection no longer shows a server file path.** A credential file other users
  can read gets the chmod hint without the path (new Web message
  `web-router-error-permissions`); the path is logged at warn level on the server.
- **A failed router edit no longer leaves new credentials sealed for the old profile.**
  The Web router form and `kcc router edit` used to seal the new password, token or
  read-only password before storing the changed profile, with no way back: a refused or
  failed update (for example a mistyped `--url http://host/ui`, a router deleted
  meanwhile, or a state write error) left the old profile signing in with the new
  secret. The profile is now validated before anything is sealed, and when the update
  fails every previous sealed record is put back byte for byte. `kcc router edit
  --url` also checks the new address against the outbound policy first, like
  `router add`.
- **`KCC_PASSWORD` fills one credential per command.** `kcc router add` and
  `kcc router edit` used to seal the same `KCC_PASSWORD` value as the password and the
  read-only password when both had no file; such a command is now refused with exit 2
  (`cli-router-password-env-shared`) and seals nothing. Give the other secrets with
  `--password-file`, `--token-file` or `--read-password-file`.
- **Clearing a firewall rule's description or schedule no longer enables the rule.**
  An empty description or "no schedule" in the Web dialogs sends
  `no access-list <list> rule <index> description` (or `schedule`); it used to send
  `no access-list <list> rule <index> disable`, which turned a disabled rule back on.
  Saving either dialog with the value the rule already has sends nothing and is audited
  `unchanged` instead of `success`.
- **Audit waits are bounded and keep their entries**: an audit entry waiting on another
  process's append lock is no longer dropped after about 25 s; the writer keeps it and
  writes it, in order, once the lock is free. A change the router applied whose entry is
  still queued after the bounded wait (30 s; 20 s after the disarm of a management
  change) is reported as done instead of failed: the CLI exits 0 with the
  `audit-entry-pending` note and `"audit_pending": true` in its `--json` document, MCP
  write results carry `"audit_pending": true` (the key is absent otherwise), and the
  Web shows the note as its success toast. A management change's recovery bracket sends
  its disarm without waiting for any audit entry. A Web sign-in waits at most 5 s for its
  entry. `kcc serve` and `kcc mcp stdio` give the writer 5 s at exit and log the count
  of entries still queued.
- `[[routers]] auth` now selects the sign-in scheme (`ndw2`, `ndw4`, `digest`,
  `token`) instead of being ignored, and `token_file` profiles connect with the token
  instead of being refused at startup. Stored router profiles keep their file format.
- **A busy router refuses a CLI apply before a job starts**: `kcc migrate apply`,
  `kcc preset apply` and `kcc copy` onto a router whose write lease another process
  holds exit 5 with the router-busy message, audit `cli.refused` with outcome `refused`
  and `reason: "router_busy"`, and leave no job record. They used to announce a run,
  stop it with "Migration stopped", exit 1 without an audit entry and leave a run id
  that could be finished.
- `[web] login_max_failures` now sets the lockout threshold (it was ignored and the
  limit was always 5). Router names in `kcc.toml` (`[[routers]] name`, `[logs] routers`)
  follow the registry's rule, 1 to 32 characters from `a-z`, `0-9` and `-`.
- A stale job no longer stops startup: recovery of an interrupted job bounds its router
  probe at 5 s, records the job as interrupted in the audit log and goes on, and the
  unread recovery notices are gone.
- The label that names who holds a router's lease is released as soon as the change set
  is dropped, so a "router busy" message cannot name a holder that has already finished.
- Bridge membership in a migration is decided from the final plan: a member the target
  cannot build gets no `include` line, and the wizard review and the plan agree after
  lines are excluded. Preset options accept numeric switch-port sources
  (`interface 1`). The migration and preset previews offer no Apply when nothing would be
  sent.
- A recovery bracket never leaves a timer armed without saying so: a migration or
  component install that fails after the arm disarms it or reports it, and a refused
  arm whose disarm was accepted says nothing was applied and the timer is off.
- **Migration and preset mappings reach secret lines and access points**: a line that
  carries an encrypted (`ns3`) secret or a WireGuard private key now follows the
  interface, port and radio mappings like its sibling lines (it used to go to the
  source-named interface) and is reported `remap` when a mapping changed it; such a line
  is also checked for a scalar conflict, so replacing a different secret on the target
  blocks until you choose to overwrite it. A radio mapping `WifiMaster<n>` ->
  `WifiMaster<m>` now also moves that radio's access points
  (`WifiMaster<n>/AccessPoint<k>` -> `WifiMaster<m>/AccessPoint<k>`) in migrations and
  presets; an exact access-point mapping still wins.
- **Migrations and presets change kcc's own login password safely**: the management
  phase reconnects with the router account's current password until the line that sets
  its new password has run, then with the new one; a cross-model migration that moves the
  management address first, or sets another user's password first, used to reconnect
  with a password the router did not have yet and was rolled back by the timer. A line
  that sets that account's password (`plain`, `md5` or `nt`) is a management line in
  migrations and presets too and needs the new password (a password typed for that
  account is used): a preset or same-realm hash copy without one is refused with
  `PasswordRequired` before any write instead of failing and being rolled back. A line
  that removes that password is refused. The target inventory records that login
  (`TargetInventory::login`).
- **Changes that can cut kcc off are classified as management changes.** The MTU,
  identity, PPP password, "connect via" and default-route settings of the internet
  connection kcc's own connection runs over now ask for the fail-safe confirmation on
  every surface (the Web's PPP password dialog confirms it with its own Apply) and run
  inside the router's recovery timer; they used to run as plain writes with no timer, so
  a wrong value left kcc cut off until the router was power-cycled. Management detection
  compares the router's addresses with the address kcc's connection is pinned to instead
  of looking the router's host name up again (a blocking lookup that could fail or answer
  differently), and a bridge, or a member of one, whose evidence cannot decide is now a
  management interface for every bridge, not only `Bridge0`.
- **kcc refuses to change the listener it reaches the router through**: moving the HTTP
  port of a router whose kcc URL is `http://`, turning on the HTTP-to-HTTPS redirect for
  it, and turning HTTPS off or moving its port for an `https://` URL (`kcc services port
  http`, `kcc services https off|port|redirect`, MCP `kcc_services_write`) are refused
  before anything is sent: the CLI exits 10 explaining it (`cli-listener-in-use`), MCP
  answers `forbidden`. They used to be sent and always rolled back by the fail-safe timer,
  with every other unsaved change. Change the listener on the router, then the router's
  URL in kcc.

### Security

- **Live views end with their session.** The fleet, dashboard, router log, interface
  traffic, job and apply-progress streams were authorized only when they opened, so a
  stream left open kept sending router data after logout, after the account was
  disabled, deleted or given another role, after its role lost the router, and past the
  session's 12-hour limit. Each stream now checks its session before every event and at
  least every 5 seconds, ends when the session is gone or its role changed, and ends at
  the session's absolute expiry; the browser reconnects to a fresh stream if the session
  is still valid. The checks do not refresh the session's idle deadline.
- **kcc's own router accounts are protected fail-closed.** Changing the password of,
  removing a tag from or deleting the read-only polling login is now refused like the
  profile's login, on the Web UI, the CLI (exit 10, before connecting) and MCP
  (`forbidden`). When kcc cannot tell its own account (an API token profile with no
  login, or a router profile the Web UI cannot read), every password change, tag change
  and deletion of a router account is refused instead of allowed, and adding an account
  with a password is refused there too. Removing a tag from the profile's own login is
  refused as well (only `cli` of `admin` was before).
- **Logins no longer queue on `users.json` and no longer tell accounts apart by timing.**
  Every login attempt, an unknown name included, used to rewrite and sync `users.json`
  while holding its exclusive lock, with the Argon2id check inside the lock, so a stream
  of failed logins delayed every other login and account change. The password is now
  checked with no lock held, and the file is written only when an account's failure count
  or lockout changes (creating an account under a taken name no longer rewrites it either).
  Simultaneous failed logins each count once and lock the account at the same attempt as
  before. At most one Argon2id run per CPU goes on at a time (19 MiB each); the others
  wait. Disabled and locked accounts now run the same Argon2id work as a wrong password,
  so their answer is no faster than for an unknown name.
- **The privilege floor warns about GID 0 and logs what it kept.** A root group is still
  accepted (OpenShift runs with GID 0) but now produces a startup warning, and the
  applied floor (real UID, bounding set cleared or not, remaining bounding mask) is
  logged once after tracing starts instead of being discarded.
- **The session cookie is `Secure` and `__Host-` prefixed behind an HTTPS reverse proxy.**
  With listener TLS off and `[web] public_url` set to an `https` URL, the Web UI used to
  set the plain `kcc_session` cookie without `Secure` and send the plain CSP. Both now
  follow the same decision, made once in the configuration (listener TLS or an `https`
  `public_url`). The kit's own routes (`/mcp`, health, version) carry no `Cache-Control`;
  this is recorded as an open deviation.
- **Login-page sessions are bounded.** Every visit to the login page without a session
  created one more server-side session, without limit. Sessions before login now end
  after 5 minutes without use (or `[web] session_idle`, if shorter), and kcc holds at
  most 64 of them per client address and 10 000 in total; one more evicts the oldest.
  Signed-in sessions are never evicted.
- **Your own password change rotates your session.** `POST /ui/account/password` now
  moves the session to a new id and CSRF token and sets the new cookie, as the forced
  first-login change already did; the old id stops working and the account's other
  sessions still end. The browser reloads the account page (`/ui/account?saved=true`)
  instead of receiving it in the answer. A rotated session keeps its login time, so the
  forced first-login change no longer restarts the `session_absolute` limit.
- **One secret masker for every surface.** MCP results and the Web UI's raw answers
  recognize secret members by one rule (see `docs/PRIVACY.md`): MCP now also masks
  hyphenated and short names such as `private-key`, `obfs-key`, `preshare-key`,
  `community`, `key` and `pin`, and both replace a secret member whole even when it
  holds an object, such as `show interface`'s `{"password": {"ns3": ...}}`, which the Web
  used to show. The markers are unchanged: `<redacted>` on MCP and the CLI, `********`
  on the Web. The command explorer's form treats the same names as secret fields.
- **Raw router answers are redacted for roles without `RevealSecrets`.** The answers of
  MCP `kcc_rci_read`, `kcc_rci_batch` and `kcc_cli_parse`, of the Web command
  explorer, its jobs and the RCI and CLI consoles, and of `kcc show` and
  `kcc rci get|post|batch` used to carry the router's stored secrets, such as the
  `ns3` lines of `show running-config`, to any role with `Read`. Unless the role holds
  `RevealSecrets` on that router, every string of such an answer is now redacted as
  configuration text as well (`<redacted>` on MCP and the CLI, `********` on the Web); a
  string that cannot be read as configuration lines shows only the marker. With
  `RevealSecrets` the strings come as the router sent them, and explorer jobs now show
  their answer that way too. MCP keeps masking secret-named members for every role.
- Read batches of the RCI console, `kcc rci post|batch` and `kcc_rci_batch` send each
  item as validated instead of its printable copy with secret arguments replaced.
- **Configuration text redaction** (backup downloads and diffs on the Web, MCP and the
  CLI, the configuration page, stored lines, preset and migration reviews, anonymized
  fixtures) replaces the pre-shared key of `crypto ike key <name> <psk>` instead of the
  key name, the `preshared-key` and `xauth-password` of `crypto ipsec profile`, and
  every `ns3` payload in every command.
- Generic interface reads (`kcc interfaces list|show` and their `--json` documents)
  keep only which credentials an interface stores (`"authentication": {"password":
  true}`) and drop every `ns3` member that `show interface` returns.
- **Secret files must be owner-only.** On Unix kcc refuses to read a secret file that
  group or others can access (any bit of mode 077), the rule it already applied to the
  master key. It covers router `password_file`, `read_password_file` and `token_file`,
  CLI `--password-file`, `--current-password-file`, `--token-file` and
  `--read-password-file` input, WireGuard `.conf` imports, log sink `password_file`,
  `bearer_token_file` and `api_key_file`, and `[server] tls_key_path`. The refusal reads
  "`<path>` can be read by other users. Run chmod 600 `<path>` and try again."
  (`errors-secret-file-permissions`); a CLI command exits 3. Windows has no mode check.
- Every router credential kcc stores is sealed, including API tokens and read-only
  polling passwords (see the entries above).
- **Bounded login names in the audit log.** A Web sign-in whose username breaks the
  account name rule (1 to 64 bytes of `a-z`, `0-9`, `.`, `_`, `-`) is refused exactly like
  an unknown user and audited with the actor `<invalid-username>` instead of the submitted
  text. Every audit actor id is cut to 64 bytes, so failed logins can no longer grow
  `audit.jsonl` by up to 1 MiB each.
- **CLI key and account changes reach a running server.** `kcc serve` checks
  `api_keys.json` and `users.json` every 2 seconds and on `SIGHUP`: a key revoked with
  `kcc apikey revoke` is refused within about 2 seconds, and the Web sessions of an account
  disabled with `kcc user disable`, reset with `kcc user passwd`, deleted, or given
  another role in `users.json` end. They used to last until restart or session expiry,
  even after `SIGHUP`. A key's last-use record does not reload anything; an unreadable
  file keeps the last good state with a warning.
- **Router and log sink connections ignore proxy environment variables.** `HTTP_PROXY`,
  `HTTPS_PROXY`, `ALL_PROXY` (and their lowercase forms) used to send router requests
  and Loki/Elasticsearch deliveries through the named proxy, past the address the
  outbound policy checked and pinned. Every router and sink connection now goes straight
  to its destination.
- **More cloud endpoints are never admitted.** Besides `169.254.169.254`, the outbound
  policy now always refuses all of `169.254.169.0/24` and `169.254.170.0/24` (container
  and pod credential endpoints, cloud DNS and time servers) and `fd00:ec2::/64`, whatever
  `allowed_networks` says. `kcc router add|test` and the Web router form name such an
  address as a metadata address.
- **`kcc_rci::OutboundPolicy::default()` admits nothing** (no network, suffix or loopback),
  as the documentation always said; it used to admit the private ranges and the Keenetic
  and Netcraze cloud suffixes. kcc builds its policy from `[outbound]`, so the
  configuration behaves as before.
- **Private output files never follow symbolic links.** `kcc migrate plan --out`,
  `kcc migrate report --out` and `kcc migrate apply --report` used to write through the
  fixed temporary file `<out>.kcc-tmp`, following a symbolic link or reusing a file
  someone else created there. They now write a new owner-only temporary file with a
  random name in the output directory and rename it into place, and refuse (exit 1) an
  output path that is a symbolic link. Removing a legacy plaintext `<id>.password` file
  overwrites it only when it is a regular file; a symbolic link there is removed without
  touching the file it names.
- **Preset records are written like the rest of state.** A saved preset is written
  owner-only (0600 in a 0700 `presets` directory), synced and renamed into place; it used
  to follow the umask without a sync. `kcc preset list`, the Web presets page and MCP list
  skip a damaged or unreadable record with a warning naming its file instead of failing.
- **A preset capture never replaces a preset of another router scope.** Capturing under
  the id of a stored preset (MCP `kcc_preset_capture` derives it from the name, `kcc
  preset capture` uses the name) replaces it only for a caller holding `Migrate` on that
  preset's source router; a damaged record only for a role scoped to every router. Any
  other capture is refused and audited: MCP answers `forbidden`, the CLI exits 10. It used
  to overwrite the preset, so a key scoped to one router could destroy a preset of another.
  Reading, deleting, planning and applying a preset outside the caller's scope now answer
  exactly like a missing id (MCP `invalid_arguments` instead of `forbidden`, CLI exit 2
  instead of 10), and a file capture checks the CLI principal's router scope.
- **The master key no longer changes its directory's mode.** When `KCC_MASTER_KEY_FILE`
  names a new key in an existing directory (for example `$HOME`), that directory keeps its
  mode; only directories kcc creates for the key are made 0700. kcc used to change an
  existing parent to 0700, or fail to start when it did not own it.
- **Background jobs belong to the user who started them.** A diagnostic, an explorer
  background command or the component commit can be followed (its live stream) or
  stopped only by the user who started it, or by a role holding `ManageUsers` on the
  router; to anyone else its stream and Stop answer HTTP 404, exactly like a job that
  does not exist. Any reader of the router could watch or stop another user's job
  before. Job ids are now `job-` and 32 hex digits drawn from the operating system's
  random number generator instead of the time, the process id and a counter, so one's
  own job no longer reveals the ids of the others.
- **The CLI grants only roles the CLI principal covers, like the Web UI.** `kcc apikey
  create` and `kcc user add` (and `kcc admin init`) refuse a role whose permissions or
  routers the `[cli] role`, narrowed by `[cli] router_scope`, does not hold: exit 10,
  audited as `forbidden`, nothing stored. The check now lives in
  `kcc_app::api_keys::create_api_key` and `AccountStore::create`, which take the acting
  role and are shared by both surfaces. The CLI used to check only that the role
  existed. An unknown role is still reported as not found (exit 2), now after the
  password is read.
- **A role cannot be deleted while it is being granted.** Deleting a custom role counts
  its holders under the `users.json` and `api_keys.json` locks while it holds the
  `roles.json` lock, and creating an account or API key or changing an account's role
  holds the `roles.json` lock from its role check to its write. A `kcc apikey create` or
  `kcc user add` racing a role deletion in the Web UI could leave a key or account bound
  to a deleted role before.
- **Route-table router scope uses the decoded router id.** The Web UI's route table
  checked a role's router scope against the raw, percent-encoded path segment while the
  pages used the decoded id; both now use the decoded id (`/ui/r/%68ome/...` is `home`),
  and a segment that does not decode to UTF-8 is refused.
- **Wizard secrets do not outlive their run.** A migration kept its sealed source and
  typed passwords forever, and a run of a saved preset left before its last step kept its
  sealed passwords. Finishing a run of either wizard, the end of an apply nobody finishes
  (the router's recovery window) and a day without a change of the run now delete the
  run's sealed source, copied settings and passwords (the run's record and reports stay;
  a copy run's age is now its last change, not its start). Choosing the source or the
  target again deletes the typed passwords, which the presets wizard used to reuse
  silently. The migration's password fields are matched to their user by name: a form
  whose hidden user names do not match the page's users is refused.

### Upgrade notes

- **Sealed router credentials and account hashes of earlier builds are not readable.**
  Router credential records of schema 1 and web account password hashes written by an
  earlier build no longer open, and there is no upgrade path (kcc has no deployments).
  Backups, presets and migration runs are not affected.
- **Run `chmod 600` on every secret file** that `kcc.toml`, a CLI command or a log sink
  names before you upgrade, or kcc refuses it. The shipped Podman secrets are mounted
  0400 and pass; keep `mode=0400` (or 0600) on any further `Secret=` line.
- **New `kcc router add` and `kcc router edit` options**: `--auth`, `--token-file`,
  `--read-login`, `--read-password-file` (and on edit `--new-token`,
  `--new-read-password`, `--clear-read-login`). The password file you pass is input
  only: kcc seals it and you can delete the file. A router stored by an earlier version
  that still names an external password file keeps working and is warned about once.
- **Fix router names**: a `[[routers]] name` or `[logs] routers` entry with uppercase
  letters, dots or more than 32 characters now fails config validation; rename it.
- **Copy the new Quadlet unit** (`StopTimeout=80`) when you deploy with Podman.
- **Machine consumers**: new MCP error codes `router_mode_unknown`,
  `management_not_sent_fail_safe_armed`, `management_saved_fail_safe_armed` and
  `migration_rollback_restarting`; write results carry `"audit_pending": true` when the
  change is applied and its audit entry is still queued; the audit outcome
  `fail_safe_armed` is gone (the entry is `failed` with `fail_safe_armed: true`);
  `router.profile_*` entries list `credentials` instead of `credentials_changed`;
  `kcc migrate apply` needs `--yes` without a terminal.

### Known limitations

See the Limitations section of [README.md](README.md). No firmware line has live
hardware evidence yet.

[Unreleased]: https://github.com/andrico21/keenetic-control-center/commits/master
