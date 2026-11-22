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
- **MCP server** over Streamable HTTP with API keys and over stdio: 70 tools in nine
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

- **API key expiry**: a key may expire, chosen on the Web keys page (7, 30 or 90 days or
  1 year) or with `kcc apikey create --expires-in <duration>`; after it MCP requests
  with the key get HTTP 401. `api_keys.json` records it as `expires_at` (files without it
  still load), `kcc apikey list` shows it (`--json`: `expires_at`, `expired`), and the
  CLI now refuses key names the Web refuses (1 to 64 of `a-z0-9._-`), exit code 4.

- **Entware planners and the Entware drive guard** (library): plans for the `opkg`
  settings (chroot, timezone, init script, DNS override, removal) and for `media
  initialize ext4`, each read back from the router. Ejecting the drive Entware runs from
  (`opkg disk`) is refused on the Web, in the CLI (exit code 10) and over MCP
  (`conflict`) until acknowledged; nothing changes for routers without Entware.
- **Guided Entware setup job** (library): one Destructive write job that installs the
  missing `opkg` and `ext` components by a rebooting component commit, sends `opkg disk
  <drive> <installer>` once with an installer from the closed table, proves the install
  from the router log lines of this attempt and a read-back of `opkg disk`, and ends with
  the configuration unsaved for an explicit save.
- **MCP toolset `entware`** (off by default, not safety-reducing): `kcc_entware_read`
  (`status`, `settings`, `drives`) and `kcc_entware_write` (`setup` as a job with the
  installer chosen only by `arch`, `chroot`, `timezone`, `initrc`, `dns_override` inside
  the recovery bracket, `remove`); `kcc_storage_write` gains `initialize` and the input
  `acknowledge_entware_drive` for `eject` and `initialize` of the Entware drive.

- **Entware SSH enrolment** (library): a probe shows the router's Entware host key with
  a single-use five-minute ticket; a bootstrap with the confirmed fingerprint and the
  Entware root password (used once, never stored) pins the key and installs kcc's own
  key; a changed host key is re-pinned the same way; revoke removes kcc's key from the
  router, disable forgets it locally. Every step needs `Destructive`; the steps that
  contact the router refuse while `opkg chroot` is on, after the router URL host changed
  and over MCP; each is audited as `entware.ssh.*` with public fingerprints only.

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

- **Permissions `manage_notifications` and `manage_schedules`**: two new custom-role
  permissions (checkboxes on the Roles page, route families `/ui/admin/notifications` and
  `/ui/admin/scheduled`); only the built-in `admin` holds them. `roles.json` keeps schema 1,
  so an older binary refuses a custom role that names either permission.

- **Notification settings and the sealed Telegram bot token**: `kcc.toml` gains
  `[notify.telegram]` with `api_url` (default `https://api.telegram.org`; `https`, or
  `http` only to a loopback host, no credentials, query or fragment, never a cloud
  metadata, unspecified, multicast or broadcast address) and `ca_file`. The state
  directory gains `notify.json` (on/off, language, client details, events, up to 10
  chats), `notify_state.json` (written by kcc only) and the bot token, sealed under
  `notify:telegram` in `notify/telegram.token.sealed`.
- **Web UI: Administration > Notifications** (`/ui/admin/notifications`,
  `ManageNotifications`): the notifier's status, the Bot API address from `kcc.toml`
  (read-only), a write-only bot token field with a confirmed removal, the on/off switch,
  message language, client-detail switch and events, the chats, and a test message
  showing "sent" or the failure class. New audit actions `web.notify_settings`,
  `web.notify_token` (`credential_changed` or `credential_cleared`),
  `web.notify_chat_add`, `web.notify_chat_remove` (label only) and `web.notify_test`
  (`success` or `failed`). The administration tab bar gains a Notifications tab for roles
  holding the permission.
- **CLI: `kcc notify`** (`ManageNotifications` for the `[cli] role`): `show` (`--json`
  without the token), `enable`, `disable`, `events <list|default>`,
  `locale <tag|default>`, `client-details on|off`, `token [--file <path>]` (else
  `--password-file`, `KCC_PASSWORD` or a hidden prompt; never an argument value),
  `token --clear`, `chat add <id> --label <text> [--thread <n>] [--silent]`,
  `chat remove <id>` and `test [--chat <id>]`, which sends one message from the command
  and exits 6 naming the failure class. New audit actions `cli.notify_settings`,
  `cli.notify_token`, `cli.notify_chat_add`, `cli.notify_chat_remove` and
  `cli.notify_test`, with the Web page's parameters.
- **Scheduled-action store and run ledger**: `schedules.json` holds weekly scheduled
  actions (client policy switch, preset apply, backup, reboot) with their owner, at most
  64 per router and 256 in total; `schedule_runs.json` records each run before it starts,
  so a slot runs at most once, and keeps the last 20 runs per schedule. New `kcc.toml`
  table `[schedules]` with `default_timezone` (default `"UTC"`).
- **Telegram delivery (library only)**: `kcc-telemetry` gains a Bot API client that sends
  plain-text `sendMessage` requests only (no proxy, no redirects, metadata and other
  never-admitted addresses refused by its resolver, the token never logged) and a
  delivery outbox with storm control: 30 s merge window, 1 message/s and 20/min per chat,
  256 waiting lines per chat, `retry_after` on 429, backoff from 5 s to 5 min, lines older
  than 1 h dropped, a refused token or chat recorded in `notify_state.json`. New
  self-metrics `kcc_notify_messages_total{result}` and `kcc_notify_dropped_total{reason}`.
- **Telegram notifications in `kcc serve`**: the server sends, per selected event, a
  router offline (two failed polls in a row; one message with the time of the first
  failure) and back online (with the outage length), a refused router login (once per
  streak), a failed change (router, action, actor, and whether the fail-safe timer is
  still armed; scheduled runs report their own), an account lockout (once per lockout
  window), an audit log repair or a stopped audit writer, new router firmware (once per
  router and version, recorded in `notify_state.json`), a failed job, and new unregistered
  devices (off by default; at most one message per router per 5 minutes, named by
  pseudonym unless client details are on, never by IP address). Messages are rendered in
  the chosen language (else `[web] default_locale`), times in `[schedules]
  default_timezone`, and every line starts with `[kcc]`. A restart or fail-safe rollback
  kcc sends mutes that router's offline and online messages for 15 minutes. Settings and
  token changes made on the Web page or with the CLI apply to a running server within
  its state watch. While a router event is selected, every router is polled around the
  clock. Only `kcc serve` sends; entries other processes append to the audit log are not
  notified. The test message of the Web page now goes through the running notifier.
- **Scheduled actions run in `kcc serve`**: the server keeps the active schedules of
  `schedules.json` (an edit made elsewhere applies within its state watch) and runs each
  weekly slot at most once: a slot up to 2 minutes late still runs; later ones are
  skipped as `late` in one ledger step with one message naming how many were missed;
  a wall clock stepped back never repeats a slot. Runs of one router go one after the
  other. Each run acts as audit actor `system`/`schedule:<id>` with its owner's
  authority at run time: a missing, disabled or out-of-scope owner pauses the schedule
  `owner_unavailable`, a role that lost a permission of the action pauses it
  `forbidden`, a removed router pauses its schedules `router_removed` (at start and on
  every profile change). A busy router is tried again every minute until 10 minutes
  after the slot, then the run is skipped `router_busy`. A policy switch changes one
  registered client's host line and is never saved (a router restart undoes it); a
  backup stores the startup configuration as `scheduled-<id>`; a reboot mutes the
  router's offline and online messages for 15 minutes and succeeds only when the router
  answers again within 15 minutes with a fresh uptime (`did_not_come_back` otherwise).
  Policy, backup and reboot run as jobs `scheduled.policy_switch`, `scheduled.backup`
  and `scheduled.reboot`. A run
  left started by a previous server is marked `interrupted`, reported once and never
  run again. New audit actions `schedule.run` (target the action, params `owner`,
  `slot`, `requested_by`, `job`; outcome `success`, `failed` or `skipped`) and
  `schedule.pause` (params `owner`, `reason`). New notification lines for the scheduled
  events. On a stop the scheduler admits no further run before the jobs are drained;
  the server waits at most 10 s for a run in progress.
- **Scheduled preset applies**: a preset schedule applies its stored preset in Merge
  mode, planned again at every run against a fresh inventory with the owner's role
  narrowed to the router and the preset's source router (an owner without `Read` and
  `Migrate` on the source router pauses the schedule `forbidden`). A plan that needs
  input, has a management-phase line or sets a WireGuard private key, an unacknowledged
  documentation-based firmware line, older firmware or a missing preset skip the run
  (`not_ready`, `management_lines`, `wireguard_key`, `documentation_tier`, `firmware`,
  `preset_unavailable`). The run takes the router's lease before the applier's migration
  job starts, keeps a verified apply unsaved (the fail-safe timer is stopped; the run
  records `unsaved` and the `show last-change` checksum) and rolls a failed one back
  (`preset_rolled_back`). When the rollback or the keep-unsaved step fails, it keeps the
  lease until the fail-safe timer ran out, then reports `preset_restored` or
  `preset_state_unknown` from `show last-change`; a failed preparation is not rolled back
  (`preset_failed`, or `preset_failed_armed` when the timer may be armed, in which case it
  also keeps the lease until the timer's interval plus one second has passed; interactive
  applies are unchanged). Nothing is ever saved. New notification line for an applied preset and reasons for these codes.
  `docs/MIGRATION.md` "Scheduled presets".
- **CLI: `kcc scheduled`** (`ManageSchedules` for the `[cli] role`, plus the action's
  permissions on the router): `list`, `show <id>` (with the last runs), `add --router
  <id> --name <text> --days mon,... --at HH:MM [--tz <zone>]` with one of
  `--policy-switch --mac <mac> --policy <name>`, `--preset <id>
  [--ack-documentation-tier]`, `--backup` or `--reboot` (zone default
  `[schedules] default_timezone`), `edit <id>`, `pause <id>`, `resume <id>`,
  `delete <id>` and `run-now <id>`, all with `--json`. Add, edit, resume and run-now
  check the router first (refusal codes `forbidden`, `router`, `client_unknown`,
  `policy_unknown` and the preset codes, the same check the Web page uses); a policy
  switch or preset needs `--yes`, a reboot `--confirm-destructive <router-id>`. The CLI
  user becomes the owner (`cli:<user>`). `run-now` runs in the CLI process through the
  server's run path as the schedule's owner, records the run without a slot, audits
  `schedule.run` with `requested_by` `cli:<user>`, sends no Telegram message and ends a
  busy router at once (`router_busy`, exit 5). New audit actions `cli.schedule_add`,
  `cli.schedule_edit`, `cli.schedule_pause`, `cli.schedule_resume`,
  `cli.schedule_delete` (params `id`, `action`, `router`).
- **Fake router**: `show system` reports as `uptime` the seconds since the last
  simulated reboot once one happened.
- **Web UI: Administration > Scheduled actions** (`/ui/admin/scheduled`,
  `ManageSchedules`): the schedules the role sees with their state, next slot and last
  run; add and edit dialogs (router, days, hour, minute, IANA zone suggested from the
  bundled database and prefilled with `[schedules] default_timezone`, and the action: a
  registered client and a policy read from the router, a preset the role may apply with
  the documentation-tier acknowledgement, a backup, or a restart with the router's name
  typed); pause, resume, a confirmed delete and a confirmed run-now. Creating, editing and
  resuming ask the running scheduler first and make the clicker the owner. `kcc serve`
  attaches its scheduler when the Web UI is enabled: a run-now checks the clicker's
  permissions besides the owner's, runs in the background through the scheduler's run
  path (recorded with `requested_by` = `web:<user>`, audited as `schedule.run`, reported
  to Telegram), is never retried (a busy router ends it `Skipped router_busy`) and is
  waited for at shutdown within the scheduler's 10 s. New audit actions `web.schedule_create`,
  `web.schedule_update`, `web.schedule_pause`, `web.schedule_resume`,
  `web.schedule_delete` and `web.schedule_run_now` (params `schedule`, `action` kind and
  `router`; a refusal's outcome is its code). The administration tab bar gains a
  Scheduled actions tab for roles holding the permission, the router dashboard names the
  next scheduled action, and the configuration page names a scheduled change the router
  has not saved. `kcc_web::admin_scheduled::ScheduleControl` and
  `WebState::with_schedules` attach the scheduler.
- **Weekly slot times and the time zone database** (library): `kcc-app` computes the
  slots of a weekly schedule (days, hour and minute in an IANA zone) on the `jiff` crate's
  bundled time zone database; the system time zone and zoneinfo files are never read, so a
  slot falls at the same instant on every host. `jiff` is a new dependency (listed in
  `THIRD_PARTY_NOTICES.md`).
- **Audit entry broadcast and a distinct polling login failure** (library):
  `AuditLog::subscribe` hands out every entry the writer appends once it is durable, in
  chain order (the notifier reads it); the audit file format and hashes are unchanged. A
  refused polling login is reported as `PollError::Auth` instead of a reason text.
- **State files followed by the running server**: besides `api_keys.json` and
  `users.json`, the 2-second state watch now reloads the notifier (`notify.json`, the
  sealed bot token) and the scheduler (`schedules.json`).
- **Fake Telegram Bot API** (`kcc-testkit`): `FakeTelegram` serves `sendMessage` with
  scripted faults (429 with `retry_after`, 401, 403, chat not found, 500) and records
  requests without logging a token; `kcc-fake-sinks` serves one next to the fake Loki and
  Elasticsearch and prints a `telegram <url>` line.
- **Live Telegram suite**: `crates/kcc/tests/live_telegram.rs` (`#[ignore]`d) sends one
  message through the real Bot API with the owner's bot and chat. It needs
  `KCC_LIVE_TELEGRAM_TOKEN_FILE` and `KCC_LIVE_TELEGRAM_CHAT` and contacts no router, so
  it is exempt from `KCC_LIVE_TARGET_CONFIG` and `KCC_LIVE_ALLOW_SERIAL` (`AGENTS.md`,
  "Live env contract").
- **SSH address admission and a fake Entware SSH server** (library and test kit):
  `OutboundPolicy::admit_ssh(router, port)` resolves a router's host and keeps only
  addresses inside `allowed_networks` (loopback only when admitted; a host admitted only
  through `allowed_suffixes` gets none; metadata addresses never). `kcc-testkit` gains
  `entware_ssh::FakeEntwareSsh` (russh 0.65.2, `ring` backend, a new dependency): an
  ed25519 host key that can be replaced, password and `authorized_keys` sign-in, an
  `opkg` package database, init scripts that follow Entware's `rc.func`, counters and
  fault switches; `kcc-fake-router --entware-ssh-port <port>` serves one.
- **Entware status model** (library, read-only domain `entware`): `read_status` reports
  whether Entware can be installed (the `usb` and `storage` components, the `show version`
  architecture), the `opkg` and `ext` components, the `opkg` settings from `show rc`, the
  ext2/3/4 drives with their `opkg disk` argument (`<label>:/`, else `<uuid>:/`), the
  media that can be initialized as ext4, and whether the DNS filter engine is `opkg`. The
  fake router (`kcc-testkit`) gains the `opkg` settings and `dns-proxy filter engine`,
  available `opkg`/`ext` components and a media uuid and `initialize-supported` list.
- **Permission `manage_mcp`** (`ManageMcp`, thirteenth permission): guards the MCP
  settings and connections pages (`/ui/admin/mcp*`); only the built-in `admin` holds it.
  The role name `kcc-account` is reserved (a custom role with it is refused) and is always
  in the MCP RBAC configuration with every tool and router scope `*`. `roles.json` keeps
  schema 1, so an older binary refuses a custom role that names the new permission.
- **MCP settings state file and new `[mcp]` keys**: `[mcp]` gains `locked`, `endpoint`,
  `[mcp.dedicated]` and `[mcp.auth.main|dedicated|kcc|oidc|mtls]` (see `docs/CONFIG.md`);
  existing keys keep their meaning and defaults. Web-managed values live in
  `mcp_settings.json` (schema 1) and are resolved per key as environment, locked kcc.toml
  key, state file, kcc.toml, default; `kcc serve` and `kcc mcp stdio` read MCP settings
  only through that resolver. A role the MCP settings name cannot be deleted. Each MCP
  toolset carries a `safety_reducing` flag (`raw`). Library: `remove_unheld` and
  `holder_counts` take the set of roles the MCP settings hold.
- **New library crate `kcc-ssh`** (no user-visible change yet): SSH to a router's Entware
  only to policy-admitted addresses, with a mandatory pinned ed25519 host key, one
  session per router (four in total), a 256 KiB output cap and connect, auth, read and
  mutation timeouts. Commands come only from a closed typed set (`opkg` list, update,
  install, remove, upgrade; init script list and `start|stop|restart|check`; adding and
  removing kcc's own `authorized_keys` line) whose arguments pass token grammars.
  The fake Entware SSH server now runs the two `authorized_keys` scripts.
- **Live MCP settings and reload fan-out**: toolset, `read_only`, `allow_destructive`
  and `max_result_bytes` changes applied to a running `kcc serve` bind open MCP sessions
  at their next call when they tighten (a tool turned off leaves the next `tools/list`
  and is refused as unknown) and new sessions when they loosen; migration plans survive.
  API key and role reloads (Web pages, state watcher, `SIGHUP`) reach every running MCP
  server; the state watcher and `SIGHUP` start once per `kcc serve`, outside the MCP
  server's start-up. Library: `TransportReload` registers named handles (`register`, `unregister`,
  `set_tools`, no `slot`), succeeds with none registered, and `install_roles` returns
  nothing; `KccMcp::reconfigured` and `KccMcp::publish_gates`; `kcc::server_live::McpApply`.
- **Sealed SSH state per router** (library and state, no user-visible change yet):
  `kcc_app::entware_ssh` keeps a router's enrolment record, kcc's private key and a
  single-use, five-minute probe ticket bound to router, port and actor as sealed files
  `<state>/router-ssh/<id>.sealed`, `<id>.key.sealed` and `<id>.ticket.sealed`; removing a
  router in the Web UI or with `kcc router remove` also wipes them.
- **Dedicated MCP listener**: `[mcp.dedicated] enabled = true` runs a second, MCP-only
  listener (default `127.0.0.1:8444`; no Web UI, no metrics) with the `[server]`
  certificate, a self-signed one generated once into `<state>/mcp/dedicated-cert.pem` and
  `dedicated-key.pem` (owner-only), or none on loopback; `endpoint = "dedicated"` leaves
  the main listener's `/mcp` without tools. A dedicated listener that cannot start is
  skipped at start and logged. Until OAuth and client-certificate sign-in are available,
  a listener whose `oauth` is not `none` or whose `mtls` is not `off` does not start: the
  main listener then starts with kcc.toml's sign-in settings, the dedicated one is skipped.
- **Live restart of the MCP listeners**: `kcc serve` runs its listeners under a
  supervisor (`kcc::server_listeners::ListenerSupervisor`): a settings change that
  restarts a listener builds and validates the new one first, then stops, serves,
  registers and health-checks it (within 10 s), and reverts to the previous listeners on
  any failure; settings are applied and `mcp_settings.json` written only after that. If a
  previous listener cannot bind again within 10 s, `kcc serve` stops with an error. The
  main listener's `rmcp_server_kit_*` metrics restart from zero at each restart (the
  `kcc_*` series continue); SIGTERM stops both listeners before the existing shutdown
  sequence.

### Changed

- **Entware drive and init-script commands are destructive.** Raw and explorer `opkg disk`,
  `opkg initrc` and `media initialize` now need the Destructive confirmation; `opkg
  dns-override` runs under the fail-safe timer.
- **Container stop timeout 100 s**: `deploy/podman/kcc.container` sets `StopTimeout=100`
  (was 80): 10 s are reserved for stopping the scheduler and 2 s for queued Telegram
  notifications, and the margin grows to 13 s.
- **The container end-to-end run covers notifications and scheduled actions.**
  `deploy/podman/e2e.sh` stores a fake bot token and a chat with `kcc notify`, sends a
  test message to a fake Telegram Bot API, and creates a backup schedule on the Web admin
  page whose "run now" must leave a backup and a Telegram message. The seccomp profile,
  re-traced over these paths, is unchanged: no syscall added or removed.

- **Interface changes fail closed when kcc cannot tell which interface carries its
  connection.** When no router interface owns the address kcc reaches the router at (a
  relay, address translation or the cloud path), a change to any interface (taking it down,
  its security level or address, the MTU, identity, PPP password, "connect via" or default
  route of an internet connection, a firewall binding or Wi-Fi schedule on it, a segment or
  VPN connection naming it) is now a management change, except on a bridge whose
  neighbours in the router's ARP or hotspot records are all on other interfaces: it asks for the fail-safe
  confirmation on every surface (the Web dialog, MCP `confirm_required`, the CLI's `--yes`)
  and runs inside the router's recovery timer. It used to run as a plain write except on
  a bridge or a bridge member. When kcc does know the interface, creating a connection
  stays a plain write. `ManagementVerdict::risk` no longer takes the interface name, and
  `wan::plan_dhcp` and `wan::plan_static_address` no longer take the unused one.
- **Test kit: `FakeRouterBuilder::reached_directly`.** It lists `Loopback0` owning
  `127.0.0.1`, the address the fake router is reached on, so kcc can tell which interface
  carries its connection, as on a router reached directly. Without it (the default, and
  the `kcc-fake-router` binary) no interface owns that address.
- **A password typed for a router user wins over a same-realm hash.** When a migration or
  preset source carries `user <name> password md5|nt` made on a router with the target's
  realm and you typed a password for that user (CLI `--user-password <user>=<file>`), kcc
  now sends `user <name> password plain` with it instead of copying the hash. Before, the
  hash was copied and the typed password ignored; a run that changed kcc's own login then
  reconnected with a password the router did not have and ended only when the fail-safe
  timer restored the router. Without a typed password a same-realm hash is still copied,
  and for kcc's own login the run is still refused with "router password required" before
  anything is sent.
- **A stopped migration says how many lines it applied.** `kcc migrate apply` and
  `kcc preset apply` report a run that failed after its first migrated line with the
  failure's exit code (6 for a router failure or a router-side rollback) and how many lines
  were applied before it stopped, or, when the rollback left the router still restarting,
  that it is restarting with its saved configuration. Rolling back a run that is already back on its saved
  configuration (the router restored itself) sends nothing and succeeds on every surface;
  before, it was refused as invalid input, so the CLI printed "The request was rejected
  before anything was sent." with exit 4 after lines had been applied.
- **Test kit: the fake router's request log keeps every parser line.**
  `kcc_testkit::RequestRecord::commands()` (new) lists every root `parse` line of a request
  in body order, a batch included, with secret-bearing lines (now also `crypto ike key`) as
  `None`; lines are attached to their own request even when requests overlap.
  `RequestRecord::command()` stays the last line of the request. The new
  `kcc_testkit::leak::contains_secret` finds a test secret in its JSON, `Debug` and
  CLI-quoted forms as well, and the secret-leak tests use it.
- **Test kit: shared safety-bracket helpers.** The new `kcc_testkit::bracket` module holds
  the arm and disarm lines of each recovery mechanism (`Recovery`) and the shared table of
  bracket failure fates with the fault that causes each (`Fate`); the Web, MCP and
  domain tests use it instead of their own copies.
- **Container image tags and labels.** A prerelease tag (one with a `-`, such as
  `v0.2.0-rc.1`) is published only under its own tag and no longer moves `:latest`, so a
  Quadlet unit or `run.sh` on `:latest` stays on the last stable release. The image's
  `org.opencontainers.image.version` label carries the tag's version instead of always
  `0.1.0`. Images and release archives are published only after every CI gate passes.
- **The seccomp profile filters only `x86_64` and `aarch64`.** The 32-bit `x86`, `x32`
  and `arm` ABIs, which the image never uses, are no longer allowed. The profile is
  regenerated from the union of two traces (`deploy/podman/README.md`).
- **`cargo xtask seccomp gen --check-missing`** fails only when a freshly traced syscall
  is missing from the committed profile; CI's container drift check now runs it and
  blocks instead of only reporting.
- **Seccomp traces on both architectures.** The container workflow traces the shipped
  binary twice on its amd64 and its arm64 runner, runs the drift check on both, and
  uploads the traces as the `seccomp-trace-amd64` and `seccomp-trace-arm64` artifacts
  the profile is regenerated from (`deploy/podman/README.md`).
- **The seccomp profile allows `fchmodat`.** arm64 has no `chmod` and uses `fchmodat`
  instead, so the arm64 image could not create its state directory under the profile
  (`state I/O on /var/lib/kcc: Operation not permitted`). The profile is regenerated from
  native amd64 and arm64 traces.
- **The seccomp profile allows `sched_yield`.** It is a runtime spin-yield that shows up
  intermittently in the amd64 traces; the profile is regenerated from the union of the
  amd64 and arm64 traces.
- **Every live suite needs a test-device profile.** Each `live_*` suite, read-only ones
  included, requires `KCC_LIVE_TARGET_CONFIG`: a `kcc.toml` whose profile for the router
  has `test_device = true` and whose `[outbound] allowed_networks` admits it. The profile
  is checked before the router is contacted, and `KCC_LIVE_ALLOW_SERIAL` now covers every
  router a suite contacts, the migration source included. A missing variable still logs
  `live-skip:<reason>` and returns (`AGENTS.md`, "Live env contract").
- **`cargo xtask cancel-safety` covers every async function.** It checked only fully
  `pub` ones; it now fails for any async function without a `// cancel-safe:` or
  `// NOT cancel-safe:` comment, whatever its visibility. A function that can reach a
  router sign-in is NOT cancel-safe, because a cancelled sign-in can leave an orphaned
  router session, so router reads are marked that way.
- **`cargo xtask assets-check` rejects every way around HTML escaping.** The `safe`
  filter, `{% filter safe %}`, the `none` escaper and the safe-HTML marker outside
  `markup.rs` and `lib.rs` fail the gate. Pre-rendered HTML travels as a child template
  marked with `fragment!` or as `markup::Rendered`, never as a `String`.
- **`cargo xtask profile-eq` compares lint levels with the vendored profile.** The root
  `[workspace.lints]` must equal the `[workspace.lints.rust]` block of
  `docs/rust-guidelines/RUST_GUIDELINES.md`, levels and priorities included, so a lint
  lowered from `deny` to `warn` fails the gate; a missing block is an error.
- **Dependency vetting uses imported audits.** `cargo vet` imports the audits of
  bytecode-alliance, embark-studios, google, mozilla, ISRG and Zcash, `xtask/` has its own
  `supply-chain/` checked by the CI xtask job, and a bump adds an exemption only for a
  crate no imported set covers (`CONTRIBUTING.md`, "Dependency bumps"). `kcc-rci` uses
  `getrandom` 0.4.
- **The end-to-end scripts fail on any error.** Each step of `deploy/podman/e2e.sh` and
  `live-e2e.sh` runs with `set -e`, so a failure in the middle of a step fails it, and
  the clean-up stops the processes it started instead of hanging.
  `scripts/live/web-smoke.sh` passes the password through a 0600 `--env-file`, not a
  command-line argument.
- **`kcc.toml` router profiles follow the same rules as the others.** A `[[routers]]`
  `url` must be an origin (no path, query or fragment) and is refused by `kcc.toml`
  validation with the field named, where it was accepted and then failed when the
  registry was built; a router added with the Web UI or `kcc router add` now has a
  malformed TLS pin refused when it is stored instead of when kcc connects.
- **`kcc backup diff` compares what changed, in order.** It compared sets of redacted
  lines, so a changed secret, a reordered command or a repeated command showed no
  difference. It now compares the complete text of every command in order (as the Web UI
  does) and prints the removed and added commands redacted, `kcc` refuses a difference
  too large to compare in order with exit 4, and its help no longer says "Count".
- **Rollback finishes and `preset delete` are confirmed like the other destructive
  actions.** `--finish rollback` of `kcc migrate apply`, `kcc preset apply` and `kcc copy`
  needs `--confirm-destructive <router>` in addition to `--yes`, and `kcc preset delete
  <id>` needs `--confirm-destructive <id>`; a refusal exits 10 before anything is sent.
- **Rollback results say `"unsaved": false`.** `kcc config failsafe rollback` and `kcc
  migrate finish rollback` reported `"unsaved": true` after the router restored its saved
  configuration.
- **`--json` covers argument errors.** An unknown flag or a missing argument prints the
  `{"error": {"kind": "usage", ...}}` object on stderr and exits 2; help and version are
  unchanged.
- **A missing confirmation names the router** instead of `-`.
- **Secret writes prove the new value.** Setting the password of a router account (also
  the VPN server account password), a PPP connection or a Wi-Fi access point now reads the
  stored, encoded value from the running configuration before the write and fails with
  `VerificationFailed` (MCP `verification_failed`, CLI exit as for any read-back failure)
  naming the setting, never the secret, when it has not changed afterwards. A router that
  acknowledges but ignores the write no longer passes. Setting the value an account,
  connection or access point already has is now reported the same way (the stored value
  did not change). If the running configuration cannot be read before the write, nothing
  is sent. New public API: `PresencePredicate::ConfigSecretReplaced` and
  `VerificationSpec::replaced`; the Web success message for these writes says that the
  stored value changed (`web-secret-changed`).
- **Firewall rules with ports need TCP or UDP.** A firewall rule with a source or
  destination port on `icmp`, `esp`, `gre`, `ipip` or `ip` is refused while planning as a
  validation error on the field `source-port` or `destination-port` (CLI exit 4, MCP
  `validation_failed`), before anything is sent; it was refused before as an internal line
  error.
- **Firewall reorder goes through the domain planner.** The Web "Move up"/"Move down"
  actions plan the move with `firewall::change::plan_order_rule`
  (`access-list <list> rule <index> order <position>`, validated as `index` and
  `new-index`) instead of building their own line. The public reader
  `firewall::read::configured_rules` is replaced by `configured_list(router, list)`, which
  returns `ListedRule` entries.
- **DHCP pools: one DNS server, a clearable DNS field, no silent overwrite.** A pool
  with more than one DNS server is refused before anything is sent: `kcc dhcp pool`
  with a second `--dns` exits 4 (validation, field `dns`), MCP answers
  `validation_failed`, and the Web pool editor shows the new field error
  `web-dhcp-error-dns-one` (it now shows every DNS server the router reports, instead of
  keeping only the first). An empty DNS field in the Web editor sends
  `no ip dhcp pool <name> dns-server` and is read back as absent. "Add pool" refuses a
  name the router already has (field error `web-dhcp-error-name-taken` under `name`).
- **`kcc dhcp pool` needs `--gateway`, and a replace needs the options it would reset.**
  `--gateway` is required (it no longer defaults to `--begin`, a client address).
  `--lease-seconds` and `--state` have no clap defaults any more: a new pool still gets
  86400 and `on`, but replacing a pool the router already has without them exits 2 with
  `cli-dhcp-pool-replace-needs` and sends nothing. An omitted `--interface` or `--dns`
  keeps the pool's own, as before.
- **Client and DHCP read-back runs before the audit entry.** The `show ip hotspot` checks
  of client host changes and the `show rc ip dhcp host` check of a static lease are now
  verifications of the workflow change itself, so they run before the
  `router.change_cli` entry is written. A failed check leaves no entry claiming the
  change applied; only the front end's failure entry records it. Host verifications
  compare the MAC address in lower case, as the router reports it. A failed check now
  names the resource it read (`show/ip/hotspot`, `show/rc/ip/dhcp/host`) as the
  `verification_failed` field instead of `client/<mac>` or `static-lease/<mac>`.

- **Metric changes.** `kcc_metrics_series_dropped_total` (a counter that grew on every
  scrape) is replaced by the gauge `kcc_metrics_series_dropped`: the number of per-client
  series left out at the latest scrape, per router. The free-text interface `description`
  is no longer a label of `keenetic_interface_up` (labels `router`, `interface`, `type`);
  it moved to the new info family `keenetic_interface_info{router,interface,description}`,
  always 1. The `kcc_jobs` gauge is exact again after the job event stream lags: every
  counted job is settled from its record. The Grafana dashboard follows (the dropped-series
  panel, a new `keenetic_interface_info` query in the interface table).

- **The catalog itself classifies every raw DELETE as destructive.** `kcc_catalog`'s
  validation used to return the risk of the removed command (often `Write`) and each front
  end raised a DELETE to destructive on its own; `ValidatedRequest::risk` is now
  `Destructive` for every DELETE, and the MCP `kcc_rci_delete`, `kcc rci delete` and the
  Web RCI console take it from there. Their gates are unchanged. A generated argument type
  the runtime does not know now fails the catalog load (`InvalidGeneratedCatalog`) instead
  of becoming unconstrained text.

- **A raw batch that fails part-way is audited for what was applied.** A batch larger than
  one request (about 900 KiB) is sent in chunks. When a later chunk fails, the earlier
  chunks were already applied: the change is now audited as `router.change_batch` with a
  partial outcome and the params `{"error":"request_failed","succeeded":N,"failed":N,"unanswered":N}`
  (counts only), and the request error is returned. Before, nothing was audited. A router
  reply with fewer or more answers than items is now an error (the response could not be
  decoded) instead of a success counted over the answers present.
- **Router status items are judged by their level alone.** An item whose `status` level is
  unknown is treated as an error, and an `error` item whose code, subsystem or message is a
  number or missing is still an error. Before, such items were ignored and the reply
  counted as a success.
- **Self-metrics count every router request and login.** Batches, configuration downloads
  and uploads, identity detection, background operations (ping, traceroute, live logs) and
  factory-setup clients now count in `kcc_router_requests_total`,
  `kcc_router_request_duration_seconds` and `kcc_router_auth_total`; the factory-setup
  sign-in check also waits for the router's request budget like every other request.

- **New setting `[outbound] argon2_max_iterations` (default 16, 1 to 64).** At ndw4 sign-in
  a router asking for more Argon2 iterations than this is refused ("router authentication
  cost exceeds local policy") before any key is derived. Before, any count up to the
  protocol maximum of 64 was accepted. Raise the setting for a router that needs more.
- **A read timeout is the same error on every sign-in path.** Under token, HTTP digest and
  ndw4 sign-in a router that stops answering is now reported as a timeout, as it already was
  for ndw2, instead of a transport failure.
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
- **Forwarded router log times are labelled naive local time.** A router writes its log
  times in its own time zone without an offset, and kcc does not know that offset.
  Elasticsearch, OpenSearch and stdout documents now carry `@timestamp` without an offset
  (`2026-11-06T12:00:01`, it used to claim `+00:00`); Loki entries carry the same wall-clock
  digits as Unix nanoseconds, as before. In `kcc-telemetry`, `LogRecord::ts` is a
  `NaiveDateTime`, and `parse_records` takes kcc's UTC clock (only to infer the year) and
  returns `ParsedLog`.
- **The Loki `level` label has a fixed set of values**: `error`, `warning`, `info`, `debug`
  and `other`. A severity word the router sends outside that set becomes `other` instead of
  a new stream label.

- **Two VPN refusals name their field.** An IPsec virtual-IP pool with neither or both of
  `end` and `size` is refused as an invalid `end` before the catalog is asked (it was an
  unknown field `invalid`), and a WireGuard import with an IPv6 `AllowedIPs` range is
  refused as an invalid `address` (it was an invalid `mask`); both stay validation
  refusals (CLI exit 4, MCP `validation_failed`).

- **Migration verification no longer needs Internet access or `Bridge0`.** The Internet
  check is recorded in the apply report (`ApplyReport.internet`) and never fails
  verification, so a target pre-staged on the bench without an uplink can be verified and
  committed. The management interface is the interface whose address kcc connects to (from
  `show interface`), not the first bridge: verification checks that interface's link and
  reports it (`ApplyReport.management_interface`), and `TargetInventory.management_interface`
  is that interface, or `None` when no interface holds the address. Planning then treats
  an address or security-level change of any bridge as a management change
  (`TargetInventory::may_carry_management`), and verification checks no link.
- **Migration reports show the redacted command text.** Every item of the JSON, Markdown
  and HTML report (Web download, `kcc migrate report`, MCP plan and preset reports) carries
  its source and resulting line with secrets replaced by `<redacted>`, instead of
  `<redacted> -> <redacted>`; preset reports list their items (they were empty). The
  report headings and the HTML `lang` come from the user's language;
  `MigrationReport::to_markdown` and `to_html` take a `Locale`. Markdown code spans can no
  longer be broken out of by backticks in a command. The report JSON shape and
  `schema_version` 1 are unchanged.

- **Typed classification reasons and inputs in `kcc_migrate`.** A classified line carries
  `ClassifiedItem::reason`, a `rules::reason::Reason`, instead of the string
  `reason_key`, and `ClassifiedItem::input`, a `rules::reason::NeededInput` (a component to
  install, a user's new password, the reconnect URL); `needed_input` stays as its words.
  A preset item's `reason` is a `presets::plan::reason::PresetReason`, and `PresetInput`
  can be matched exhaustively. The names in plans, reports, the plan JSON, the report JSON
  and the MCP `reason` fields are unchanged; a rule file naming an unknown reason fails
  to load. The engine's three maps collect from `MapEntry`s (`FromIterator`).
- **`UpdateCheck` keeps the firmware-update results.** The Web UI's second cache on top
  of the check is gone: `UpdateCheck::cached` returns the latest result and whether a
  check is due, and the dashboard starts a check only then. A check that reached the
  router but got no answer is not repeated until the six hours pass.
- **Dependencies at the latest version past the three-day cooldown**: `sha3` 0.11 -> 0.12
  (the only semver-incompatible update; ndw4 sign-in now computes HMAC-SHA3-512 with
  `hmac::SimpleHmac`, same output), `rmcp` 3.9.0 -> 3.10.0 and the compatible updates
  `cargo update` selects, in both workspaces; the CI gate tools cargo-deny 0.20.2 and
  cargo-audit 0.23.0. No behaviour change.
- **Compatible updates past the cooldown**: `clap` 4.6.8, `clap_complete` 4.6.12,
  `clap_derive` 4.6.8, `clap_lex` 1.1.2 and `uuid` 1.29.3 in the root workspace; `clap`,
  `clap_derive` and `clap_lex` in xtask. No behaviour change. `jiff` 1.0.1 is held back
  until its cooldown ends.

### Removed

- **Copy numbers on backups made in the same second.** The configuration page probed the
  store and renamed a second backup of the same reason in the same second to
  `manual--2` (up to `--9`, then refused it with "a backup for the same reason was stored
  a moment ago"). The store already gives such a backup its own name
  (`<second>-1-<reason>.txt`), so every backup now keeps its reason and none is refused
  for its second; an uploaded file's name keeps up to 41 characters (was 38). A
  `--N` reason stored by an earlier build is shown as it is stored.

- **Duplicate CLI spellings.** `kcc diagnostics log [--lines N]` (use `kcc log read
  [--lines N]`, which reads the same log) and the `ppp` kind of `kcc vpn secret` (use
  `kcc wan password <name>`, which sets the same PPP password and also detects when the
  connection carries kcc's own traffic). `kcc diagnostics` is now described as "Router
  diagnostics" in `--help`.
- **Storage partition check and format.** The `partition_check` and `partition_format`
  operations of the MCP tool `kcc_storage_write` (now `eject` only; an old operation is
  answered `invalid_arguments`), the CLI subcommands `kcc storage check` and
  `kcc storage format`, the hidden Web routes `POST /ui/r/{router}/system/storage/check`
  and `GET|POST .../storage/format`, and in `kcc-domain` the public
  `storage::{MaintenanceAction, MaintenanceRequest, plan_maintenance}`. They named
  `system partition check|format`, which no catalog has, so every call was refused.
- **Test-only and pass-through `kcc-domain` items.** `wifi::ns3_presence` and
  `wifi::Ns3Presence`, `InterfaceChangeError::is_fail_safe_unarmed`, `SafetyNet::commit`
  and `configuration::save` (callers use `ChangeSet::commit`/`save`), and the unused
  `router` argument of `interfaces::apply`. A management interface change no longer reads
  `show last-change` a second time after the workflow's own check, and a VPN credential
  write no longer downloads the running configuration a second time for the presence
  check the workflow already ran.
- **The test-only migration retry policy.** `kcc_migrate::apply::StopPolicy`
  (`ContinueOnNonCritical`), `ApplyOptions::stop_policy` and `PlannedLine::non_critical`
  (also the `non_critical` member of the plan JSON phases): no front end could select the
  retry, and a migration always stops at the first rejected line.

### Fixed

- **`kcc` commands fit Windows' 1 MiB main-thread stack again.** After the MCP settings
  change, `kcc preset apply` in a debug build overflowed it on Windows; the command
  dispatchers now box each command's future. Linux and macOS were not affected.
- **Migrations and presets no longer copy Entware settings.** The `opkg disk`, `opkg chroot`,
  `opkg dns-override`, `opkg initrc`, `opkg timezone` and `opkg object-group` lines are
  skipped as source hardware instead of being copied to the target.
- **An Entware time zone containing `//` (a URL) is refused.** The planner sent
  `opkg timezone https://...` to the router; it now refuses such a name as an invalid CLI
  token before any request, on the Web, in the CLI and over MCP, where the same check runs
  before the router is contacted.

- **kcc can create its state on Windows.** Creating the state directory or any owner-only
  file failed with "The parameter is incorrect" (Windows error 87). The entry now gets the
  process user as owner and a protected DACL whose only ACE gives OWNER RIGHTS full access;
  nothing is inherited from the parent directory, and a directory passes its ACE on to the
  entries created inside it.
- **A migration cannot half-move a router defined in `kcc.toml`.** When the management
  phase moved such a router to another address, kcc kept the new URL only in memory
  (a reload brought the old one back) but already wrote the new password into the
  operator's `password_file`. kcc now refuses the move before writing anything and
  logs the `url` to set in `kcc.toml`.
- **The command explorer offers no Execute button for a background command that
  changes the router.** Such a command (`ussd send`, for one) was always refused when
  sent and audited as a validation failure; its detail page now says so and shows no
  button.
- **A new API key is shown even when the key table cannot be read again.** When the
  table refresh after creating an MCP API key failed, the Web UI answered an empty 500
  and the stored, working key was never shown. The dialog now shows the key once in an
  uncached response (never logged or audited), and the table keeps its old rows until
  the page is reloaded.
- **Storage failures on the administration, sign-in and account pages show the
  localized error page.** Users, roles, API keys, sign-in, sign-out, the own password
  change and the account language answered a storage failure with an empty 500; they now
  answer with the generic localized 500 page, like every other page.
- **A role form naming an unknown permission is refused with a field error.** The role
  dialog used to answer such a form with a bare text body; it now shows the form again
  with a localized permission error and stores nothing. The Roles page, the refusal
  messages and the CLI take the permission names from one list.

- **Save is refused while the fail-safe timer is armed.** The configuration page hid
  Save while the timer ran, but a direct `POST /ui/r/{router}/config/save` still saved and
  left the timer armed. It now sends nothing, answers that the changes must be kept or
  rolled back, and is audited `web.config_save` with outcome `armed`.
- **A backup store that cannot be read is reported.** Deleting a backup while the store
  could not be listed answered an unaudited 404 ("not found"); it now shows that the
  backups could not be read and is audited `failed`. A wizard run record that cannot be
  read while its index is built again, or when its apply ends, is logged as a warning
  instead of being dropped silently.
- **The wizards' Roll back confirms the typed router name as every other destructive
  dialog does.** With `confirm=yes` and no name typed the dialog no longer shows the
  name-mismatch error; a wrong name still shows it and nothing is sent.

- **A migrated realm-bound password with an encoded hash is sent as a plain password.**
  Replacing `user <name> password md5|nt ns3 <hash>` produced
  `user <name> password plain ns3 <password>`, which the target cannot decode; the
  migration and preset classifiers now share one replacement that writes the password as
  a plain word.

- **An FQDN group description can be set.** `kcc dns fqdn-group ... --description` and the
  MCP DNS tool were always refused (the group name was validated as an unknown field of
  `object-group fqdn description`); the description is now sent as
  `object-group fqdn <name> description "<text>"` on 5.x firmware. 4.3 documents no such
  command and still refuses it before anything is sent.
- **One unreadable firewall rule no longer blocks every firewall write.** The CLI and MCP
  firewall writes read back only the list they change, and keep a rule they do not model
  (for example `port gt 1024`) as an unstructured entry; before, such a rule in any list
  made every write fail, and an added rule was reported failed after it was sent.
- **VPN planners**: deleting through the VPN client path now reads the interface first and
  refuses a name that is not a VPN client type (WireGuard, OpenVPN, IPsec, L2TP, PPTP, SSTP,
  ZeroTier, OpenConnect, proxy), and a VPN client delete keeps the Destructive risk (the Destructive permission and
  confirmation now apply to it). WireGuard
  import errors name the line only: `UnknownField`, `Malformed` and `Duplicate` carry no field
  name or line text, so a mistyped key line never appears in an error, Debug output or log.
  WireGuard ASC accepts at most 16 values and quotes each value in the rendered line. The
  VPN server status reads the IPsec virtual IP per crypto-map name (`crypto map`), and
  `VpnServerStatus::ipsec_virtual_ip` is now a map from crypto-map name to its virtual-IP
  settings.
- **Clearing a connection-policy description works.** An empty description field on the
  Web page, MCP and CLI now sends `no ip policy <name> description` (no argument);
  before, the plan failed locally with an invalid-response error and nothing was sent.

- **Route removal is verified by the route's own command.** A removal succeeds when the
  exact `ip route` or `ipv6 route` line is gone from a fresh running configuration; the
  routing-table row count is no longer compared, so inactive routes and concurrent table
  changes no longer fail a removal. The broad-clear recovery now restores the static
  routes saved from the running configuration (interface-only and default routes
  included) instead of the routing table, restores every one before it reports the first
  failure, and reports a route the model cannot carry (`auto`, `reject`) as an invalid
  response after all others were restored.

- **A failed segment-creation step is rolled back too.** When a step's request reached
  the router and its read-back (or audit) failed, creation now removes that step with the
  earlier ones; a step the router refused, or that failed before it was sent, is not
  rolled back.

- **One malformed `kcc-segment:` description no longer hides every segment.** Segment
  discovery skips an ownership record it cannot decode (bad JSON, invalid values, or a
  context other than its VLAN) and logs a warning with the line number only.

- **DHCP pools are read only from their own block.** Indented lines of a later
  top-level block (`bind` under `ipv6 subnet`, `enable` under `crypto map`) no longer
  overwrite the last pool's interface or state, so the DHCP page and the static lease
  subnet check use the pool's real binding.

- **Client pseudonyms are complete, exact and bounded.** `[privacy] redact_clients_in_mcp`
  now also pseudonymizes client names (`name`, `hostname`, `host`, `fqdn`, `alias` inside a
  client object), replaces MAC, IPv4 and IPv6 addresses found inside any free-text string,
  and applies the same pseudonymizer to progress notifications of running tools. An
  identifying key is matched by whole word (`ip`, `ip_address`, `ipAddress`, `mac`,
  `hostname`, `address`), no longer by the letters "ip": `description`, `script` and `tip`
  keep their values. Pseudonyms, in MCP results and in the per-client metrics labels, are now
  `client-` plus 16 hex digits of a keyed hash with a random per-process key (before:
  `client-N` from a map that grew with every client seen). They are stable only while one
  kcc process runs and change with every start; the metrics pseudonym of a MAC also differs
  per router.
- **MCP results keep their codes when they are cut to `max_result_bytes`.** A result over the
  budget used to be replaced by `{"truncated": true, "next_cursor": "1"}`, which dropped the
  error code, the fail-safe message and the unsaved/persists flags of a failed write. Now
  `error`, `message`, `field`, `unsaved`, `persists_immediately`, `audit_pending`,
  `request_id`, `applied`, `rebooting`, `factory_reset`, `job_id` and `status` are kept, the
  largest array is cut to the items that fit, and `truncated` is `true`. `next_cursor` is the
  offset of the first item not returned, and only for a tool that has a `cursor` input (it is
  absent when no item fits and for every other tool). A kept payload that alone exceeds the
  budget is still refused with `internal`.
- **The MCP `fields` argument is applied.** `kcc_routers_list`, `kcc_catalog_search` and
  `kcc_rci_read` keep only the requested members of every object item of the result's
  arrays (the router `statuses` of `kcc_rci_read` are kept whole); an unknown name is absent
  and masked or pseudonymized values stay masked. Before, the argument was validated and
  ignored.
- **MCP `limit` is clamped to 1..=100** for `kcc_routers_list` and `kcc_catalog_search`, like
  the migration tools. `limit: 0` used to return no items and, for `kcc_catalog_search`, a
  `next_cursor` equal to the current cursor.
- **The `confirm` input of the curated MCP write tools is documented truthfully**:
  "required when the change touches management" (or is destructive), one text for the
  routing, policy, NAT, firewall, client, DHCP, segment and DNS tools (and every other
  curated write tool). Before, those tools called it "unused". `kcc_firewall_write` no longer
  lists the `index` and `description` inputs: the tool never accepted them and answers
  `invalid_arguments` as before when they are sent.

- **Tab-indented configuration text is refused instead of being flattened.** Leading
  whitespace other than spaces is an invalid-indentation parse error naming the line;
  space indentation reads as before.
- **A show read the router serves only by POST keeps its query.** When a router refuses
  GET for a show resource (404 or 405), kcc reads it by POST with the query parameters as
  the body; before, the POST was sent empty, so a filtered read (for example one
  interface's statistics) returned the unfiltered answer, and every later read of that
  resource ignored its query. A 404 for one query no longer moves the whole resource to POST.

- **Router session cookies are refreshed only from answers that may refresh them.** A 401
  no longer installs the cookie it carries (which skipped the next sign-in and failed the
  replay), an answer to a request sent with an older cookie no longer replaces a newer
  sign-in, and a malformed refresh of the session cookie, or an unrelated cookie that is not
  plain ASCII, no longer turns a change the router applied into an error.
- **Concurrent HTTP digest requests keep one nonce count.** Requests challenged with the
  same nonce at once continue one count instead of each restarting it.
- **File, lock and sealing work no longer runs on the async workers.** The automatic
  pre-change backup, router profile and password writes, job records (start, end and the
  startup recovery), every file of the Web migration and preset wizards, and the preset
  store behind the Web pages and the MCP preset tools now run on Tokio's blocking pool,
  so a slow disk or a lock held by the CLI no longer stalls other Web, MCP and polling
  work. A request dropped while such a write runs no longer interrupts it: the write
  completes.
- **One unreadable preset no longer hides the others.** The preset list skips and logs
  (file name only) every record it cannot read, open or parse, I/O errors included; only
  an unreadable presets directory fails the list.
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
- **Router sessions are reused and ended.** A profile with a read-only login signs in once
  and keeps that session across polling rounds (it used to open a new session, and run the
  ndw4 key derivation, on every poll and never sign out); the session is replaced when
  the profile changes and signed out when `kcc serve` or `kcc mcp stdio` stops. A
  background operation (for example a log read) reuses the main client's derived keys,
  signs its own session out when it finishes or its handle is dropped, and puts the
  router's process id into its request as an encoded query value. A cancelled background
  operation now returns the new `RciError::Cancelled` instead of `RciError::Timeout`
  (a deadline still returns `Timeout`). A subscriber that joins just as an idle router
  poller exits now still gets data.

- **Retention survives an unreadable backup file.** A malformed or unreadable `.txt` file in
  a router's backup directory used to make listing and pruning fail for that router for good.
  Such a file is now skipped (it is never moved or deleted), logged once per scan with its
  file name, and counted separately by `BackupStore::listing`; pruning keeps working.
- **Jobs leave no lock files behind.** Each job used to leave `job-<id>.lock` and
  `job-owner-<id>.lock` in the state directory for good. The per-record lock is gone (the
  ownership lock already serializes writers) and the ownership lock file is removed with
  the finished record when it is pruned.
- **A lost final job record is logged.** A failed final write of a job record is logged
  with its error kind instead of being dropped silently.
- **Write jobs need a router by construction.** `JobRunner::start` takes a `JobTarget`
  (`Read(Option<router>)` or `Write(router)`), so a write job without a router can no longer
  be started.
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
- **Diagnostics ask the router for progress every 500 ms**, not every 10 ms, so a running
  ping or traceroute no longer loads the router.
- **Viewers of a router's log page share one reader**: without a log collector, any
  number of open log streams of one router cost the router one `show log` read every
  5 seconds (they used to read it once per viewer); the reader stops when the last
  viewer leaves.
- **A flood of explorer downloads or jobs no longer evicts other users' results**: the
  kept large responses (8) and job answers (32) are bounded per user, a user over the
  bound loses their own oldest, and a running job's answer is never evicted.
- **Page views do less work**: the backups table takes each size from the stored record
  instead of decrypting every backup (`BackupInfo` gains `size`; the file format is
  unchanged), tables sort each row's key once, and the configuration comparison runs off
  the async workers.
- **The migration review no longer takes quadratic time** in the number of form fields
  it submits.

- **Log forwarding is at-least-once while kcc runs, as documented.** A connection error,
  reset or timeout of a log sink is retried like HTTP 429 and 5xx (same backoff, delays
  capped at 60 seconds); it used to drop the batch as permanent. Both sink clients now give
  up a connection after 5 seconds and a request after 30, and an Elasticsearch Bulk reply
  is read up to 8 MiB (a longer one counts as malformed).
- **Records lost at exit are counted.** Records still undelivered when the 10-second flush
  at shutdown ends, in flight or queued, are counted in
  `kcc_log_records_dropped_total{reason="shutdown"}`; a retry wait or a stuck request no
  longer outlives the flush.
- **One malformed router log record no longer stops forwarding** for its router: the
  record is skipped and counted once in
  `kcc_log_records_dropped_total{sink="collector",reason="parse"}`, and the others are
  forwarded.
- **Log collectors stop together.** Every collector's wait between reads ends on shutdown,
  and all collectors are stopped at once, so `kcc serve` no longer waits out a stream
  interval (5 s) or a poll interval (30 s) per router.
- **Batch selection for a log sink measures each record once** and outside the queue lock,
  instead of re-encoding the growing batch for every record while relays wait on the lock.
- **Web dialogs show an error when the router read fails** instead of a form filled in
  from nothing: the security level no longer opens on Private, the address dialog no
  longer opens on DHCP, and the internet, Wi-Fi, route, policy, firewall and port
  forwarding dialogs no longer offer empty choices. Changes checked against the router
  (Add connection, Add route, the policy actions and the dialogs that read their
  choices) stop with the same error, audited `unreachable`, and send nothing; a policy
  change whose policies cannot be read is audited `unreachable`, no longer `gone`.
- **Add connection no longer creates over an existing interface** when the router's
  interface list cannot be read; with the list read, an existing name is refused as
  before.
- **Add route sends the canonical route the router stores**: the IPv4 network without
  host bits (`198.51.100.7` with `255.255.255.0` is `198.51.100.0`), the IPv6 prefix and
  every gateway in canonical form (`2001:DB8:7::1/64` is `2001:db8:7::/64`). The read-back
  compares the route the router stores, and a route it already has is refused as a
  duplicate whatever its spelling.

- **Wizard errors are no longer mistaken for something else.** A migration whose typed
  passwords cannot be opened answered its inputs and preview as if no password had been
  typed, and its apply was audited `refused`; these now answer an internal error, and
  the apply is audited `web.migrate_apply` `failed`. A preset whose settings cannot be
  read when they are revealed was audited `forbidden` with a 403; it is now audited
  `failed` with an internal error (a preset deleted meanwhile answers 404). An apply whose
  files cannot be written, or whose job cannot be admitted for another reason than a busy
  router, is audited `failed` (it was not audited, or read as busy).
- **A bridge member the target lacks reads as target hardware.** The migration review
  showed "the target does not support this setting" for it; it now says it belongs to
  the source's hardware, as the report does.
- **`kcc mcp stdio` shuts down gracefully on SIGTERM and SIGINT.** A signal killed the
  process at once, in the middle of a management change: the disarm was never sent and
  queued audit entries were lost. It now stops reading stdin, waits (at most 10 s) for
  open change brackets, drains jobs, flushes the audit log and exits 0, as `kcc serve`
  does. SIGHUP is unchanged.
- **CLI messages are now translated.** The remaining English-only explanations of the
  command line (`--seconds`, `--from`, `--user-password`, IPv4-only route options, an
  oversized WireGuard file, a source without a firmware version, an unknown `[cli]` or
  stdio role, `healthcheck` and `tls self-signed` failures, and the start-up failures of
  `kcc serve` and `kcc mcp stdio`) are now shown in the output language. English text is
  unchanged. An unsupported `--lang` is now reported in the language of `KCC_LANG`,
  `LC_ALL` or `LANG` instead of always in English.
- **An MCP apply retried at once is admitted, and a busy target is a `conflict`.**
  `kcc_migration_apply` and `kcc_preset_apply` answered as soon as their job reported its
  verdict, while the job still held the target for a moment, so a retry right after a
  refusal (for example with `ack_documentation_tier`) could be refused as `internal`. Both
  tools now answer once the job has ended, and an apply whose job cannot be admitted
  because another write job runs on the target is refused as `conflict`, as the Web
  wizard reports it busy.

### Security

- **CLI lines outside the catalog are destructive changes.** A line the catalog cannot
  map, sent through the raw escape (`kcc_cli_parse`, the Web CLI console's "send
  unvalidated" box), used to be a management change. It is now destructive: besides
  `RawRci` and `ManageRouters` it needs the `Destructive` permission; over MCP also
  `[mcp] allow_destructive = true` and `confirm: true` (as before), and in the Web console
  the router name typed in the dialog instead of a plain confirmation. It still runs under
  the recovery timer.
- **Unknown field names no longer cost time in proportion to their length.** The "did
  you mean" suggestion for an unknown request field skips a name longer than every
  candidate by more than two characters (it cannot be within the suggestion distance), so
  a huge field name in an RCI request no longer builds an edit-distance table per sibling.

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
- **Router `url` values in `kcc.toml` must be origins**: a `[[routers]] url` with a path,
  query or fragment now fails config validation; remove the extra part.
- **Copy the new Quadlet unit** (`StopTimeout=100`) when you deploy with Podman.
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
