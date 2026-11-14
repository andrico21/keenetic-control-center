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

- **One message per migration failure**: the CLI, the Web UI, MCP and the engine report
  each migration failure with the same sentence. `ReplanRequired` asks to review the plan
  again everywhere (the preset page used to show the drift text), and the MCP migration
  finish reports a failed disarm by what it left (`management_applied_fail_safe_armed`
  or `management_saved_fail_safe_armed`) instead of always
  `management_outcome_unknown_fail_safe_armed`.

### Changed

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

### Fixed

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

### Known limitations

See the Limitations section of [README.md](README.md). No firmware line has live
hardware evidence yet.

[Unreleased]: https://github.com/andrico21/keenetic-control-center/commits/master
