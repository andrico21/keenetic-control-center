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

### Known limitations

See the Limitations section of [README.md](README.md). No firmware line has live
hardware evidence yet.

[Unreleased]: https://github.com/andrico21/keenetic-control-center/commits/master
