# Keenetic Control Center (kcc)

kcc manages Keenetic and Netcraze routers through their RCI HTTP API. It is one
binary with three front ends that share the same permissions, audit log and change
workflow:

- a Web UI (the primary interface): fleet dashboard, network, Wi-Fi, clients, DNS,
  firewall, routing, VPN, system, configuration presets and migration between
  routers, users, roles and the audit log;
- an MCP server (Streamable HTTP with API keys, or stdio) for AI assistants;
- a command-line interface (`kcc --help`).

kcc is unofficial and is not affiliated with Keenetic Limited or Netcraze.

## Supported firmware

| Firmware line | Tier |
|---|---|
| 5.1 | `hardware-verified` |
| 5.0 | `documentation-based` |
| 4.3 LTS | `documentation-based` |
| Older than 4.3 | `unsupported` |

`documentation-based` lines are built from the official manuals and tested only
against the simulator in `kcc-testkit`. See [docs/FIRMWARE.md](docs/FIRMWARE.md).

## Quick start

Download the archive for your platform from the GitHub releases page and check it
against `SHA256SUMS` (`sha256sum -c SHA256SUMS --ignore-missing`). Each archive holds
the `kcc` binary, the licenses, this file and `kcc.example.toml`, a sample
configuration listing every setting with its default.

```bash
kcc admin init      # create the first administrator; prints its password once
kcc serve           # start the Web UI and MCP server on 127.0.0.1:8443
```

Then open the Web UI, sign in and add a router. Before kcc may contact a router, list
the router's network in `[outbound] allowed_networks` of `kcc.toml` (see
`kcc.example.toml`).

## Documentation

- [docs/MONITORING.md](docs/MONITORING.md): Prometheus metrics, dashboards, alerts and
  log forwarding.
- [docs/MCP_TOOLS.md](docs/MCP_TOOLS.md): MCP tools exposed to AI assistants.
- [docs/PRIVACY.md](docs/PRIVACY.md): what kcc stores and what it may send to a model.
- [docs/FIRMWARE.md](docs/FIRMWARE.md): firmware support tiers.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
