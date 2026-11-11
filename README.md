# Keenetic Control Center (kcc)

kcc manages Keenetic and Netcraze routers through their RCI HTTP API. It's one binary
with three front ends that share the same accounts, permissions, audit log and change
workflow:

- a **Web UI**, the main interface: fleet dashboard, clients, DHCP, segments, network
  and Wi-Fi, routing, NAT, firewall, DNS, VPN, system pages, configuration backups,
  presets, migration between routers, a command explorer, and user, role and API-key
  administration;
- an **MCP server** (Streamable HTTP with API keys, or stdio) for AI assistants;
- a **command-line interface** (`kcc --help`).

kcc is unofficial and is not affiliated with Keenetic Limited or Netcraze.

![Fleet dashboard](docs/images/dashboard.png)

More screenshots: [clients](docs/images/clients.png), [network](docs/images/network.png),
[firewall](docs/images/firewall.png), [DNS](docs/images/dns.png),
[system](docs/images/system.png), [presets](docs/images/presets.png),
[migration wizard](docs/images/migration.png), [audit log](docs/images/audit.png).
The [user guide](docs/USER_GUIDE.md) walks through every page.

## Supported firmware and models

| Firmware line | Tier |
|---|---|
| 5.2 | `documentation-based` (uses the 5.1 command catalog) |
| 5.1 | `hardware-verified` |
| 5.0 | `documentation-based` |
| 4.3 LTS | `documentation-based` |
| Older than 4.3 | `unsupported` |

`documentation-based` lines are built from the official command reference manuals and
tested only against the router simulator in `kcc-testkit`. The live hardware campaign
has not run yet, so no line carries live evidence today. Details, and what differs
between lines, are in [docs/FIRMWARE.md](docs/FIRMWARE.md).

Models come from the official manuals (catalog in [catalog/](catalog/README.md)). The
simulator models KN-1811, KN-1010, KN-3810 and NC-3013. Netcraze models map to their
nearest Keenetic hardware family; that mapping is unverified on Netcraze hardware.

## Install

**Release archives.** Download the archive for your platform from the GitHub releases
page and check it against `SHA256SUMS`:

```text
sha256sum -c SHA256SUMS --ignore-missing
```

Each archive holds the `kcc` binary, the licenses, this file and `kcc.example.toml`, a
sample configuration listing every kcc setting with its default.

**Container.** The OCI image runs as UID 65532 on a distroless base under a seccomp
allowlist. [deploy/podman/README.md](deploy/podman/README.md) covers rootless Podman,
secrets, volumes, the Quadlet unit and the seccomp profile.

**Privilege floor.** kcc refuses to run as root, under sudo or elevated on Windows: it
exits with code 77 before doing anything else. On Linux it also drops every capability
and sets `no_new_privs`. Run it as an ordinary user.

## Quick start

1. Create `kcc.toml` in the config directory (`~/.config/kcc/kcc.toml` on Linux). kcc
   contacts only routers inside `[outbound] allowed_networks`:

   ```toml
   [outbound]
   allowed_networks = ["192.168.1.0/24"]
   ```

   Both `allowed_networks` and `allowed_suffixes` are empty by default, so a fresh
   install refuses every router until you name its network. `kcc router add`,
   `kcc router test`, the Web UI's router form and every command on a router from
   `[[routers]]` then say which setting to change and show the router's address, and
   `kcc serve` logs one warning at startup when routers are configured but both lists
   are empty.

2. Create the first administrator and add a router. The examples in this repository
   use `$ROUTER_URL` for the router address (for example `http://192.168.1.1`) and a
   file `router.pw` holding the router's admin password:

   ```bash kcc-doc-test
   kcc admin init
   kcc router add home --url "$ROUTER_URL" --login admin --password-file router.pw
   kcc router test --router home
   ```

   `kcc admin init` prints the administrator's password once; you change it at the
   first login.

3. Start the server and open <http://127.0.0.1:8443/ui/> in a browser:

   ```text
   kcc serve
   ```

Routers can also be added in the Web UI (Dashboard, Add router). Plain HTTP is
accepted only on loopback; any other listener needs TLS
(`kcc tls self-signed --host <name>` writes a certificate pair) or an https
`public_url` behind a trusted proxy. Every setting is described in
[docs/CONFIG.md](docs/CONFIG.md).

## Command line

The CLI reads the same `kcc.toml` and state directory as the server. Writes run
through the same change workflow as the Web UI (backup, conflict check, read-back,
audit) and never save unless you ask:

```bash kcc-doc-test
kcc info
kcc clients list
kcc interfaces list
kcc interfaces description Bridge0 "Home network"
kcc config state
kcc config save
kcc backup create --reason before-upgrade
kcc backup list
kcc catalog search "ip route"
kcc show version
kcc --json info
kcc audit verify
```

Global options: `--router <id>` picks the router when more than one is configured,
`--json` prints one JSON document, `--lang` picks the output language. Changes that
can cut kcc off from the router need `--yes`; destructive ones need
`--confirm-destructive <router-id>`. Settings copy and migration commands are in
[docs/MIGRATION.md](docs/MIGRATION.md).

## MCP for AI assistants

Two transports serve the same tools ([docs/MCP_TOOLS.md](docs/MCP_TOOLS.md)):

- **stdio**: set `[mcp] stdio_enabled = true`; the client starts `kcc mcp stdio`. The
  local identity gets the role in `[mcp] stdio_role` (default `viewer`).
- **HTTP**: `kcc serve` answers on `/mcp` and needs an API key in an
  `Authorization: Bearer` header. Create one per assistant; the key is printed once:

  ```bash kcc-doc-test
  kcc apikey create claude --role viewer
  ```

Claude Code:

```text
claude mcp add kcc -- kcc mcp stdio
claude mcp add --transport http kcc http://127.0.0.1:8443/mcp --header "Authorization: Bearer <key>"
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.kcc]
command = "kcc"
args = ["mcp", "stdio"]
```

Cursor (`.cursor/mcp.json`):

```json
{ "mcpServers": { "kcc": { "url": "http://127.0.0.1:8443/mcp", "headers": { "Authorization": "Bearer <key>" } } } }
```

Write tools appear only when the role allows them and the toolset is enabled in
`[mcp] toolsets`. Destructive tools, and raw changes to management settings, also need
`[mcp] allow_destructive = true` and `confirm: true` in the call. What an assistant may send to its model provider is
described in [docs/PRIVACY.md](docs/PRIVACY.md).

## Safety model

- **Permissions.** Built-in roles `viewer`, `operator` and `admin`, plus custom roles
  with router scopes. The Web UI, MCP and the CLI check the same permission before any
  router request. Migration, preset and settings-copy applies need `Read`, `Migrate`,
  `Write`, `Save` and `Destructive` before any router request. That fixed set covers
  planning, replay, persistence and the recovery bracket for every finish choice. The
  built-in `operator` can plan these operations but cannot apply them.
- **Change workflow.** Each write takes a per-router lease, makes an encrypted backup of
  the startup configuration, refuses if someone else changed the router in between,
  verifies the result by reading it back and appends a hash-chained audit entry.
- **Fail-safe.** Changes that can cut kcc off (management interface, firewall on it)
  run under the router's fail-safe timer, which restores the saved configuration if
  kcc loses the router. Migration and preset applies always do.
- **Nothing is saved implicitly.** Saving to the startup configuration is a separate,
  explicit step.
- **Secrets stay out of output.** Reports, logs, audit entries and MCP results carry
  redacted values; revealing a secret needs the `RevealSecrets` permission and is
  audited.
- **Managed router passwords are sealed.** Passwords entered in the Web UI or through
  `KCC_PASSWORD`/a CLI prompt are encrypted under the master key in
  `<state>/router-credentials/<id>.sealed`. Back up `master.key` separately; state
  cannot recover these credentials without it. Explicit `--password-file` and
  `password_file` paths remain operator-managed files.

The threat model is in [docs/SECURITY.md](docs/SECURITY.md).

## Limitations

- No firmware line has live hardware evidence yet; see [docs/FIRMWARE.md](docs/FIRMWARE.md).
- kcc refuses to change the password of the router account it logs in with and sends
  nothing to the router. Change that password on the router, then run
  `kcc router edit <id> --new-password`.
- An API key created with `kcc apikey create` reaches a running `kcc serve` only after
  `SIGHUP` (Unix) or a restart; keys created on the Web UI administration page apply
  at once.
- OpenVPN credentials can't be written (the 5.1 catalog has no command for them); IPv6
  access lists are read-only (no catalog has `ipv6 access-list`).
- MCP migration plans, transient MCP presets and unsaved preset drafts in the Web UI live
  in memory and are lost on restart. An armed router timer still rolls the router back.
- Wide tables scroll sideways on phones without a visual cue.

[CHANGELOG.md](CHANGELOG.md) lists what exists today.

## Documentation

- [docs/USER_GUIDE.md](docs/USER_GUIDE.md): every Web UI area.
- [docs/MIGRATION.md](docs/MIGRATION.md): presets, settings copy and migration.
- [docs/CONFIG.md](docs/CONFIG.md): every `kcc.toml` key.
- [docs/SECURITY.md](docs/SECURITY.md): threat model and reporting.
- [docs/PRIVACY.md](docs/PRIVACY.md): what kcc stores and sends.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): crates, data flow, change workflow.
- [docs/MCP_TOOLS.md](docs/MCP_TOOLS.md): MCP tools.
- [docs/MONITORING.md](docs/MONITORING.md) and [docs/METRICS.md](docs/METRICS.md):
  Prometheus metrics, dashboards, alerts and log forwarding.
- [docs/FIRMWARE.md](docs/FIRMWARE.md): firmware support tiers.
- [docs/I18N.md](docs/I18N.md): languages and translation workflow.
- [CONTRIBUTING.md](CONTRIBUTING.md), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
