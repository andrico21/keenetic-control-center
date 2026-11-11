# Presets, settings copy and migration

kcc moves configuration between routers in two ways:

- **Presets and settings copy** move selected groups of settings (DNS, routes, Wi-Fi,
  ...) onto a router that keeps the rest of its configuration.
- **Migration** replays a whole configuration onto another router, usually a fresh one
  replacing an old one.

Both read the source's **startup** configuration (from a router, a kcc backup or a
saved file), so unsaved changes on a source router aren't copied. Both apply under the
target's fail-safe timer and verify what they wrote. Neither saves until you choose
to. The Web UI pages are described in [USER_GUIDE.md](USER_GUIDE.md); this document
explains the rules.

## Presets and settings copy

### Groups

A preset is a set of groups captured from one source. Each group selects whole
configuration lines:

| Group | Lines it takes | Secrets |
|---|---|---|
| `dns-secure` | `dns-proxy` TLS and HTTPS upstreams, filter, intercept, rebind protection, max TTL | kept encrypted |
| `dns-records-routing` | `ip host`, `object-group fqdn`, `dns-proxy route` | none |
| `policies` | `ip policy` | none |
| `static-routes` | `ip route`, `ipv6 route` | none |
| `firewall` | `access-list`, `interface * ip access-group` | none |
| `vpn-clients` | WireGuard, OpenVPN, IPsec, ZeroTier, OpenConnect and proxy interface settings, L2TP/PPTP/SSTP interfaces, `crypto` | WireGuard keys regenerated |
| `wifi` | Wi-Fi SSID, authentication, encryption, hidden SSID, schedule, up | kept encrypted |
| `system-baseline` | time zone, NTP, remote syslog, SSH/Telnet/UPnP/NTP services, SSH/Telnet/HTTP security levels | kept encrypted |
| `router-users` | `user` | kept encrypted |
| `schedules` | `schedule` | none |

The definitions live in `crates/kcc-migrate/rules/groups.toml`.

### Dependency inclusion

A group can depend on definitions its lines refer to. When a selected line names an
interface, a connection policy, an FQDN object group or a schedule, the definition of
that object is pulled in too. For example a DNS route pulls the policy and object group
it references, and a Wi-Fi schedule pulls the schedule. The review lists every pulled
line with its reason.

### Merge and Mirror

- **Merge** (default) adds or updates the captured lines and keeps everything the
  target has on its own.
- **Mirror** does the same, then removes target lines in the selected groups that the
  preset doesn't have. Only lines inside the selected groups are removed.

### WireGuard keys

By default kcc doesn't copy captured WireGuard private keys. The target generates new
keys, and the results list the new public keys, so you must update the peers. Use
`--keep-wireguard-keys` in the CLI (or the option in the Web UI) to copy the private
keys instead. Two routers then share one WireGuard identity, so kcc adds a warning to
the results.

### Rules for applying

- The target's firmware must be the same as or newer than the source's.
- A documentation-based target firmware needs an explicit acknowledgement
  (`--ack-documentation-tier`).
- Interfaces, ports and radios that don't exist on the target must be mapped, or the
  plan is blocked; in the CLI exclude them with `--exclude`.
- Router-user password hashes are realm-bound (see below); you type the password.
- Lines kcc can't send through a validated request are marked `unsupported` and left
  out.

### Finishing

After apply and verification you choose:

- **Keep unsaved**: stop the fail-safe timer and keep the changes in the running
  configuration only.
- **Save**: write them to the startup configuration.
- **Roll back**: restore the configuration from before the run.

The CLI requires `--finish keep-unsaved|save|rollback` when it has no terminal.

### Storage

Stored presets are encrypted in `<state>/presets/`. Transient copies (`kcc copy`, Copy
settings in the Web UI) are never stored as presets. MCP transient presets and Web UI
drafts of a new preset live in memory and are lost on restart.

### Example

The examples use the same router as source and target so they run anywhere; in practice
`--router` (or `--to`) names another router.

```bash kcc-doc-test
kcc router add home --url "$ROUTER_URL" --login admin --password-file router.pw
kcc preset capture --from home --groups dns-secure,static-routes --name lan
kcc preset list
kcc preset show lan
kcc preset plan lan --router home --mode mirror
```

Copying straight from one router to another, then rolling back:

```text
kcc copy --from home --to lab --groups dns-secure --finish rollback
```

## Migration

### How it works

1. **Source**: the startup configuration of a router, a kcc backup
   (`backup:<router>/<name>`) or a saved file (`file:<path>`).
2. **Target inventory**: kcc reads the target's model, firmware, ports, radios,
   interfaces and current configuration without changing anything.
3. **Mapping**: source ports, radios and interfaces are mapped onto the target's.
4. **Classification**: every source line gets a disposition (below).
5. **Plan**: lines in replay order, with redacted reports in JSON, Markdown and HTML.
6. **Apply** under the fail-safe timer, line by line, then verification.
7. **Finish**: commit (fail-safe commit and save) or roll back.

### Firmware rule

The target firmware must be the same as or newer than the source's, and at least 4.3.
The source version comes from the configuration header or the live router; when
neither has it, planning stops. A documentation-based target needs an acknowledgement.

### Clean target

Migration expects a target in factory or near-factory state. Lines the target has and
the source doesn't are reported as residual and flagged `target_not_clean`; the plan
still proceeds and leaves them in place unless you choose to remove them in the review.
Factory-reset the target first for a predictable result.

### Dispositions

| Disposition | Meaning |
|---|---|
| `copy` | replayed unchanged |
| `remap` | replayed after a mapping or your replacement value |
| `skip-hardware` | left out: describes the source hardware |
| `skip-identity` | left out: carries the source's identity |
| `needs-input` | blocks until you supply a value or decision |
| `unsupported` | left out: the target catalog can't validate it |
| `conflict` | blocks: the target has a different value; choose which wins |

### Never migrated, and why

- **Identity**: KeenDNS registration and booking, cloud registration, ACME and other
  certificates and PKI material, mesh pairing, interface MAC addresses, kernel
  tunables set with `system set`. Copying them would clone the source's identity.
- **Agreements**: `dpn accept` and `eula accept` aren't replayed; the target's own
  agreement texts are shown for you to accept.
- **Hardware**: LEDs, buttons, USB power, radio calibration, USB and printer settings
  tied to the source device.
- **Embedded save commands**: the plan never contains a save; finishing is your choice.

### Realm-bound passwords

Router-user passwords are stored as hashes bound to the device's authentication realm
(`md5(login:realm:password)`). A hash from another device doesn't work, so these lines
are `needs-input`: you type each password (CLI: `--user-password <user>=<file>`) and kcc
sends it as `user <name> password plain`, encrypted in kcc until the migration ends.
kcc asks even for the same model, because realm equality hasn't been confirmed on
hardware.

### Management phase and reconnect

Lines that change how kcc reaches the target (management interface address or security
level, HTTP port or SSL) move to a final phase and need the address kcc should use
afterwards (`--reconnect-url`). kcc switches to it after those lines and allows two
minutes per transition to reach the router again.

### Fail-safe behaviour

- kcc arms the target's fail-safe timer (900 s by default, 300 to 3600) before the
  first migrated line and renews it while it works. A factory-fresh target gets its
  admin password first.
- Lines are sent one at a time, so a critical rejection stops the run before later
  lines execute.
- On failure, or Stop, kcc rolls back. If kcc stops or loses the router, the timer
  restores the saved configuration by itself.
- Encrypted (`ns3`) secrets are sent as they are; only an explicit rejection makes kcc
  retry with the decoded value.
- After a kcc restart the wizard can't resume an apply: it ends as interrupted and the
  router's timer restores the saved configuration.

### Raw restore caveats

Configuration and backups offers a raw restore of a backup onto the same router model:
kcc uploads the file as the startup configuration, reboots, reconnects at the current
address and compares the router's checksum with the uploaded text.

- The backup must name the same hardware and a firmware version; otherwise use the
  wizard.
- Firmware that rewrites the configuration text fails the checksum check.
- There's no live progress, and a backup that changes the management address ends
  with "the router did not answer".

### Rehearsal advice

- Rehearse on a spare router marked `test_device = true`, with the same firmware line
  as the real target.
- Read the plan and report first (`kcc migrate plan`, `kcc migrate report`), then apply
  with `--finish rollback`, check the result, and run again with `commit`.
- Keep a backup of the target and of the source.

### CLI

```bash kcc-doc-test
kcc migrate plan --from router:home --router home --out plan.json
kcc migrate report --from router:home --router home --format markdown --out report.md
```

`kcc migrate apply --from <source> --plan plan.json --finish commit|rollback|keep`
re-plans from the same inputs and refuses if the plan changed. `kcc migrate finish
commit|rollback` finishes a kept migration through the router's fail-safe timer.
In router mode, migration commit and preset save use native commit; in other modes
they save and cancel the scheduled reboot, requiring recovery permission before saving.
If disarming fails, the command reports that recovery remains armed; a completed save
is reported separately. Keeping a preset unsaved requires recovery permission in either mode.

A refused commit or save, or a lost reply before confirmed disarm, also leaves the
finish incomplete. CLI finishes exit 6 and all front ends audit `fail_safe_armed: true`.
MCP `kcc_migration_finish` returns `management_outcome_unknown_fail_safe_armed` for
these closing failures, including failed disarm. Treat recovery as armed even when a
lost native commit reply means the router may already have saved and disarmed.
When a scheduled-mode save succeeds but disarm fails, the saved configuration already
contains the changes. A subsequent reboot or scheduled rollback loads that saved
configuration; it does not necessarily undo the migration. Keep the pre-run backup
if you need to restore the earlier configuration.
