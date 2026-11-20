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
  out. The CLI plan, the MCP plan and the Web wizard's review and preview show the same
  classification, so the counts there are the ones the apply uses.

### Finishing

After apply and verification you choose:

- **Keep unsaved**: stop the fail-safe timer and keep the changes in the running
  configuration only.
- **Save**: write them to the startup configuration.
- **Roll back**: restore the configuration from before the run.

The CLI requires `--finish keep-unsaved|save|rollback` when it has no terminal.

### Scheduled presets

A weekly scheduled action can apply a stored preset (see `kcc serve`'s scheduled
actions). Nobody is there to answer questions, so a scheduled apply is narrower than an
interactive one:

- **Merge only.** Mirror mode is never offered.
- **Planned again at every run** against a fresh inventory of the router, with the
  owner's role at run time narrowed to the router and the preset's source router. The
  owner needs `Read`, `Migrate`, `Write` and `Save` on the router and `Read` and
  `Migrate` on the source router; a role that lost them pauses the schedule `forbidden`.
- **Refused** when creating the schedule, and **skipped** with a reason at a run:
  a plan that still needs input or conflicts with the router (`not_ready`), a line of the
  management phase (`management_lines`: it can cut kcc's connection or change its
  sign-in password), a WireGuard private key, copied or generated (`wireguard_key`),
  a router on a documentation-based firmware line when the schedule carries no
  acknowledgement (`documentation_tier`), firmware older than the preset's (`firmware`),
  or a preset that is gone (`preset_unavailable`). Component installation is never part
  of a preset apply.
- **Never saved.** A verified apply ends with keep unsaved: the fail-safe timer is
  stopped and the changes stay in the running configuration only, so a router restart
  undoes them. Every message about the run says so, and the run records the router's
  `show last-change` checksum.
- **Rolled back** when a line fails or verification fails: the router returns to its
  saved configuration (`preset_rolled_back`).
- **When the rollback or the keep-unsaved step itself fails**, the run keeps the
  router's lease until the fail-safe timer has run out, then reads `show last-change`: it
  reports that the router restored its saved configuration (`preset_restored`), or, when
  changes are still unsaved or the router does not answer, that the state is unknown
  (`preset_state_unknown`); check the router then.
- An apply that fails before any line is sent is not rolled back; when the fail-safe
  timer's arming could not be confirmed, the message says the timer may still be armed
  (`preset_failed_armed`), and the run keeps the router's lease until the timer's
  interval plus one second has passed, then ends. Interactive applies free the lease at
  once.
- A busy router (lease or job) is tried again like any scheduled action, with a new
  plan each time. The run is the migration job of the applier.

### Storage

Stored presets are encrypted in `<state>/presets/`. Capturing under the id of a stored
preset replaces it only when you hold `Migrate` on its source router; otherwise the
capture is refused. A preset of a router outside your scope is not listed, and showing,
deleting or applying it answers like a missing preset. Transient copies (`kcc copy`, Copy
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
kcc copy --from home --to lab --groups dns-secure --finish rollback --confirm-destructive lab
```

## Migration

### How it works

1. **Source**: the startup configuration of a router, a kcc backup
   (`backup:<router>/<name>`) or a saved file (`file:<path>`).
2. **Target inventory**: kcc reads the target's model, firmware, ports, radios,
   interfaces and current configuration without changing anything.
3. **Mapping**: source ports, radios and interfaces are mapped onto the target's. A
   mapping applies to every line that names the object, including lines with encrypted
   secrets or WireGuard keys. A radio mapping (`WifiMaster0` -> `WifiMaster1`) also
   moves the radio's access points (`WifiMaster0/AccessPoint1` ->
   `WifiMaster1/AccessPoint1`) unless an access point has its own mapping. Presets use
   the same mapping rule.
4. **Classification**: every source line gets a disposition (below).
5. **Plan**: lines in replay order, with redacted reports in JSON, Markdown and HTML.
   Each report item shows the source line and the line sent, with every secret replaced
   by `<redacted>`; the Markdown and HTML headings are in your language.
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

### Verification

After the last line, kcc reads the target's running configuration back: every planned
line must be there, every planned removal gone, and nothing else changed. It then checks
the link of the management interface, the interface whose address kcc connects to (as
reported by `show interface`); a down link fails verification. When no interface holds
that address (NAT, a port forward), no link is checked and the apply report says so with
an empty `management_interface`. Internet reachability is only recorded (`internet` in the
apply report): a target on the bench without an uplink still verifies.

The same management interface decides which lines are management changes, replayed last
and followed by a reconnect. When it is unknown, an address or security-level change of
any bridge counts as one.

### Dispositions

| Disposition | Meaning |
|---|---|
| `copy` | replayed unchanged |
| `remap` | replayed after a mapping or your replacement value |
| `skip-hardware` | left out: describes the source hardware |
| `skip-identity` | left out: carries the source's identity |
| `needs-input` | blocks until you supply a value or decision |
| `unsupported` | left out: the target catalog can't validate it |
| `conflict` | blocks: the target has a different value, an encrypted secret included; choose which wins |

Bridge membership is retained when the target already reports the member or when the
same plan has an executable setting that creates the mapped logical interface. To keep
missing source hardware fail-closed, kcc treats `GigabitEthernet<n>/<n>` (but not its
`/Vlan<n>` logical suffix), `WifiMaster<n>`, `WifiMaster<n>/AccessPoint<n>`,
`FastEthernet*`, `Usb*`, `Ethernet*`, and the `ISP` port alias as physical; every other
interface name is treated as logical. This split is a name heuristic derived from the
catalog and known router inventories, not a hardware-verified fact.

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
hardware. A password you type for a user always wins: kcc sends it even when the
source's hash was made for the target's realm and would otherwise be copied.

### Management phase and reconnect

Lines that change how kcc reaches the target (management interface address or security
level, HTTP port or SSL) move to a final phase and need the address kcc should use
afterwards (`--reconnect-url`). kcc switches to it after those lines and allows two
minutes per transition to reach the router again. A target defined in `kcc.toml` cannot
move: kcc refuses the new address (the log names the `url` to set in `kcc.toml`), stores
nothing, and the run ends like a failed reconnect.

A line that sets the password of the router account kcc signs in with
(`user <login> password plain|md5|nt ...`) is a management line too, in migrations and
in presets (Merge and Mirror). kcc must know that new password: a password you typed for
that account (CLI: `--user-password <login>=<file>`) is used; a hash copied from a router
with the same realm carries no password kcc can use, so the run is refused with "router
password required" before anything is sent. kcc reconnects with the account's current
password until that line has run, and with the new one after it. A line that would
remove that password is refused.

### Fail-safe behaviour

- kcc arms the target's fail-safe timer (900 s by default, 300 to 3600) before the
  first migrated line and renews it while it works. A factory-fresh target gets its
  admin password first.
- If a step before the first migrated line fails (accepting an agreement, installing a
  component), kcc disarms the timer again; when it can't confirm the disarm, it reports
  that the timer may still be armed (MCP `management_not_sent_fail_safe_armed`). Installing components reboots the target onto its
  saved configuration, which clears the timer, and the run ends asking for a fresh plan.
- Lines are sent one at a time, so a rejected line stops the run before later lines
  execute.
- On failure, or Stop, kcc rolls back. If kcc stops or loses the router, the timer
  restores the saved configuration by itself.
- Encrypted (`ns3`) secrets are sent as they are; only an explicit rejection makes kcc
  retry with the decoded value.
- After a kcc restart the wizard can't resume an apply: it ends as interrupted and the
  router's timer restores the saved configuration.
- An applied run nobody finishes holds the target only while the router's timer runs.
  When the timer's interval has passed since its last renewal, the router has restored
  its saved configuration, so kcc lets the target go: the Web run ends as rolled back by
  the router, and an MCP migration or preset apply is closed (its report stays readable
  for an hour). Other writes to the target are refused until then.

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

`--from` (here and in `kcc preset capture` and `kcc copy`) is `<router-id>` or `router:<id>`,
`backup:<router>/<name>` or `file:<path>`.

`kcc migrate apply --from <source> --plan plan.json --finish commit|rollback|keep`
re-plans from the same inputs and refuses if the plan changed. Apply asks for confirmation
on the terminal (or accepts `--yes` for automation); refusal exits 10. `kcc migrate finish
commit|rollback` finishes a kept migration through the router's fail-safe timer.
Applying, keeping and saving need `Read`, `Migrate`, `Write` and `Save`, which the built-in
`operator` role holds: the recovery timer around the run is armed, kept alive and disarmed
under the run's `Migrate`. A rollback finish (chosen with `--finish rollback`, `finish
rollback` or a rollback button) and a plan that installs components also need
`Destructive`, checked before any router request. `--finish rollback` of `migrate apply`,
`preset apply` and `copy` also needs `--confirm-destructive <router>` (a `--yes` alone does
not confirm it), as `finish rollback` does.
When a verification failure causes the router to roll back, apply prints
"Migration verification failed. kcc rolled back automatically and restored the startup configuration." and exits 6.
Any other failure after the first migrated line is rolled back too (by kcc, or by the
router's timer when kcc lost it); apply then says how many lines were applied before the
run stopped and exits with the failure's code (6 for a router failure). Rolling back a run
that is already back on its saved configuration sends nothing and succeeds.
In router mode, migration commit, preset save and `kcc config failsafe commit` use the
native commit, which saves the startup configuration; in other modes they save and cancel
the scheduled reboot.
`kcc config failsafe commit` controls a standalone timer, so in those modes it requires
`Destructive` before saving. An explicit rollback uses the native fail-safe rollback
in router mode and reboots the router at once in other modes, so it restarts with its
saved configuration.
If disarming fails, the command reports that recovery remains armed; a completed save
is reported separately.

A refused commit, save or explicit rollback, or a lost reply before confirmed disarm,
also leaves the finish incomplete. So does a commit or keep that finds the target changed
since verification, or cannot detect the target: it sends nothing, and the timer stays
armed until you roll back or it runs out. CLI finishes exit 6 and all front ends audit
outcome `failed` with `fail_safe_armed: true`.
If the router accepts an explicit rollback and then stays unreachable during the bounded
restore check, scheduled-reboot mode reports that the router is restarting with its saved
configuration; router mode conservatively reports the recovery outcome as unknown and armed.
MCP `kcc_migration_finish` returns `management_outcome_unknown_fail_safe_armed` for
these closing failures, `management_applied_fail_safe_armed` when only the disarm failed,
and `management_saved_fail_safe_armed` when the configuration was saved but the disarm
failed. Treat recovery as armed even when a lost native commit reply means the router
may already have saved and disarmed. A scheduled-reboot rollback the router accepted
before it went silent returns `migration_rollback_restarting` and closes the migration:
every surface reports that the router is restarting with its saved configuration, and
none offers to finish it again.
If the role loses `Save` after apply, finish returns
`management_not_committed_fail_safe_armed`: commit was not sent, recovery remains
armed, and the migration stays available for retry after the role is fixed.
When a scheduled-mode save succeeds but disarm fails, the saved configuration already
contains the changes. A subsequent reboot or scheduled rollback loads that saved
configuration; it does not necessarily undo the migration. Keep the pre-run backup
if you need to restore the earlier configuration.
