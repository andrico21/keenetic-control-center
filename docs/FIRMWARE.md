# Supported firmware

kcc talks to KeeneticOS and NetcrazeOS routers through the RCI HTTP API. Every firmware
line has a support tier, which the Web UI shows on the router dashboard and `kcc info`
prints.

| Firmware line | Tier | Catalog | Live evidence |
|---|---|---|---|
| 5.2 | `documentation-based` | 5.1 | not applicable |
| 5.1 | `hardware-verified` | 5.1 | live verification not yet run |
| 5.0 | `documentation-based` | 5.0 | not applicable |
| 4.3 LTS | `documentation-based` | 4.3 | not applicable |
| Older than 4.3 | `unsupported` | none | not applicable |

- **`hardware-verified`** lines are listed in `HARDWARE_VERIFIED` in
  `crates/kcc-rci/src/capabilities.rs`; a test checks this table against it. 5.1 is
  the line of the owner's test routers. The live hardware campaign hasn't run yet: its
  suites recorded `live-skip` because no live router was available. Until it passes,
  5.1 has the same evidence as the other lines.
- **`documentation-based`** lines are built from the official Keenetic command
  reference manuals and tested only against the router simulator in `kcc-testkit`,
  not on real hardware. The dashboard of such a router says so. Reads and changes stay
  allowed; migration and preset applies onto such a target need an explicit
  acknowledgement.
- **`unsupported`** means firmware older than 4.3, or a version kcc can't read. Reads
  may be incomplete, and there is no command catalog, so validated writes are refused.

## What differs between lines

- **Command catalog.** Each line has its own catalog generated from that line's
  manuals (`catalog/4.3`, `catalog/5.0`, `catalog/5.1`); 5.2 and newer use the 5.1
  catalog until a 5.2 catalog exists. Commands missing from a router's catalog are
  refused before anything is sent, so pages and tools hide them.
- **Sign-in.** kcc picks the scheme the router advertises: `x-ndw2-interactive` on
  the lines up to 5.1, `x-ndw4-interactive` (Argon2-based, expected on 5.2) when the
  router offers it, or HTTP digest. ndw4 is tested only against the simulator.
- **Migration direction.** Configuration moves only onto the same or a newer line.
- **Missing everywhere.** No catalog has `ipv6 access-list`, so IPv6 firewall lists
  are read-only.

## Models

The catalogs cover the Keenetic models with an English manual for each line
([catalog/sources.lock](../catalog/sources.lock)); when a router's model isn't in the
catalog, kcc uses the union of all models of that line. Netcraze models map to their
nearest Keenetic hardware id (`NETCRAZE_ALIASES` in `kcc-rci`); no Netcraze hardware
has been tested. The simulator models KN-1811, KN-1010, KN-3810 and NC-3013.
