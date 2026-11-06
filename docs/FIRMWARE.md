# Supported firmware

kcc talks to KeeneticOS and NetcrazeOS routers through the RCI HTTP API. Every firmware
line has a support tier, which the Web UI shows on the router dashboard.

| Firmware line | Tier | What it means |
|---|---|---|
| 5.1 | `hardware-verified` | Exercised by the live hardware suites on a test router. |
| 5.0 | `documentation-based` | Built from the official manuals; no real-hardware run yet. |
| 4.3 LTS | `documentation-based` | Built from the official manuals; no real-hardware run yet. |
| Older than 4.3 | `unsupported` | Not supported; reads may be incomplete. |

The `documentation-based` lines are built from the official Keenetic command-line
manuals and are tested only against the simulator in `kcc-testkit`, not on real
hardware. The dashboard of a router running one of them shows a notice saying so; reads
and changes stay allowed.

A line becomes `hardware-verified` only after the live suites pass on it; the list lives
in `HARDWARE_VERIFIED` in `crates/kcc-rci/src/capabilities.rs`.
