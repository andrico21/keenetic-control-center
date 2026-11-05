# Problems - keenetic-control-center

Unresolved blockers and technical debt discovered during work on this plan.

_Auto-scaffolded by /ulw-execute. Append new entries below - never overwrite._

---

## [todo 53] Live-router assumptions unverified (no hardware) - 2026-11-05
- `spikes/live-router/probe.sh` ran as `live-skip:kcc_live_url-unset`; RESULT.md marks all probes 1-9 (incl. 7b) NOT-RUN.
- Still unverified on real firmware: fail-safe semantics (arm, disarm-keeps-unsaved, re-arm + commit, reboot-revert), `parse` accepting `ns3` secrets, realm-bound `password md5` user hashes, POST-only / background `show log` + `show ipsec` behaviour, `/auth` header shape.
- Impact: todos 16 (fake router v2), 28 (migration rules), 30 (migration applier), and 21-22 (disarm-keeps-unsaved) build on R-CLI/R-RCI semantics marked `assumed`. Re-run the probe on a `test_device` router (todo 51) and fold any DISPROVED row into those todos.
