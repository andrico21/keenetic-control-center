# kcc-live-readiness: learnings (append-only; CI lessons, gotchas, conventions discovered while executing)

Public repository: never write the owner's router id, address, host, network, serial, MAC, name, SSID or any captured value here (the leak scan `python3 /home/andrico/kcc-live-scan.py staged` runs before every chore(omo) commit).

## [2026-11-26] Executor notes carried over from the review
- Leak scan hit blocks the commit; no override. If a learned identifier is an ordinary word that new code legitimately contains, stop and ask the owner; never weaken the scan.
- Todo 28: one test for Stop in session-continuation mode (dedicated session signed out, no DELETE sent). The new Web continuation-ping test must not use `#[tokio::test(start_paused = true)]` with the loopback fake.
- Todo 9: its evidence log should also show the schedule-eligibility (`kcc`) and telemetry (`kcc-app`) tests.
