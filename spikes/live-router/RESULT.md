# Live-router probe result (todo 53)

Run: 2026-11-05, `bash spikes/live-router/probe.sh` on the development host.

Outcome: `live-skip:kcc_live_url-unset`. No Keenetic/Netcraze router is reachable
from this host and none of `KCC_LIVE_URL`, `KCC_LIVE_LOGIN`, `KCC_LIVE_PASSWORD_FILE`,
`KCC_LIVE_ALLOW_WRITE`, `KCC_LIVE_ALLOW_SERIAL` is set, so the script recorded
`{"live-skip": "kcc_live_url-unset"}` and never touched an auth or write path.
Every assumption below is therefore NOT-RUN. Downstream todos use the R-CLI / R-RCI
semantics as `assumed` until a real run answers them (todo 51's live campaign, or a
manual run of this script against a `test_device` router).

| # | Assumption probed | Status | Todo text that changes if hardware DISPROVES it |
|---|---|---|---|
| 1 | `GET /auth` returns 401 with `WWW-Authenticate` listing `x-ndw2-interactive` (and possibly `x-ndw4-interactive`), `X-NDM-Realm`, `X-NDM-Challenge`, and a session cookie with `Max-Age=300` | NOT-RUN (no live router, `KCC_LIVE_*` unset) | 16 (fake-router `/auth` headers, cookie name, Max-Age) |
| 2 | `show version`, `show system mode`, `show identification` answer on GET with the fields the catalog keys on (`serial`, model, firmware) | NOT-RUN (no live router, `KCC_LIVE_*` unset) | 16 (fake-router fixtures), 28 (rule matching on model/firmware/mode) |
| 3 | A single full-path `parse` of `interface PPTP9 description "kcc-probe"` creates the interface, shows up in `/ci/running-config.txt`, and `no interface PPTP9` removes it | NOT-RUN (no live router, `KCC_LIVE_*` unset) | 16 (`parse` emulation), 30 (applier sends full-path lines, verifies via running-config) |
| 4 | `parse` accepts `authentication password ns3 <blob>`; running-config keeps an ns3 blob that decodes to the same plaintext | NOT-RUN (no live router, `KCC_LIVE_*` unset) | 28 (secret rules carry ns3 verbatim), 30 (applier replays ns3 secrets) |
| 5 | `user kccprobe password plain <p>` is stored as `password md5 md5hex("kccprobe:<realm>:<p>")`, so md5 user hashes are realm-bound and do not move between routers with different realms | NOT-RUN (no live router, `KCC_LIVE_*` unset) | 28 (user-password classification: realm-bound = re-enter), 30 (applier user handling) |
| 6 | `show log` / `show ipsec` behave differently on GET and POST `{}`; `show log` POST `{"once": true, "max-lines": 20}` returns `{"log": {"<id>": {"message": {...}}}}`; stream mode POST `{"once": false, "max-lines": 5}` + GET polls returns `continued: true` and only new ids; DELETE stops it | NOT-RUN (no live router, `KCC_LIVE_*` unset) | 16 (background-process and POST-only show emulation) |
| 7 | `system configuration fail-safe timer reboot 120` arms; an unsaved change stays visible in `show last-change` while the session is kept alive for 60 s | NOT-RUN (no live router, `KCC_LIVE_*` unset) | 16 (fail-safe emulation), 30 (applier arm/verify/commit sequence) |
| 7b | `no system configuration fail-safe timer` disarms but keeps the change in running-config with `unsaved` still true; re-arm + `system configuration fail-safe commit` saves to startup | NOT-RUN (no live router, `KCC_LIVE_*` unset) | 16, 30, and 21-22 (disarm-keeps-unsaved assumption) |
| 8 | Armed 120 s + unsaved change + no requests for 180 s means the router reboots and the change reverts (needs `KCC_LIVE_ALLOW_REBOOT=1`) | NOT-RUN (no live router, `KCC_LIVE_*` unset) | 30 (rollback-by-timeout path), 16 (fault injection) |
| 9 | `show system country` is readable; `system country` persists immediately (R-CLI 27053-27058), outside fail-safe | NOT-RUN (no live router, `KCC_LIVE_*` unset) | 28 (country classified as immediate/unsafe), 30 (applies it last) |

## Script verification done without hardware

- `shellcheck spikes/live-router/probe.sh` (v0.11.0) exits 0 with no `disable` directives.
- With `KCC_LIVE_*` unset: prints `live-skip:kcc_live_url-unset`, writes the
  skip record, and exits 0 without making any network call.
- Serial gate: run against a scratch loopback mock (not committed) that reports a
  serial missing from `KCC_LIVE_ALLOW_SERIAL`. The mock received only `GET /auth`,
  `POST /auth` (ndw2 login, needed to read the serial) and
  `GET /rci/show/identification`. The script printed `live-skip:serial-not-allowed`
  and sent no RCI POST and no cleanup requests.
- The bash ns3 codec matches `zyxel_scramble.py` (R-NS3) on encode and decode test
  vectors.
- A scratch end-to-end run against the same mock exercised probes 1-7b and 9, and
  probe 8 correctly skipped. Cleanup left no interface, user, description or armed
  timer behind, and the evidence file contained none of the password, ns3
  plaintext/blob, challenge, session id or hashes. The mock only exercises the
  script's logic. It says nothing about real firmware behaviour, so none of the
  rows above changes.
