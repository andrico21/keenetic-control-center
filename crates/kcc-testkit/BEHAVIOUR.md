# Fake router behaviour

`disconnect_after_parse` applies the matching parser command then resets its TCP
connection and subsequent connections. `disconnect_before_parse` resets them without
executing the command. These opt-in faults simulate loss of management connectivity;
they do not stop the simulated recovery timer or alter its state. This is assumed
fault injection, not captured hardware behaviour.

What `kcc-testkit`'s `FakeRouter` simulates, and where each behaviour comes from.

Sources:

- **R-RCI**: [Eralde/rci-tools](https://github.com/Eralde/rci-tools) `docs/AUTH.md`
  (ndw2 login) and `docs/RCI_API.md` (resource kinds, root batching, `show rc`/`show sc`,
  `no`, DELETE). Documented behaviour of real routers.
- **R-RS**: [hexqnt/keenetic-rci](https://github.com/hexqnt/keenetic-rci) @ `b7f3f79`
  (MIT OR Apache-2.0). The ndw2 known-answer vector in `src/ndw2.rs` and the shape of the
  `show version`, `show identification`, `show system` and `show interface` fixtures are
  adapted from its `src/auth.rs` and `tests/fixtures/`.
- **assumed**: chosen for the simulator from R-CLI/R-RCI documentation, not confirmed
  against a router. Todo 53 was `NOT-RUN` because no hardware was available; see
  `spikes/live-router/RESULT.md` and `.omo/evidence/task-53-keenetic-control-center.json`.

## Profiles

| Model | Product (`X-NDM-Product`) | Realm | Firmware profiles |
|-------|---------------------------|-------|-------------------|
| `KN-1811` | Titan | `Keenetic Ultra` | 5.1.3, 5.0.12, 4.3.9 |
| `KN-1010` | Giga | `Keenetic Giga` | 5.1.3 |
| `KN-3810` | Hopper | `Keenetic Hopper` | 5.1.3, 4.3.9 |
| `NC-3013` | Speedster | `Netcraze Speedster` | 5.1.3 |

- The 5.1 profiles are seeded from `fixtures/<hw_id>/settings.json` and
  `fixtures/<hw_id>/show.json`. The seeds are synthetic (no capture yet, todo 17): MACs
  are `02:00:00:*`, addresses come from 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24,
  serials are zeros. Port counts differ per model (`KN-3810` and `NC-3013` have one LAN
  port fewer). **assumed**
- **`KN-1811` 4.3.9, `KN-1811` 5.0.12 and `KN-3810` 4.3.9 are `assumed
  (documentation-derived)`.** There is no 4.3 or 5.0 hardware. These profiles start from
  the model's 5.1 seed and drop every JSON pointer listed in `fixtures/derived/4.3.json`
  or `fixtures/derived/5.0.json`. Today that list holds `ipv6 access-list` (documented
  from the 5.1.1 CLI on). It grows when the 4.3/5.0 catalogs (todos 12-14) name more
  commands and fields absent from those lines.
- `show version` reports the profile's `title` and `release` (`5.1.3`/`5.01.C.3.0-0`,
  `5.0.12`/`5.00.C.12.0-0`, `4.3.9`/`4.03.C.9.0-0`) unless the builder overrides them.
  The release strings are **assumed**.

## Authentication (`/auth`)

| Behaviour | Source |
|-----------|--------|
| `GET /auth` without a valid session: 401 with `WWW-Authenticate: x-ndw2-interactive realm=".." challenge=".." session_id=".." session_cookie=".."`, `X-NDM-Realm`, `X-NDM-Challenge`, `X-NDM-Product`, `Set-Cookie: <NAME>=<sid>; Path=/; SameSite=Strict; Max-Age=300` | R-RCI (real routers send `SameSite=Lax`; the plan pins `Strict`) |
| Cookie name: 12 random uppercase letters, fixed per server instance; session id 16, challenge 32 random uppercase letters | R-RCI examples; lengths **assumed** |
| Every `GET /auth` without a valid session opens a new session with a new challenge | **assumed** |
| `POST /auth {"login","password"}` accepts `sha256hex(challenge + md5hex(login:realm:password))` (lowercase) for the cookie's session: 200 `{}`; anything else 401 with an empty body, and the challenge stays the same | R-RCI hash; failure handling **assumed** |
| `GET /auth` with a valid session: 200 `{}` | R-RCI status; body **assumed** |
| `DELETE /auth`: ends the session, 200 `{}`; 401 without a valid session | **assumed** |
| Sessions expire after 300 s idle (sliding: every authenticated request refreshes them) | `Max-Age=300` from R-RCI; sliding **assumed** |
| Every `/rci` request without a valid session: 401, empty body (checked before the body is read) | plan |

## RCI (`/rci/`)

`FaultInjection::refuse_batch_pointer` refuses each root batch item containing the
configured JSON pointer before applying it. The HTTP response remains 200 and has
one ordered response per item; refused items contain an RCI error status. Other
items execute normally. This is assumed fault injection for completion reporting,
not captured router behavior.

| Behaviour | Source |
|-----------|--------|
| `GET /rci/` returns the whole settings tree; `GET /rci/<path>` the node at `<path>` | R-RCI |
| `?name=X` on a named collection (e.g. `interface`) selects entry `X`; as the last step the answer is `{"X": {..}}`, mid-path it descends (`/rci/interface/traffic-shape?name=X`) | R-RCI |
| `?name=` / `?mac=` on an array selects the first member with that field | R-RCI (`ip hotspot host`) |
| Unknown settings path or unmatched selector: 404, empty body | **assumed** |
| `POST /rci/` and `POST /rci/<path>` take an object or an array; an array is applied in order and answered with an array | R-RCI |
| Answers mirror the request; each written leaf answers `{"status":[{"status":"message","code":"0","ident":"FakeRouter","message":".."}]}` | R-RCI shape; codes/idents **assumed** |
| Fields the tree does not know are dropped from the answer, so a body of only unknown fields answers `{}` and changes nothing | R-RCI (`{}` for empty), plan |
| `"no": true` deletes the addressed node, or matching array members (`name`/`mac`, all members without an identity) | R-RCI |
| New keys under `interface` (or `{"name": ".."}`) create an entry | R-RCI |
| An array member body with `name`/`mac` updates the matching member or appends one | **assumed** |
| A POST to a path that does not exist answers `{}` | **assumed** |
| `DELETE /rci/<path>?name=..|mac=..` removes the node: 200 with a status, 404 if absent | R-RCI; 404 **assumed** |
| Bodies over 1 MiB: 413 | R-RCI ("about a megabyte"), exact limit **assumed** |
| Bodies that are not JSON: 400 | **assumed** |
| `/rci` without the trailing slash: 405 for every method | plan |

## Show and read-through

| Behaviour | Source |
|-----------|--------|
| `GET`/`POST /rci/show/<path>` answer from the profile's show fixtures; a missing fixture is 404 with an empty body | plan |
| `?name=`/`?mac=` (or string fields of a POST body) narrow a show fixture: an object keyed by name yields the entry, an array the first matching member | R-RS `show interface` shape; narrowing **assumed** |
| In a root POST, `{"show": {"system": {}}}` and `{"show": {"clock": {"date": {}}}}` answer the fixture nested in the request shape; unknown shows answer `{}` | R-RCI |
| `{"show": {"rc": ..}}` and `{"show": {"sc": ..}}` fill the request shape from the JSON settings tree | R-RCI |
| `GET /rci/whoami` returns `{"name": <login>, "tags": [..]}` | R-RCI names `whoami` as readonly; shape **assumed** |

All profiles add the same deterministic synthetic baseline after model-specific seed loading
and older-firmware removals. The baseline is **assumed** and contains:

- six `show ip hotspot` clients spanning wired/wireless and registered/unregistered states,
  matching DHCP bindings, ARP neighbours and wireless associations;
- `Bridge0` with `192.0.2.1`, Internet-facing `ISP`, 2.4/5 GHz `WifiMaster0`/`WifiMaster1`,
  access points, and numeric `show interface stat` counters keyed by interface id;
- policy, IPv4/IPv6 route, DNS proxy, media, USB, schedule, KeenDNS, mesh-member and UPnP
  redirect answers;
- `show rc interface <name>` projects `ip access-group <acl> in|out` bindings from the
  mutable configuration. **assumed**
- 480 synthetic `show ip nat` rows whose compact JSON exceeds 100 KiB for pagination tests.

`show interface bands` and `show system mode` remain absent and return 404. Dynamic AST
projections for hotspot, DHCP bindings, routes, DNS proxy and interfaces layer over these
fixtures; fixture values remain the baseline for unmodified rows and fields.

## CLI configuration files and parser

- A silent-no-op entry equal to a full CLI command intercepts special handlers
  too, including native fail-safe commands. The existing `parse` entry retains
  its ordinary-command scope. **assumed fault injection**, added for task 67.
- Named crypto-map virtual-IP enable/range/DNS fields project from the map context.
  This task 67 projection is **assumed**, not a hardware capture.
- Mesh acquisition adds a member whose id equals the candidate identifier to fresh
  `show mws member` responses. **assumed**, added for task 67; no hardware capture.
- Structured NTP server/master/sync-period writes update the mutable AST and
  `show rc ntp`; silent-no-op injection targets `ntp`, not `parse`. **assumed**.
- VPN/SSTP/OpenConnect server interface, pool and DNS settings, OpenConnect routes
  and WireGuard server interface bindings project from mutable CLI state. These
  task 67 projections are **assumed**, not hardware captures.
- KeenDNS booked names, HTTP proxy contexts/upstreams and cloud security levels
  project from running CLI state. Dropping a name removes its booking. These task
  67 projections are **assumed**, not hardware captures.
- WAN CLI address, DHCP, identity, connect-via, priority, MTU and default-route
  settings project under `show rc interface` from mutable interface leaves.
  Default-route is false when absent. **assumed**, added for task 67.
- `show rc system log` projects configured servers, suppressed identifiers and the
  reduction flag from mutable CLI state. **assumed**, added for task 67.
- `ip hotspot default-policy <selection>` replaces the configured default;
  `ip hotspot policy <interface> <selection>` replaces only that interface's policy.
  `show rc ip hotspot` projects `default-policy` and the interface-keyed `policy`
  object from the mutable AST. **assumed**, added for task 67; no hardware capture.
- `show rc schedule` projects schedule names, descriptions and configured action
  times from the mutable AST. `show schedule` includes these configured rows.
  This task 67 projection is **assumed**, not captured from hardware.
- Management listener `show rc ip http|ssh|telnet` fields are projected from the
  mutable CLI AST: numeric ports, security levels and HTTP SSL enable/redirect/port.
  Absent SSL enable and redirect commands project false. **assumed**, not captured
  from hardware; added for task 67 fresh read-back verification.
- The JSON settings tree and CLI configuration ASTs are deliberately independent stores.
  A write to one does not propagate to the other. Tests must not infer propagation.
- `show rc ip policy` projects policy contexts and their child commands from the running
  configuration AST for curated-domain write verification. **assumed**
- `access-list <name> rule <index> disable|description <text>|schedule <name>` stores one
  line per rule and property (the `no` form removes that property only), and `access-list
  <name> rule <index> order <new-index>` moves the rule among the list's permit and deny
  lines instead of storing a line, renumbering the property lines with it; an unknown list
  or an out-of-range position changes nothing. **assumed (R-CLI documentation 3.3.4, not
  live-verified)**
- Every profile seeds running and startup `kcc-config` ASTs from
  `fixtures/<hw_id>/startup-config.txt`. Seed addresses are documentation ranges.
- `GET /ci/running-config.txt` and `GET /ci/startup-config.txt` print canonical AST text
  with model, version, `http/rci` agent, and the lowercase MD5 of the command body.
- Root `POST {"parse":"<full-path line>"}` mutates only running config. Supported
  stand-in catalog commands cover interface creation/removal, description and IP address,
  save/reboot, fail-safe, components, and tools used by this simulator. Unknown commands
  return code `7405600` and leave the AST byte-identical. This command-existence check is
  temporary until `kcc-catalog` exposes its generated catalog at runtime.
- RCI writes for `system hostname`, `system description` and `system clock timezone`
  update the settings tree, running CLI AST, matching `show system` or `show clock date`
  projection, and `show last-change` unsaved state together. **assumed (R-CLI catalog and
  R-RCI projection shape, not live-verified)**.
- `parse` accepting `authentication password ns3 <blob>` is **assumed (R-CLI
  documentation, not live-verified - see `spikes/live-router/RESULT.md`)**. The AST parser
  itself accepts typed NS3 tokens; the simulator catalog stand-in does not yet expose that
  command.

## Fail-safe and last change

All semantics in this section are **assumed (R-CLI documentation, not live-verified - see
`spikes/live-router/RESULT.md`)** because todo 53 probes 7 and 7b were `NOT-RUN`:

- `timer reboot 60..86400` arms; `keep-alive` restarts the full period.
- `no ... fail-safe timer` disarms while leaving unsaved running changes intact.
- `commit` copies running to startup and disarms; `rollback` restores startup and simulates
  reboot.
- Injectable-clock expiry restores startup, disarms, and drops every session. The next use
  of an old cookie is 401.
- `show last-change` returns agent, user, running checksum, unsaved flag and a `fail-safe`
  object with active/mode/timeout/remaining.

## Uploads, processes and injected faults

- `Handle::max_concurrent()` reports the peak number of simultaneously handled HTTP
  requests since that fake router started, including authentication, background requests,
  and injected latency. A cancellation-safe guard decrements the active count on handler
  exit. This is server-side test instrumentation, not a firmware behavior assumption.

- `PUT /fui/startup-config.txt` parses and replaces startup config; running changes only
  after `system reboot`. **assumed (R-RCI/R-FORUM-UPLOAD documentation, not live-verified).**
- `tools ping` returns a per-instance background process id and running state. POST-only
  show/process behavior is **assumed (R-CLI documentation, not live-verified - see
  `spikes/live-router/RESULT.md`)**.
- `components install <name>` and `components remove <name>` stage additions/removals,
  visible through `show components list` and `show components pending`. `components commit`
  clears every session immediately and opens a five-second temporary-unreachable window:
  every HTTP request receives 503 until the injectable `Clock` reaches the deadline. The
  first request after expiry atomically applies the staged set, bumps the final firmware
  title/release build (`5.1.3` -> `5.1.4`, `5.01.C.3.0-0` -> `5.01.C.4.0-0`), and updates
  `show version` `ndw.components`. **assumed (R-CLI documentation, not live-verified).**
- `components check-update [force]` is unknown to the fake unless
  `FakeRouter::with_firmware_update` opts in. Then the parser answers a `message` status
  plus `"available": true, "version": "<title>"` (`FirmwareUpdate::Available`) or
  `"available": false` (`FirmwareUpdate::Current`) and changes nothing. **assumed (answer
  shape not live-verified; the catalog marks the command as an action that changes no
  settings).**
- `FaultInjection` is per fake-router instance: acknowledged silent no-op paths, HTTP 500
  after N requests, latency, session drop after N requests, and refusal to disable
  management `Bridge0`. No mutable state is shared between separately built instances.
- `FaultInjection::fail_parse_matching(substring, times)` rejects only the next `times`
  matching parser lines with an RCI error status before mutation; unrelated and later
  parser requests succeed. **assumed**
- `FaultInjection::fail_safe_arm_noop(true)` answers `system configuration fail-safe timer
  reboot <s>` with `fail-safe armed.` but leaves the timer off, so `show last-change` keeps
  `fail-safe.active: false`. **assumed (models a router that acknowledges without arming)**
- `system country <code>` (parser) and `POST /rci/system/country` are applied to running and
  startup configuration at once: no save is needed, the unsaved flag does not change, and
  fail-safe expiry or rollback cannot undo it. **assumed (R-CLI documentation "permanently
  stored", not live-verified: todo 53 probe 9 `NOT-RUN`)**
- `FaultInjection::route_wipe_on_remove(true)` makes the next single-route `no ip route` or
  `no ipv6 route` remove every running static route in that address family and return
  `cleared all routes.`; the fault then disarms. **assumed (simulates the R-MCP2 incident)**
- `FaultInjection::show_requires_post(path)` answers `GET /rci/<path>` for that show
  resource (for example `show/clock/date`) with 404 and an empty body, while
  `POST /rci/<path>` answers as usual. **assumed fault injection** (models a router that
  serves a show resource only by POST; lets tests tell the client's POST fallback for show
  commands from a plain GET)
- `Handle::request_log()` records method, path, sorted query pairs, and non-secret root
  parser lines. Parser lines containing password or key command fields are omitted; headers,
  cookies, authorization values, and other request bodies are never retained.
  `settings_snapshot`, `running_config_text`, and `startup_config_text` expose independent
  store snapshots for workflow assertions. **assumed test observability API**

## Other assumed protocol details

- Imported WireGuard private keys and peer preshared keys are encoded as NS3 before
  insertion into the running AST; `show interface` reports presence only. Omitting
  the private key retains the existing router-generation simulation. **assumed
  (documentation-derived, not verified against hardware)**.
- Replaying an already encoded WireGuard secret preserves its NS3 token. The
  parser also accepts the catalog's name-only `ip dhcp host <host>` form as a
  stored declaration. Both extensions are **assumed**, exercised by the migration
  matrix rather than verified against hardware.
- Interface IPsec PSKs, named IKE keys, and IPsec profile PSKs/XAuth passwords
  use NS3 storage in the fake. IKE identity selectors remain non-secret arguments;
  replacement uses the key name. These CLI shapes and storage choices are **assumed**.

- POST-only `show log` and `show ipsec` behavior remains **assumed (R-CLI documentation,
  not live-verified - see `spikes/live-router/RESULT.md`)** and is not yet a full stream
  emulation.

## Not simulated yet

ndw4, token and digest auth, and full `show log` streams.

## Migration scenarios (assumed)

An explicitly empty admin password (`builder.user("admin", "", ...)`) models factory
setup: `/auth` returns 200 without a cookie and reads are available until a successful
`user admin password plain` sets the credential. Password changes update authentication
and invalidate sessions. This behavior is assumed, not hardware-verified.

`FakeRouter::with_migration(migration::Fixture)` enables optional operating-mode replies,
unaccepted DPN/EULA documents and explicit acceptance, NS3 rejection, management movement
between two HTTP Host values, and clock-driven loss after a configuration write. Ordinary
fixtures retain their historical absent mode/agreement endpoints. Both listeners for an
address transition can serve clones of the same router; the inactive host returns 503.
Expired fail-safe timers are processed before connectivity checks, restoring running
configuration and the original management host. All these semantics are assumed from
the todo-53 NOT-RUN fallback, not observations of real firmware.

Legacy-firmware fixtures (4.3 and 5.0 derived trees) also carry `cifs master` and `kabinet port`
nodes, which exist only in those catalogs, so raw-tool tests can create and remove a
legacy-only command. These nodes are test fixtures, not observations of real firmware.
