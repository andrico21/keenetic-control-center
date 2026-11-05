# Fake router behaviour

What `kcc-testkit`'s `FakeRouter` simulates, and where each behaviour comes from.

Sources:

- **R-RCI**: [Eralde/rci-tools](https://github.com/Eralde/rci-tools) `docs/AUTH.md`
  (ndw2 login) and `docs/RCI_API.md` (resource kinds, root batching, `show rc`/`show sc`,
  `no`, DELETE). Documented behaviour of real routers.
- **R-RS**: [hexqnt/keenetic-rci](https://github.com/hexqnt/keenetic-rci) @ `b7f3f79`
  (MIT OR Apache-2.0). The ndw2 known-answer vector in `src/ndw2.rs` and the shape of the
  `show version`, `show identification`, `show system` and `show interface` fixtures are
  adapted from its `src/auth.rs` and `tests/fixtures/`.
- **assumed**: chosen for the simulator, not confirmed against a router. The live probe
  (plan todo 53) has not run yet; todo 16 reconciles these rows with its evidence.

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
| `{"show": {"rc": ..}}` and `{"show": {"sc": ..}}` fill the request shape from the settings tree. Both read the same tree here; todo 16 adds separate running/startup configs | R-RCI; single tree is a simplification |
| `GET /rci/whoami` returns `{"name": <login>, "tags": [..]}` | R-RCI names `whoami` as readonly; shape **assumed** |

## Not simulated yet

Background processes, `system configuration save`, CLI `parse`, fail-safe, ndw4, token and
digest auth, `show log` streams. These come in todos 10, 16 and later.
