# kcc-live-readiness: issues (append-only; defects found outside a todo's scope, flakes, surprises)

## [2026-11-26] Todo 4 (outside scope, not fixed)
- `crates/kcc-testkit/src/capture.rs` `verify_serial` reads `show identification` through `RciClient::show`, which retries as `POST /rci/show/identification` after a GET 404/405; the hardware protocol lists only GET for show resources. Left unchanged because todo 4 must not change `--allow-serial` gating; a real router answers the GET, so the POST never happens there. Reproduce: a FakeRouter with `FaultInjection.show_requires_post` containing `show/identification`, then `verify_serial`; the request log shows the POST.
- `crates/kcc-testkit/src/capture.rs` (now about 800 code lines, 478 before) and `src/anonymize.rs` (about 980, 764 before) are far over the ~250-line file budget; todo 4 kept the plan's placement (`items()` and `CALL_SITES` in capture.rs) and moved its new logic into `capture/continued.rs` and `capture/self_check.rs`. A later split (render/write, fetch, item table) would be a refactor of its own.

## [2026-11-26] Todo 4 fix round: residuals not fixed (by brief)
- NextDNS profile ids (`sni`, `uri`, `profile` under `nextdns`) are not aliased.
- `object-group fqdn` group names and their addresses are not aliased.
- `Rendered::write` reuses an existing capture directory without clearing it (stale files of an earlier run stay; predates todo 4).
- `map_ipv6` records a link-local address as a learned identifier even when its mapping returns it unchanged (small interface id, e.g. `fe80::1`); the self-check would then exit 3 on such a router (fail-closed false positive; predates this round).
- A 4-5 character name glued to a word character in another case (`Vasya` vs `vasya_pc`) is neither rewritten nor found (by the whole-word rule for short values); the exact spelling is still rewritten.
- The global `name` alias still over-learns system words (`admin` from whoami), now case-insensitively for values of 6+ chars.
- `capture.rs` (~960 lines) and `anonymize.rs` (~1290) remain over the file-size budget; this round put new logic into `anonymize/fold.rs`, `anonymize/mac_forms.rs`, `anonymize/variant_tests.rs`, `capture/self_check.rs` and `tests/capture/leaks.rs`.

## [2026-11-26] Todo 4 fix round 3: accepted residuals
- Not rewritten nor detected (no real router form, or would need a crate/normalization pass): JSON-escaped (`\uXXXX`) values inside text, NFD vs NFC, fullwidth forms, zero-width/soft-hyphen insertions, values split across a line break, base64 of a name.
- A 4-5 character learned value glued to a word character in another case is neither rewritten nor found (whole-word rule for short values; avoids false exit 3).
- A learned `fqdn` with a trailing dot does not match text without the dot.
- Link-local IPv6 that keeps its interface id is kept and not learned; a hashed link-local alias stays in `fe80::/64`.
- An IPv6 address glued to a letter or digit (`ip2a02:...`) is no longer rewritten; if the same address is learned elsewhere the self-check exits 3 (fail closed), else it survives.
- The post-open `(dev, ino)` check in `append_identifiers` (TOCTOU) has no test (needs a race); the pre-open symlink checks are tested. A parent-directory symlink swapped between check and open is out of scope.
- File sizes: `capture.rs` ~1000 lines and `anonymize.rs` ~1260 remain over budget (this round moved runs, components and identifiers-out logic into submodules; `capture.rs` grew by the components match and the split `write`).

## [2026-11-26] Todo 2 (outside scope, not fixed)
- `cargo machete` from the repository root (a G1 command) exits 1 on the base commit too: it reports `rmcp-macros` and `tokio` unused in the tracked `spikes/lint-macros/Cargo.toml` (`lint-macros-spike`). `cargo machete crates xtask` is clean. Reproduce: `cargo machete` at the repo root.
- With a TRACE subscriber, `hyper_util` logs the router's socket address (`127.0.0.1:<port>` in tests) at DEBUG/TRACE under its own target; `kcc_rci=debug` does not enable it, a bare `debug` filter would.

## [2026-11-26] Todo 11 (follow-ups, not changed)
- Only `web-kit-confirm-destructive-text` now says "Type the router ID ({ $id })". These still say "Type the router name to confirm" while their `{ $router }` now shows the display name (the gate still wants the id; the wrong-name error `web-explorer-confirm-name-error` names the id): `web-explorer-confirm-destructive-text`, `web-config-rollback-text`, `web-config-delete-text`, `web-config-raw-text`, `web-migrate-rollback-text`, `web-presets-rollback-text`, `web-system-entware-ssh-confirm-{read,probe,local,change}`, `web-system-entware-ssh-intro`; the typed field's label `web-explorer-confirm-name` is "Router name". Reproduce: add a router named `Home Office`, open Configuration > Roll back.
- Fragments rendered with a bare `fragment_shell` show the id where they name a router through `Localize::router_name` / `Shell::router_name` (e.g. the preset compose panel's source line, the preset report downloads and the reveal dialog title); full pages and the pickers show the name.
- CLI Fluent messages with `$router` (cli.ftl, 64 uses) keep the id.

## [2026-11-26] Todo 4 fix round 4: residuals left as recorded
- R1: a learned value equal to an interface id (a client named `Bridge0`) makes the self-check fail (exit 3), because `show-interface-stat-<id>` is a router-derived manifest string. Fails closed; kcc's shapes keep ids under `id`/`interface`, not host keys.
- R2: the mode of an EXISTING identifiers file is not tightened to 0600 (only a new file is created 0600, as the plan requires).
- R4: a run killed between `Rendered::write` and the self-check leaves an unchecked capture directory; the next run refuses it (exit 1), so the operator must inspect or delete it.
- Out of scope, found while deciding the IPv4 sweep: the anonymizer rewrites any dotted-quad run, so 4-part version strings in JSON (the `show version` `title`, component versions) become `203.0.113.N` in the fixtures (fidelity loss, not a leak). Todo 12 may want to know before reading component versions from the capture.

## [2026-11-27] Todo 11 fix round: outside scope
- `web-admin-role-scope-help` / `web-admin-error-scope` say "router names" (en; de "Routernamen"; kk) while role scopes match router IDs. Pre-existing wording; candidate for todo 26 or a follow-up.

## [2026-11-27] Todo 4 fix round 5: residuals D16-D18 (verifier proposed fixes for possible later round)
- **D16** (low, ~7% of addresses): a learned IPv4 address written in reversed form (in-addr.arpa or reversed ISP PTR) survives when the reversed quad falls in a range kept by the anonymizer: loopback (ends in .127), multicast (.224–.239), link-local (x.x.254.169), or netmask-shaped.
  - Location: `crates/kcc-testkit/src/anonymize/ipv4_forms.rs:158–168` (the reader `holds_learned` only compares forward windows), and `anonymize.rs:907–913` (`keeps_ipv4` keeps those ranges).
  - Repro: learn `81.2.69.230`, then `text("<230.69.2.81>.in-addr.arpa")` unchanged, self-check passes (exit 0).
  - Proposed fix (verifier round-5 report):
<<'FIX_D16'
In `holds_learned`, after matching each window's forward bytes, also match its reversed octets against `learned`:
- After line 165, add `|| quad(run, &reversed_four).is_some_and(|address| learned.contains(&address))` where `reversed_four` = the window in reverse order.
- This fails closed: any learned address never survives reversed.
FIX_D16

- **D17** (low): a learned /48 in the `ip6.arpa` nibble form (12 dots, e.g., `1.2.3.4.5.6.0.0.0.0.0.a.b.c.d.ip6.arpa`) or dashed spelling (e.g., `2a02-6b8-1c2d`) survives with exit 0.
  - Location: `crates/kcc-testkit/src/capture/self_check.rs:114–127` (reader `learned_addresses` and `anonymize/runs.rs:225–235` (`holds_prefix` reads `:` spans only).
  - Repro: addr `2a02:6b8:1c2d:3e4f:...` with ptr `1.2.3.4.5.6.0.0.0.0.0.a.b.c.d.ip6.arpa` gives exit 0 with nibbles in file; dashed `-` spelling survives too.
  - Proposed fix:
<<'FIX_D17'
In `learned_addresses`, add each learned /48's nibble string (12 reversed nibbles joined by `.`) and its `-`-joined spelling (plain and zero-padded) to the needles checked by `holds_prefix`. Example: `2a02:6b8:1c2d::` -> nibbles `d.2.c.1.8.b.6.0.a.0.2.0` and dashed `2a02-6b8-1c2d`.
FIX_D17

- **D18** (low): `cafe:<G48>::1` (non-routable leading group joined to a routable /48) keeps `<site>` as the subnet and exits 0 even when `<G>` is learned.
  - Location: `crates/kcc-testkit/src/anonymize/runs.rs:134–153` (`shape` function), with `anonymize.rs:819–823` (a Routed address keeps its s3).
  - Repro: `text("cafe:<G48>::1")` with G learned -> exit 0, marker in file.
  - Proposed fix:
<<'FIX_D18'
When `!is_routable(s0, s1) && is_routable(s1, s2)` (non-routable leading group but routable offset-1 pair), classify as `Embedding` (subnet dropped) instead of `Routed`. Add test case `cafe:<G48>::1` and `1:<GC>` to `addresses_joined_to_link_local_or_multicast_groups_are_rewritten`, asserting that the `:site>` group is rewritten with the learned address.
FIX_D18

## [2026-11-27] Todo 12 (outside scope, not fixed)
- The fake router answers `POST /rci/components/list` with its component-state OBJECT, while kcc's `components::read_components` reads `GET show/components/list` and decodes a SEQUENCE; replaying a fake-router capture shows it (`live_components_list`: "show components list at $: found object, expected a sequence", and `live_entware_status` through it). Reproduce: capture the fake with `kcc-capture --allow-loopback`, then `KCC_LIVE_CAPTURE_DIR=<abs dir> cargo test -p kcc-domain --test live_capture_decode -- --ignored live_components_list`.
- `kcc-capture` installs `tracing_subscriber::fmt().init()` without honouring `RUST_LOG`, so it cannot print its own value-free request list (`kcc_rci::session::send` DEBUG lines); todo 12's action log had to be reconstructed from the documented request set.

## [2026-11-28] Todo 28 (outside scope, not fixed)
- `crates/kcc-domain/src/diagnostics.rs` `read_log` (todo 21): when the first POST `show log` answer has `continued: true` it calls `client.start(path, ..)`, which is a SECOND POST in a new session (restarts the stream) and then polls a stream that never stops continuing. Before todo 28 this failed at once with `Decode(MissingPointer("/process/id"))`; now it ends with `RciError::Timeout` after the handle's 300 s deadline. Reproduction: `KCC_LIVE_CAPTURE_DIR=<abs capture dir> cargo test -p kcc-domain --test live_capture_decode -- --ignored live_log` (fails after 300 s, "the router did not answer in time"). Todo 21 should read the one-shot form or consume the stream's first chunks itself, never `start()` after a POST.
- `live_components_list` (object vs sequence) and `live_components_pending` (router not-found) still fail on the capture: todo 19.
