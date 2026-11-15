Ask: validate every lane A finding in `findings/A.md` against the code, following `CRITIC.md`. Wanted: a verdict per finding. For you: all 22 are checked. No finding is refuted outright. 9 are confirmed and 13 are adjusted, mostly downgraded or with corrected evidence. 3 stay at medium; the reviewer had 9. I made no edits and did not run `cargo`. Now: nothing in progress; the review is complete. Next: nothing; this answer is the deliverable.

### A-01 CONFIRMED
- checked: `crates/kcc-config/src/secrets.rs:1-214`, `config_text.rs:295-349` (tokenize folds `ns3 <blob>` into `Token::Ns3`), `kcc-testkit/src/cli_engine/secrets.rs:21-48`, `kcc-domain/tests/vpn_credentials.rs:80-97`, consumers `kcc/src/cli/redact.rs:46-63`, `kcc-migrate/src/presets/model.rs:198-205`, `kcc-migrate/src/rules.rs:248-312`, `kcc-web/src/wizard/analysis.rs:32-39`, `kcc-web/src/config_page/text.rs:64-74`, `kcc-testkit/src/anonymize.rs:274-298`.
- reasoning:
  - I traced each case by hand. For `interface X ipsec preshared-key ns3 B`, the index is 4, which is the expanded `ns3` word. `replace_expanded_word` only matches `expanded+1` on an `Ns3` token, so nothing is replaced.
  - For `crypto ike key office ns3 B any`, the index is 3, so `office` is replaced.
  - `crypto ipsec profile … preshared-key|xauth-password` matches no registry arm.
  - Every consumer I found re-masks `Token::Ns3`, so router-written text does not leak today.
  - Plaintext input is still exposed, because consumers mask only ns3 tokens. A hand-written preset or upload line `crypto ike key office PLAINPSK any` keeps `PLAINPSK`.
  - The unit test's `crypto ike key theta` has no name argument, so it cannot catch this.
- severity: medium

### A-02 CONFIRMED
- checked: `crates/kcc-rci/src/session.rs:120-132, 380-442, 638-654, 693-703, 767-798`
- reasoning:
  - `refresh_session` runs before the 401 check. It overwrites the cookie value for any same-name `Set-Cookie`.
  - `reauthenticate_after` then sees a different cookie and skips login. The replay is sent with the unauthenticated cookie.
  - The R1/R2 overwrite also holds. A local `Max-Age` expiry starts a new login while the request with the old cookie A is still in flight, and its refresh writes A back over B.
  - Point 3 is more reachable than the finding implies. `parse_set_cookie` returns `Err(Auth(Rejected))` for an empty matching value (`:780-782`), so a `name=; Max-Age=0` clear on an applied POST turns success into an error.
  - The precondition, a real router sending `Set-Cookie` on 401 or a cookie-clearing header, is still unverified.
- severity: medium (high only if real routers send a cookie with 401)

### A-03 CONFIRMED
- checked: `crates/kcc-rci/src/engine.rs:394-413`, `kcc-app/src/poller.rs:437-449`, `kcc-mcp/src/generic/rci.rs:198-206`, `kcc/src/cli/rci.rs:54-56`, `kcc-web/src/advanced/rci.rs:205`
- reasoning:
  - The fallback POSTs `{}` and drops `query`.
  - The cache key is `path.to_string()` only, so after one 404 every later query on that path goes unfiltered POST.
  - The poller, MCP, CLI and Web all pass non-empty queries to `show`.
  - Which resources answer 404 to GET is inferred; for example, an unknown `name` might.
- severity: medium

### A-04 ADJUSTED
- checked: `crates/kcc-rci/src/engine.rs:415-451, 647-675`, `kcc-app/src/workflow.rs:1035-1108, 1284-1295`, `kcc-app/src/workflow_batch.rs:42-73`; grep for `stop_on_error`
- reasoning:
  - There is no length check, and `completion` zips, so missing items count as neither succeeded nor failed.
  - A transport error on chunk 2 makes `apply_batch` return through `?` at `:1059-1064` before the audit record (`:1089-1098`). Chunk 1 is then applied and unaudited. This needs a batch over 900 KiB.
  - The `stop_on_error` bullet is unreachable: nothing in the workspace sets it, and it defaults to `false`.
  - A router replying with a short array is unverified.
- severity: medium
- correction: Drop the `stop_on_error` impact. The concrete consequence is an applied but unaudited multi-chunk batch on a later-chunk failure, plus silent miscounting if the reply is short.

### A-05 ADJUSTED
- checked: `crates/kcc-rci/src/lib.rs:402-483, 606-629`; status fixtures across the repo (`kcc-testkit/src/config_state.rs:208-215`, `tree.rs:142`, `lib.rs:739`, plan text quoting the router format)
- reasoning:
  - The code fails open as described. An item that does not deserialize is skipped, and `from_value` returns `Ok`.
  - Every fixture and the documented router format use a string `code` and the levels message, warning and error. Nothing shows a firmware sending a numeric code, a missing `message` or another level.
  - So this is a weakened boundary check with no demonstrated trigger.
- severity: low
- correction: This is defense-in-depth. Decide the level from `status` alone and treat unknown levels as errors. The claim that rejected writes are reported as applied is inferred only.

### A-06 ADJUSTED
- checked: `crates/kcc-config/src/config_text.rs:138-189, 295-349`
- reasoning:
  - `trim_start_matches(' ')` leaves a leading tab, so `spaces == 0` and the line becomes top-level. `tokenize` then skips the tab as whitespace.
  - Router-generated text never contains tabs. Only hand-edited uploads or presets do.
  - Orphaned children usually fail catalog lookup and show up as unsupported in the plan or preview, so this is not silent. The only valid stray command is the bare context line, for example `interface Bridge0`.
  - No lockout or wrong-router command is demonstrated.
- severity: low
- correction: The issue is real; it is a minor bug on a rare input. Reject non-space leading whitespace.

### A-07 ADJUSTED
- checked: `crates/kcc-rci/src/engine/background.rs:1-164`, `engine.rs:607-628`, `session.rs:498-515`, `ndw4_keys.rs:18,142-149,223`, `kcc-domain/src/diagnostics.rs:160-215`, `docs/BACKLOG.md:62`
- reasoning:
  - Every claim is true:
    - each `start()` builds a new `Manager` with an empty ndw4 cache;
    - `logout` is called only from `#[cfg(test)]` code (`ndw4_keys.rs:223`);
    - cancellation returns `Timeout` (`:133`);
    - `process_id` is put into the URL unencoded.
  - Diagnostics and continued log reads are user-initiated and rare. Each costs one extra login, and the router-side session leak is inferred.
  - The single global Argon2 permit is already in BACKLOG:62, so the "stalls every router" impact is not new.
- severity: low

### A-08 ADJUSTED
- checked: `crates/kcc-catalog/src/request.rs:41-85, 136-219`, `runtime.rs:155-169, 456-476`, `risk_tests/independent.rs:116-130`, `kcc-mcp/src/generic/rci.rs:263-285`, `kcc/src/cli/rci.rs:60-78`, `kcc-web/src/advanced/rci_check.rs:190-210`, `kcc-app/src/workflow.rs:971-990`, `kcc-web/src/page_kit/change.rs:110-135, 350-375`; grep for `HttpMethod::Delete`
- reasoning:
  - `capture` ignores `method`. Only `interface` DELETE is raised to destructive.
  - The repo's own test (`removals_have_the_delete_risk_floor`) asserts `deleted.risk.max(Risk::Destructive)`, so raising the floor at the call site is deliberate.
  - Every raw DELETE caller applies it. Curated DELETEs authorize through `request.permission`, not `validated.risk`.
  - No current bypass exists. The cost is duplication that may drift, and the cited newtype rule is a stretch.
- severity: low

### A-09 ADJUSTED
- checked: `crates/kcc-rci/src/auth_digest.rs:55-231`
- reasoning:
  - The race exists: two 401s each build `count = 0` and the last writer wins.
  - A spurious `Err(Auth(Rejected))` needs two unverified things: the proxy reuses the nonce across 401s, and it enforces strictly increasing `nc` even though each request sends a fresh random `cnonce`.
  - The path is only used in DigestProxy (KeenDNS) mode, under the default concurrency of 2.
- severity: low

### A-10 ADJUSTED
- checked: `crates/kcc-rci/src/engine.rs:518-533, 545-573, 698-711`, `session.rs:608-625`, `kcc-config/src/ns3.rs:30-70`, `kcc-catalog/src/runtime.rs:178-223, 296-327`, `secret_value.rs:1-82, 205-240`
- reasoning:
  - These parts hold:
    - `read_capped` grows a plain `Vec`, so each reallocation frees an unwiped copy of config bytes.
    - `Part::bytes(…to_vec())` copies the startup config without zeroizing.
    - ns3 `decode` drops the plaintext `bytes` unwiped on the `InvalidUtf8` path.
  - Two sub-claims are wrong:
    - `runtime.rs` `value.clone()` moves straight into `SecretValue::new`, which takes the secret leaves into `SecretString`. The replaced `request.protected` is then dropped through that type.
    - `session.rs:622` sends the ndw2 response digest, which is bound to the challenge, not the reusable password.
- severity: low
- correction: Limit the finding to `read_capped` (and `SecretSlice::from(Vec)`, which can reallocate), the multipart `to_vec`, and the ns3 error path.

### A-11 CONFIRMED
- checked: `crates/kcc-catalog/src/validate.rs:96-125, 210-232, 366-410`, `kcc-mcp/src/support/validate.rs:61-86`, `docs/BACKLOG.md:63`
- reasoning:
  - The MCP value cap is 900 KiB, so a single key of about 900k characters passes. `nearest` then builds a full matrix per sibling: roughly 900k by 15 cells of 8 bytes, about 100 MB each, sequentially, in synchronous code.
  - Any role with `Read` can reach this through `rci_read`.
  - BACKLOG:63 covers only the hand-written helper, not this bound.
- severity: low

### A-12 ADJUSTED
- checked: `crates/kcc-rci/src/engine.rs:150-243, 270-292, 423-451, 518-601`, `session.rs:325-331, 524-530`, `background.rs:27`
- reasoning:
  - The bootstrap and background managers have no observer. `is_bootstrap` logs in without a permit. Only `send` reports request outcomes.
  - One correction: `batch`, `download_config` and `upload` use `self.session`, which has the observer, so their logins are reported. Only their per-request outcomes are missing.
- severity: low
- correction: Missing login metrics are limited to bootstrap and background sessions.

### A-13 ADJUSTED
- checked: `crates/kcc-rci/src/outbound.rs:80-123`, `engine.rs:80-95, 252-261`, `kcc-app/src/registry.rs:385-396`, `kcc-migrate/src/inventory.rs:50-65`, `source.rs:125-140, 195-212`, `kcc-testkit/src/capture.rs:155-175`, overlay rule (a); grep for production callers
- reasoning:
  - `Default` is permissive, and README's "empty by default" refers to `kcc.toml`, which the registry respects by overriding all three fields.
  - `InventoryClient::connect`, `SourceConfig::from_live`/`load_source` and `RciClient::connect` have no production caller; only tests and the testkit capture tool use them.
  - So no production frontend reaches the permissive policy. It is a latent public-API trap against rule (a).
- severity: low
- correction: Remove the "production code paths" claim.

### A-14 CONFIRMED
- checked: `crates/kcc-rci/src/ndw4_reply.rs:95-130`, `auth_options.rs:40-50`, `ndw4_keys.rs:18`, `docs/BACKLOG.md:62`
- reasoning:
  - `iter` is accepted in `1..=64` and only memory is compared with `cap`, so a responding host can demand 64 passes over 256 MiB.
  - BACKLOG:62 covers the single permit but not the missing iteration cap, so this part is new.
- severity: low

### A-15 ADJUSTED
- checked: `crates/kcc-rci/src/auth_token.rs:15-38`, `auth_digest.rs:87,105`, `auth_ndw4.rs:166,189`, `session.rs:800-807`, `observe.rs:39-51`
- reasoning:
  - The mapping is inconsistent as described. However, `RequestOutcome::of` maps both `Transport` and `Timeout` to `Transport`, so the metric label does not change.
  - Only the error the user sees, Transport instead of Timeout, is wrong.
- severity: low
- correction: Drop the `RequestOutcome` mislabelling claim.

### A-16 CONFIRMED
- checked: `crates/kcc-rci/src/auth_options.rs:47`, `session.rs:111-118, 315, 736-743`, `ndw4_reply.rs:117`, `engine.rs:31, 87`, `capabilities.rs:39, 560`, `budget.rs:19`, `auth.rs:270-276`, `auth_digest.rs:239-250`, `kcc-config/src/quoting.rs:7`, `kcc-catalog/src/runtime.rs:191`, `validate.rs:273, 304`, `request.rs:237, 256`, `lib.rs:487`, `secret_value.rs:30, 285`
- reasoning:
  - All the duplicates exist, and `detect` ignores the configured `response_bytes`.
  - The `secret_value.rs` lines are actually 30 and 285. The file has 296 lines, so the cited `:545` cannot exist.
- severity: low

### A-17 ADJUSTED
- checked: `crates/kcc-rci/src/engine.rs:72-73`, `session.rs:187-223`, `kcc-catalog/src/validate.rs:159-169`, `kcc-config/src/config_text.rs:380-391`, `kcc-catalog/src/request.rs:168-171`; grep for callers
- reasoning:
  - Every item is as described. `Manager::connect*` is used only by tests in several crates.
  - The trap is overstated: `TlsMode::Verify` against a pinned self-signed router fails closed. A future caller would get a connection error, not lose security.
- severity: low
- correction: Losing the TLS pin means a refused connection, not a weakened one.

### A-18 CONFIRMED
- checked: `crates/kcc-rci/src/engine.rs:234-243, 252-270`, `session.rs:340-369, 444-455`, `outbound.rs:178-190`
- reasoning:
  - `is_bootstrap` says "cancel-safe" but calls `ensure_session`, which is marked "NOT cancel-safe".
  - `get` says "cancel-safe" for the same reason that `ensure_session` gives for being NOT cancel-safe (an interrupted re-authentication is recovered by the next call).
  - The DNS-only builders are marked NOT cancel-safe while saying nothing partial happens.
- severity: low

### A-19 ADJUSTED
- checked: `crates/kcc-rci/src/version.rs:53-75, 160-177`, `RUST_GUIDELINES.md:663-700`
- reasoning:
  - It is a mix of manual and derived impls, but the manual `Ord` compares every field in declaration order, so it equals `derive(Ord)` and agrees with the derived `Eq`.
  - The rule's hazard is an inconsistency, and none exists today.
- severity: info

### A-20 ADJUSTED
- checked: `crates/kcc-catalog/src/runtime/data.rs:194-215` (the file has 254 lines; the cited 267-277 do not exist), `xtask/src/catalog_build.rs:860-925`, type counts in `catalog/*/*.json`
- reasoning:
  - The `_ => ArgumentKind::String` fallback exists and catches `String` and `Filename`.
  - The cited rule is about wildcard arms over enums; this is a string match, where a catch-all is unavoidable.
  - The generator emits a closed `ValueType` set, so drift needs a code change in xtask. It is still a real cross-workspace drift risk.
- severity: low
- correction: The lines are `data.rs:198-207`. Return an error for unknown strings instead of citing the enum rule.

### A-21 ADJUSTED
- checked: `crates/kcc-config/tests/config_text.rs:19-73`, `kcc-config/src/ns3.rs:178-180`, `kcc-rci/tests/config_accessor.rs:1-85`, `kcc-i18n/src/locale.rs:141-144`, `kcc-catalog/src/tests.rs:289-330`, `kcc-rci/tests/engine.rs:131-157`
- reasoning:
  - `print(parse(x)) == normalize(x)` is a tautology, and the ns3 length test duplicates `rejects_invalid_length`. The idempotence assertion next to it is not a tautology.
  - The i18n pin is at `:141-144`, `COOKIE_NAME == "kcc_lang"`. It does fail on a rename and guards a machine-consumed cookie contract, so it is not "cannot fail".
  - The catalog background test adds catalog validation of the start, poll and stop methods, so it only partly duplicates the RCI test.
  - The source-grep test describes itself as a backup guard behind a type-level one.
- severity: low
- correction: Only one test cannot fail (the tautology). Keep the cookie-name pin.

### A-22 CONFIRMED
- checked: `crates/kcc-rci/tests/auth_survivors.rs:1-2, 72, 98, 126`, `tests/auth_parser.rs:18, 55`, `kcc-catalog/src/request.rs:168-170`
- reasoning: The mutation-run wording and the `A1`-`A7` labels are present exactly as cited.
- severity: info

## Summary
- CONFIRMED: 9 (A-01, A-02, A-03, A-11, A-14, A-16, A-18, A-22, A-04's core claim excluded since it is adjusted)
- ADJUSTED: 13 (A-04, A-05, A-06, A-07, A-08, A-09, A-10, A-12, A-13, A-15, A-17, A-19, A-20, A-21)
- REFUTED: 0
- DUPLICATE: 0

Correction to the counts above: the confirmed list is A-01, A-02, A-03, A-11, A-14, A-16, A-18, A-22, which is 8, plus none further. The adjusted list has 14 entries. Final tally: **8 CONFIRMED, 14 ADJUSTED, 0 REFUTED, 0 DUPLICATE**.

Final severities: medium for A-01, A-02, A-03 and A-04; low for 16 findings; info for A-19 and A-22.

- NEW (low, needs separate validation): `crates/kcc-rci/src/session.rs:771-772`. `parse_set_cookie` calls `raw.to_str()` and returns `Err(Transport)` before it checks the cookie name. Any unrelated `Set-Cookie` header with a byte that is not visible ASCII therefore makes `refresh_session` fail every response, including POSTs the router has already applied (`request` at `:428`).