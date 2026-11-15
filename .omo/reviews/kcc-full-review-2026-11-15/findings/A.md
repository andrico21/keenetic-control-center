No critical or high findings are confirmed in lane A. There are 22 findings: 9 medium, 12 low and 1 info. One medium (A-02) would become high if a real router sends a new cookie with its 401 replies; that is not verified. The worst confirmed problem is `kcc_config::secrets::redact`: it misses most ns3-encoded secrets the router actually writes. Every consumer I checked hides this by adding its own "mask every ns3 token" pass.

### A-01 `secrets::redact` misses router-written ns3 secrets and blanks the wrong word for `crypto ike key`
- severity: medium
- kind: security
- rule: project rule (d); RUST_GUIDELINES.md §13 "Testing quality" (the unit test checks shapes the router never writes)
- evidence: `crates/kcc-config/src/secrets.rs:65-93,101-107,110-130`
  ```rust
  ["authentication", "wpa-psk" | "password", rest @ ..] | ... => secret_after_kind(argument_index(offset, command, rest), rest)
  ["ipsec", "preshared-key", rest @ ..] | ["crypto", "ike", "key", rest @ ..]
  | ["wireguard", "peer", _, "preshared-key", rest @ ..] | ... => Some(argument_index(offset, command, rest)),
  ...
  Token::Ns3(blob) => { if expanded_index.saturating_add(1) == target { ... } expanded_index += 2 }
  ```
  The router writes `crypto ike key office ns3 <blob> any`, `ipsec preshared-key ns3`, and `xauth-password ns3` / `preshared-key ns3` under `crypto ipsec profile` (`crates/kcc-domain/tests/vpn_credentials.rs:81-87`, `crates/kcc-testkit/src/cli_engine/secrets.rs:36-44`).
- impact:
  - In the second arm group the computed index lands on the literal `ns3` word. `replace_expanded_word` only matches the payload slot, so the ns3 blob stays readable.
  - `crypto ike key office ns3 B any` gets index 3, so the key name `office` is replaced and the PSK blob is left.
  - `crypto ipsec profile … preshared-key|xauth-password` is not in the registry at all.
  - ns3 can be reversed with the public algorithm in `ns3::decode`.
  - Today nothing leaks only because consumers each re-mask every ns3 token. Copies are at `kcc/src/cli/redact.rs:54-63`, `kcc-mcp/src/config_tools/backups.rs:157-168`, `kcc-web/src/config_page/text.rs:64-74`, `kcc-web/src/advanced/preview.rs:258-266`, `kcc-migrate/src/presets/model.rs:198-205` and `kcc-testkit/src/anonymize.rs:298`. A new caller that trusts the function's doc ("every registered command secret replaced") would leak.
  - A plaintext PSK under `crypto ipsec profile` in an uploaded or preset file is redacted by no one (INFERRED that such text reaches a viewer).
  - The unit test (`secrets.rs:146-165`) uses `crypto ike key theta` and `ipsec preshared-key epsilon` without `ns3`, so it cannot catch this.
- fix: Run every arm through `secret_after_kind`. Index `crypto ike key` past the name. Add `crypto ipsec profile _ preshared-key|xauth-password`. Mask all `Token::Ns3` payloads inside `redact` itself and delete the six consumer copies. Rebuild the test fixture from the `ns3` lines the testkit actually stores.
- confidence: high on the code paths; medium on whether plaintext secrets reach a lower-trust viewer (INFERRED).

### A-02 Cookie refresh writes any `Set-Cookie` into the current session, including on 401 and from requests sent with an older cookie
- severity: medium (high if the router sends a new cookie with its 401)
- kind: bug
- rule: none (session state machine)
- evidence: `crates/kcc-rci/src/session.rs:425-433, 698-703, 644-651`
  ```rust
  let first = self.send_with_session(method.clone(), path, body, &first_session).await?;
  self.refresh_session(first.headers())?;
  if first.status() != StatusCode::UNAUTHORIZED || !kind.retry_on_unauthorized() { return Ok(first); }
  self.reauthenticate_after(&first_session).await?;
  ...
  if let Some(session) = lock(&self.session).as_mut() { session.refresh_from_headers(headers)?; }
  ...
  if self.usable_session().is_some_and(|current| !current.same_cookie(failed)) { return Ok(()); }
  ```
- impact:
  1. If a 401 carries `Set-Cookie: <name>=<new pending id>`, as the router's `/auth` challenge does, that unauthenticated cookie is installed. `reauthenticate_after` then sees a "different" cookie and skips login. The replay gets 401 and the caller sees `Http{401}`. Every later request repeats this until the local `Max-Age` (300 s) expires.
  2. Request R1 is sent with cookie A. Meanwhile R2 re-authenticates to cookie B. R1's sliding-refresh `Set-Cookie: A` then overwrites B with the dead A, which forces another login.
  3. A malformed matching cookie on a successful POST returns `Err(Auth)` even though the router already applied the change.
- fix: Refresh only on non-401 responses, and only while the current cookie `same_cookie(&snapshot)`. Never turn a refresh-parse failure into an error on a response that was already applied.
- confidence: high on the code (INFERRED: whether real routers send Set-Cookie on 401 or on ordinary responses is not verified; the fake router does not).

### A-03 `RciClient::show` drops the query on the POST fallback and caches the path as POST-only
- severity: medium
- kind: bug
- rule: none
- evidence: `crates/kcc-rci/src/engine.rs:399-412`
  ```rust
  if lock(&self.post_only_show).contains(&key) {
      return self.post(path, &json!({})).await;
  }
  match self.get(path, query).await {
      Err(RciError::NotFound) => {
          let result = self.post(path, &json!({})).await;
          if result.is_ok() { let _: bool = lock(&self.post_only_show).insert(key); }
  ```
- impact: Callers pass queries: `kcc-app/src/poller.rs:444` uses `show(&show/interface/stat, &[("name", id)])`, and `kcc-mcp/src/generic/rci.rs:204` uses the agent's `input.value`. If GET answers 404 once, the POST is sent with `{}` and no `name`, so the unfiltered answer is returned as if it were the filtered one. The path is then cached POST-only for the client's lifetime, so every later query on it is ignored too. The poller would store the same unfiltered stats for every WAN id.
- fix: POST the serialized query as the body: build the POST body from `query` (`serde_json::to_value(query)`) instead of `{}`, or refuse the fallback when the query is not empty.
- confidence: high on the code (INFERRED: which router resources answer 404 to GET).

### A-04 `batch` never checks the reply length and drops completed chunks on a later error
- severity: medium
- kind: bug
- rule: none
- evidence: `crates/kcc-rci/src/engine.rs:429-449`
  ```rust
  for chunk in chunks {
      let body = Value::Array(chunk);
      ...
      let response = self.session.post("/rci/", &body).await?;
      let Value::Array(values) = response_json(response, self.options.response_bytes).await? else { return Err(RciError::Decode); };
      for value in values {
          let item = RciResponse::from_value(value);
          let failed = item.is_err(); results.push(item);
          if failed && self.options.stop_on_error { return Ok(results); }
  ```
  The consumer at `crates/kcc-app/src/workflow_batch.rs:52-70` zips `items` with `responses` and computes `failed = responses.len() - succeeded`.
- impact:
  - If the router returns fewer elements than the chunk had, the missing items count as neither succeeded nor failed, and the change is reported as fully applied.
  - Extra elements shift which item each result belongs to, across chunks.
  - A transport error on chunk 2 returns `Err` for the whole call, so the caller cannot tell that chunk 1 was already applied.
  - `stop_on_error` cuts off the results of items the router already ran in the same POST.
- fix: Return `Decode` (or a typed partial error that carries the results so far) when `values.len() != chunk.len()`. On a mid-batch failure, return the completed results together with the error.
- confidence: high

### A-05 Status items that do not fully deserialize are dropped, so error-level replies count as success
- severity: medium
- kind: bug
- rule: RUST_GUIDELINES.md §10 "Validate and sanitize all external input at system boundaries"
- evidence: `crates/kcc-rci/src/lib.rs:416-427, 460-465`
  ```rust
  pub struct StatusItem { pub status: Level, pub code: String, pub ident: String, pub message: String }
  ...
  found.extend(statuses.iter().filter_map(|status| {
      serde_json::from_value::<StatusItem>(status.clone()).ok().map(|item| (pointer.clone(), item))
  }));
  ```
- impact: An item like `{"status":"error","code":7405600,...}` (numeric code), or one missing `message`, or carrying an unknown level, fails to deserialize and is skipped. `RciResponse::from_value` then returns `Ok`. A rejected raw or batch write is reported as applied (`workflow_batch::completion` counts it as succeeded). Curated writes are read back; raw writes are not.
- fix: Decide the level from the `status` member alone. Make `code`, `ident` and `message` lenient (string or number, optional). Treat any unrecognized level as an error.
- confidence: medium (INFERRED: field types across firmware 4.3-5.2)

### A-06 Tab-indented config text quietly flattens nested commands to the top level
- severity: medium
- kind: bug
- rule: RUST_GUIDELINES.md §10 "Validate … external input at system boundaries"
- evidence: `crates/kcc-config/src/config_text.rs:145-163`
  ```rust
  let line = raw_line.trim_end_matches('\r');
  let trimmed = line.trim_start_matches(' ');
  ...
  let spaces = line.len().saturating_sub(trimmed.len());
  ...
  commands.push(RawCommand { spaces, line_no, tokens: tokenize(trimmed, line_no)? });
  ```
- impact: `interface Bridge0\n\tip address 192.168.1.1 255.255.255.0` produces two top-level nodes. `flatten` then emits a bare `interface Bridge0` and a root-level `ip address …` instead of a `ParseError`. A tab-indented migration source or preset (uploaded or hand-edited) is restructured without any warning. Whether the result hits a valid root command depends on the catalog (INFERRED).
- fix: Return `InvalidIndent` (or a new variant) when the leading whitespace contains anything other than `' '`.
- confidence: high

### A-07 Every background operation logs in afresh and never logs out
- severity: medium
- kind: bug
- rule: RUST_GUIDELINES.md §5 "Audit Drop impls of async resources"
- evidence: `crates/kcc-rci/src/engine/background.rs:27, 95, 133-141`; `crates/kcc-rci/src/session.rs:502` (`logout` has no production caller)
  ```rust
  let session = Arc::new(session(&client.router, &client.credentials, &client.options).await?);
  ...
  let path = format!("/rci/{}?id={}", self.path, self.process_id);
  ...
  () = token.cancelled() => Err(RciError::Timeout),
  ```
- impact:
  - Each `start()` (every diagnostic and every continued log read in `kcc-domain/src/diagnostics.rs:174,209`) does its own DNS lookup and builds a new HTTP client.
  - It also starts a new `Manager` with an empty ndw4 key cache. On ndw4 routers that means a full Argon2id derivation under the global single permit, stalling logins to every other router.
  - The router session is never released (INFERRED: router session-table pressure).
  - User cancellation is reported as `Timeout`.
  - The process id from the router is put into the URL without encoding.
- fix: Reuse the parent's key cache (or `Arc<Cache>`). Call `logout` when the Handle finishes or is dropped (from a spawned task). Use `encode_query(&[("id", &process_id)])`. Add a distinct cancellation error.
- confidence: high on the code; medium on the router-side impact.

### A-08 DELETE risk is not enforced by the catalog; three frontends patch it themselves
- severity: medium
- kind: guideline
- rule: RUST_GUIDELINES.md §3 "Use the newtype pattern / validated constructors" (the invariant should live in the type); BRIEF anti-pattern "copy-paste duplication that drifts"
- evidence: `crates/kcc-catalog/src/request.rs:48-59` (risk computed without `method`), `crates/kcc-catalog/src/runtime.rs:457-468` (DELETE raised to Destructive only for path `interface`), `crates/kcc-catalog/src/request.rs:189-193`
  ```rust
  } else if key == "no" { own_leaf = true; if child == &Value::Bool(true) { self.risk = Some(Risk::Destructive); }
  ```
  The patches: `kcc-mcp/src/generic/rci.rs:270-274` (`preliminary.max(Risk::Destructive)`), `kcc/src/cli/rci.rs:72`, `kcc-web/src/advanced/rci_check.rs:192-204`.
- impact: `validate("ip hotspot host", Delete, {"mac":…})` comes back as `Write`, while the same removal written as `{"no":true}` is `Destructive`. Every caller has to remember `.max(Destructive)`; one that forgets lets a Write-only role delete.
- fix: In `ValidatedRequest::capture`, raise the risk to `Destructive` when `method == Delete`, then drop the three frontend patches.
- confidence: high

### A-09 Digest proxy state is not safe under concurrent requests
- severity: medium
- kind: bug
- rule: none
- evidence: `crates/kcc-rci/src/auth_digest.rs:79-104`
  ```rust
  let mut state = self.0.lock().await;
  if let Some(challenge) = state.as_mut() { first = first.header(AUTHORIZATION, challenge.authorization(...)?); }
  ...
  let mut challenge = Challenge::parse(&text)?;
  let authorization = challenge.authorization(credentials, method, &uri)?;
  *self.0.lock().await = Some(challenge);
  ```
- impact: Two requests that get 401 each build a fresh `Challenge` with `count = 0`, and the last one overwrites shared state that another task may have advanced. If the proxy reuses the nonce, `nc` values repeat. The replay then gets 401, which maps straight to `Err(Auth(Rejected))`: concurrent requests through KeenDNS fail spuriously with "authentication failed". It also uses `|_| RciError::Transport`, so timeouts are lost (see A-15).
- fix: Under the lock, reuse the stored challenge when the nonce is the same; otherwise replace it. Do not reset the count for an identical nonce.
- confidence: medium (INFERRED: proxy nonce policy)

### A-10 Secret bytes are copied into buffers that are never zeroized
- severity: low
- kind: security
- rule: project rule (d)
- evidence: `crates/kcc-rci/src/engine.rs:698-710` (`read_capped` grows a plain `Vec`, and every reallocation leaves the startup config with its ns3 secrets on the heap) used at `:530`; `:561` `multipart::Part::bytes(bytes.expose_secret().to_vec())`; `crates/kcc-rci/src/session.rs:622` `.body(body.to_string())` makes the `Zeroizing` wrapper meaningless; `crates/kcc-config/src/ns3.rs:43-69` (`padded` and `bytes` hold the plaintext and are dropped unzeroized, including on the `InvalidUtf8` error path); `crates/kcc-catalog/src/runtime.rs:219` → `:324` `value.clone()` copies the plaintext JSON before `SecretValue` takes ownership.
- impact: Plaintext router configs, PSKs and passwords stay in freed heap memory; anyone who can read process memory or a core dump recovers them.
- fix: Read into `Zeroizing<Vec<u8>>` with a capacity reserved up front. Pass `Bytes` built from the secret without an extra copy. Zeroize ns3 buffers on every path. Move the value into `capture` instead of cloning it.
- confidence: high

### A-11 Unbounded edit-distance work on attacker-controlled field names
- severity: low
- kind: security
- rule: RUST_GUIDELINES.md §10 (DoS bounds)
- evidence: `crates/kcc-catalog/src/validate.rs:368-377, 380-384`
  ```rust
  siblings.iter().filter_map(|candidate| { let distance = damerau_levenshtein(field, candidate); ... })
  ...
  let mut matrix = vec![0; left_chars.len().saturating_add(1).saturating_mul(columns)];
  ```
- impact: An MCP or Web request whose root object has a 1 MB unknown key computes a ~1M×(len+1) matrix for each of about 100 root siblings. That is seconds of synchronous CPU on a Tokio worker per request (bounded only by the frontend body limit, INFERRED).
- fix: Skip the suggestion when `field.len()` exceeds the longest sibling plus 2, which already guarantees a distance above 2.
- confidence: medium

### A-12 `connect_bootstrap_with` loses the observer, and request accounting differs per method
- severity: low
- kind: bug
- rule: none
- evidence: `crates/kcc-rci/src/engine.rs:189-194` replaces the session built at `:278-280` (`.with_observer(...)`) with one that has no observer; `:597-599` reports only in `send`. `batch`, `download_config`, `upload_startup_config`, `detect` and background polling never report. `is_bootstrap` (`:241`) runs a login without taking a semaphore permit.
- impact: Self-metrics under-count logins and requests (bootstrap logins, batches, config downloads are invisible), and bootstrap logins bypass the per-router concurrency budget.
- fix: Chain `.with_observer(client.options.observer.clone())` in bootstrap and background sessions. Route all request paths through one helper that takes the permit and reports.
- confidence: high

### A-13 `OutboundPolicy::default()` is permissive, contrary to the documented "empty by default"
- severity: low
- kind: security
- rule: project rule (a)
- evidence: `crates/kcc-rci/src/outbound.rs:96-123` (10/8, 172.16/12, 192.168/16, 100.64/10, fd00::/8 and 8 cloud suffixes); `RciClient::connect` (`engine.rs:259-261`) uses `RciClientOptions::default()`. Production code paths (out of my lane) use `OutboundPolicy::default().with_loopback(true)`: `kcc-migrate/src/source.rs:130-131` and `inventory.rs:58-59`.
- impact: Any caller that does not override all three fields (the registry does, at `kcc-app/src/registry.rs:392-395`) contacts LAN, CGNAT, loopback and cloud-suffix hosts that the operator never allowed.
- fix: Make `Default` deny-all. Keep the current lists as an explicit named constructor for tests.
- confidence: high

### A-14 Router-controlled Argon2 iterations are not capped locally
- severity: low
- kind: security
- rule: RUST_GUIDELINES.md §10 (DoS bounds); KNOWN-BACKLOG (single global permit)
- evidence: `crates/kcc-rci/src/ndw4_reply.rs:110-120` (`iter` accepted in `1..=64`; only memory is compared with `cap`); `crates/kcc-rci/src/ndw4_keys.rs:18` (global `Semaphore::new(1)`)
- impact: Before mutual authentication, any LAN host answering as a router can demand 64 passes over 256 MiB per login. With the single global permit, that stalls ndw4 logins to every router. A-07 multiplies the effect.
- fix: Add a local `max_argon2_iterations` (or a combined memory×iterations budget) to `Options` and refuse with `CostTooHigh`.
- confidence: medium

### A-15 Timeout errors are mapped differently on each auth path
- severity: low
- kind: bug
- rule: RUST_GUIDELINES.md §2 "Propagate errors with `?`" (keep the error type intact)
- evidence: `crates/kcc-rci/src/auth_token.rs:24`, `auth_digest.rs:87,105`, `auth_ndw4.rs:166,189` use `.map_err(|_error| RciError::Transport)`, while `session.rs:801-807` `map_reqwest_error` keeps `Timeout`.
- impact: Under token, digest or ndw4 auth, a read timeout is reported and labelled (`RequestOutcome::Transport`) as a transport failure, so the user sees the wrong error.
- fix: Use `map_reqwest_error` everywhere (make it `pub(crate)`).
- confidence: high

### A-16 Duplicated magic numbers and helpers
- severity: low
- kind: duplication
- rule: BRIEF §4 "magic numbers repeated across files"
- evidence:
  - `0x0004_0000` at `auth_options.rs:47`, `session.rs:315`, `ndw4_reply.rs:117`.
  - `8 * 1024 * 1024` at `engine.rs:31` and `capabilities.rs:39`; `detect` ignores the client's configured `response_bytes`.
  - Secret limit 256 at `kcc-config/src/quoting.rs:7`, `kcc-catalog/src/runtime.rs:191`, `validate.rs:273,304,312`.
  - Concurrency `2` at `engine.rs:87` and `budget.rs:19`.
  - Identical `header_value` at `session.rs:111-118` and `:736-743`.
  - Hex encoders at `auth.rs:270-276` and `auth_digest.rs:244-249`.
  - JSON-pointer escaping `replace('~',"~0").replace('/',"~1")` at `lib.rs:487`, `request.rs:237,256`, `secret_value.rs:290,545`.
- impact: Changing any of these limits requires editing every copy, and a missed copy leaves the code paths enforcing different values (e.g. a raised response cap that `detect` keeps refusing).
- fix: One shared constant or helper per item, exported from the owning crate.
- confidence: high

### A-17 Dead or speculative API shipped in production
- severity: low
- kind: dead-code
- rule: BRIEF §4 "dead or test-only code shipped", "defensive checks inside trusted code"
- evidence:
  - `RciClientOptions::stop_on_error` (`engine.rs:72-73`) has no caller in the workspace, and its semantics are misleading (A-04).
  - `Manager::connect` and `connect_with_options` (`session.rs:194-223`) are used only by tests and hardcode `TlsMode::Verify` and default timeouts.
  - `validate_value(…, _command: &Command, …)` (`kcc-catalog/src/validate.rs:160-169`) is a pass-through with an unused parameter.
  - `write_node`'s unreachable `let Ok(()) = … else { return; }` would silently drop children (`config_text.rs:384-386`).
  - The "defensive checks guard future callers" block in `request.rs:168-171`.
- impact: Maintenance surface, plus traps: a future caller of `Manager::connect` loses its TLS pin.
- fix: Delete them, or move them to `#[cfg(test)]` or testkit.
- confidence: high

### A-18 Cancel-safety comments contradict each other
- severity: low
- kind: guideline
- rule: RUST_GUIDELINES.md §5 "Annotate every async fn with cancel safety"
- evidence:
  - `engine.rs:238-240` `is_bootstrap` says "cancel-safe" but calls `ensure_session`, which `session.rs:345-346` marks "NOT cancel-safe" for the same reason that `session.rs:449-450` (`get`) calls "cancel-safe".
  - `engine.rs:257,268` and `outbound.rs:183-184` say "NOT cancel-safe" while stating that nothing partial happens.
- impact: The annotations carry no reliable information; someone putting `is_bootstrap` or `detect` inside a `select!` cannot trust them.
- fix: Use one rule: a cancelled login that leaves only a remote session is or is not cancel-safe, chosen once. Correct the callers to match the callees.
- confidence: high

### A-19 `FirmwareVersion` mixes derived equality with hand-written ordering
- severity: low
- kind: guideline
- rule: RUST_GUIDELINES.md §3 "DON'T: Mix manual and derived comparison impls" (line 663)
- evidence: `crates/kcc-rci/src/version.rs:57` `#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]` and `:161-179` manual `Ord`/`PartialOrd` over all fields, in declaration order.
- impact: The two agree today, but the rule exists so that adding a field (e.g. a build suffix) cannot make them disagree without the compiler noticing. Here the manual impl is identical to `derive(Ord)` anyway.
- fix: `#[derive(PartialOrd, Ord)]` and delete the manual impls.
- confidence: high

### A-20 Generated argument types fall back to an unconstrained `String`
- severity: low
- kind: guideline
- rule: RUST_GUIDELINES.md §3 "Use exhaustive match – avoid wildcard catch-all"
- evidence: `crates/kcc-catalog/src/runtime/data.rs:267-277` `_ => ArgumentKind::String` (today it catches `String` and `Filename`).
- impact: A new or renamed generator type (e.g. `Password2`, `Ipv6Mask`) silently loses validation and secret protection instead of failing to load.
- fix: Map `"String" | "Filename"` explicitly and return `InvalidGeneratedCatalog` for unknown types.
- confidence: high

### A-21 Tests that cannot fail, duplicated scenarios, and source-grep tests
- severity: low
- kind: test-quality
- rule: RUST_GUIDELINES.md §13; BRIEF §5
- evidence:
  - `crates/kcc-config/tests/config_text.rs:25-29` asserts `print(parse(x)) == normalize(x)`, which is the definition of `normalize`.
  - `:70-73` duplicates `ns3.rs` `rejects_invalid_length`.
  - `crates/kcc-rci/tests/config_accessor.rs:17-22,63-79` greps every crate's source for spellings.
  - `crates/kcc-i18n/src/locale.rs:156-159` asserts that a constant equals its literal.
  - `crates/kcc-catalog/src/tests.rs` `background_command_runs_and_cancels_through_validated_engine` repeats `kcc-rci/tests/engine.rs:131-157`.
  - `secrets.rs:146-165` (see A-01).
- impact: Green tests that pin nothing (two cannot fail at all), plus a source-grep check that `.pointer(&format!(..))` evades.
- fix: Delete the tautology, the duplicate and the const pin. Replace the grep with a type-level guard (already present per its own header).
- confidence: high

### A-22 Review-process labels left in code and tests
- severity: info
- kind: anti-pattern
- rule: BRIEF §4 "review-process labels in code"
- evidence: `crates/kcc-rci/tests/auth_survivors.rs:1-2` ("first left unprotected by the mutation run"), `:72,98,126` ("A1:", "A2:", "A3/A4:"); `tests/auth_parser.rs:18,55` ("A5/A6", "A7"); `crates/kcc-catalog/src/request.rs:168-170` ("mutations of the proof … are equivalent").
- impact: The comments describe a past review process rather than the code.
- fix: Rewrite each as a statement of the behaviour it pins.
- confidence: high

## Coverage
- **Read in full:**
  - kcc-rci: all of `src/` (`lib.rs`, `engine.rs`, `engine/background.rs`, `session.rs`, `session/transport.rs`, `auth.rs`, `auth_options.rs`, `auth_token.rs`, `auth_digest.rs`, `auth_ndw4.rs`, `ndw4_keys.rs`, `ndw4_reply.rs`, `budget.rs`, `outbound.rs`, `capabilities.rs`, `version.rs`, `catalog_path.rs`, `configuration_answer.rs`, `observe.rs`).
  - kcc-rci tests: `engine.rs`, `session.rs`, `bootstrap.rs`, `auth_parser.rs`, `config_accessor.rs`, `auth_token.rs`, `auth_digest.rs`, `auth_survivors.rs`, `auth_ndw4.rs`, `outbound.rs`, `capabilities.rs`, `capabilities/transport.rs`.
  - kcc-config: all of `src/` (`lib.rs`, `config_text.rs`, `quoting.rs`, `secrets.rs`, `ns3.rs`) and `tests/config_text.rs`.
  - kcc-catalog: `lib.rs`, `catalog_types.rs`, `runtime.rs`, `runtime/{schema,query,data}.rs`, `request.rs`, `secret_value.rs`, `validate.rs`, `cli.rs`, `cli_grammar.rs`, `search.rs`, `tests.rs`, and the first 122 lines of `risk_tests.rs`.
  - kcc-i18n: `lib.rs`, `locale.rs`, `bundle.rs`, `format.rs`, `tests/plurals.rs`.
- **Skimmed:**
  - `kcc-rci/tests/support/*.rs` (sleep and abort patterns only).
  - `kcc-catalog/src/generated.rs` (how it is consumed) and `kcc-i18n/src/keys.rs` (only `MessageKey::new` constants and `ALL`).
  - `kcc-catalog/src/secret_tests.rs` (first 60 lines).
  - Grep only across the remaining catalog test files.
  - Out-of-lane call sites, read only to confirm consequences: `kcc-app/src/{poller.rs,workflow.rs,workflow_batch.rs,registry.rs}`, `kcc-mcp/src/generic/rci.rs`, `kcc-web/src/advanced/preview.rs`, `kcc-testkit/src/{server.rs,cli_engine/secrets.rs,auth_fixture.rs,anonymize.rs}`, `kcc-domain/tests/vpn_credentials.rs`, the redaction consumers, and catalog JSON.
- **Not read:** `kcc-catalog/src/{cli_leaf_tests.rs, cli_tests.rs, persists_tests.rs, persists_tests/shapes.rs, risk_tests/*.rs, typing_tests.rs, untyped_arguments_tests.rs, validate_boundary_tests.rs, runtime/rule_tests.rs}` in full; the crates' `Cargo.toml` files.

## Clean
- RCI path, object-name, MAC, IPv4-net and router-URL validated constructors: strict grammar, no panics on arbitrary input.
- Status collection walks the tree with an explicit stack (no recursion depth risk) and produces correct RFC 6901 pointers.
- `RciError` Display and Debug carry no router message; `Credentials`, `Session`, `Options`, `Ndw2Challenge`, `SpkiVerifier` and `Keys` all redact their Debug output.
- Single-flight login: the `login` Tokio mutex plus `same_cookie`. The concurrent-expiry test (50 requests, 1 login) is sound.
- ndw4: endpoint guard, nonce-prefix check, salt and cost bounds, constant-time server-signature check before phase 3, no downgrade to ndw2, Argon2 work done in `spawn_blocking`.
- Outbound policy: DNS resolved once and pinned via `resolve_to_addrs`, metadata and IPv6 transition forms refused, embedded IPv4 checked, suffix matching on label boundaries, SPKI pinning with real handshake signature checks, redirects disabled.
- Response size cap enforced while streaming (`read_capped`).
- Batch splitting under 900 KiB, with oversized single items refused.
- Catalog: version and model selection, raw escape requires both RawRci and admin ManageRouters, CLI grammar expansion bounded at 4096 forms, CLI metacharacters refused, `SecretValue` and `WireValue` wipe on drop, password-type arguments protected.
- `quote_cli_word` and `quote_cli_text` round-trip through the real tokenizer and refuse control characters.
- ns3 encode and decode match the published test vectors; decoding cannot panic on any length.
- i18n: fallback goes locale → English → bare id, isolation marks are off, load errors are typed and surfaced via `init()`, Accept-Language q-value parsing is strict, digit grouping follows each locale's rules.