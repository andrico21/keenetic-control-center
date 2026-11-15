I've reviewed all the lane D source files in full and the in-scope tests, and the report follows in the BRIEF format. The most serious finding is D-01: clearing a firewall rule's description or schedule actually sends `no access-list L rule N disable`, which re-enables the rule if it was disabled. Nothing was edited, no `cargo` was run, and no network host was contacted.

### D-01 Clearing a firewall rule's description or schedule sends "enable rule"
- severity: high
- kind: bug
- rule: project rule (c) "every curated write is read back"; RUST_GUIDELINES.md §3 "Use exhaustive `match`" (547)
- evidence: `crates/kcc-domain/src/firewall/change.rs:96-98`
  ```rust
  RuleProperty::Description(None) | RuleProperty::Schedule(None) => {
      json!({"index":index,"no":true})
  }
  ```
  `crates/kcc-domain/src/firewall/change/render.rs:133-141`
  ```rust
  if let Some(value) = request.value.get("description").and_then(Value::as_str) {
      words.extend(["description".to_owned(), cli_token::quoted_text(value)?]);
  } else if let Some(value) = request.value.get("schedule").and_then(Value::as_str) {
  ...
  } else {
      words.push("disable".to_owned());
  }
  ```
  `render.rs:77-78` then adds the `no ` prefix. The Web reaches this path when the dialog is empty: `crates/kcc-web/src/firewall_page/rule_props.rs:97-98` and `:178-179`, with `checks.rs:47-48` returning `Ok(None)`.
- impact: An operator clears the description (or picks "no schedule") on a disabled rule, for example a disabled permit rule. kcc sends `no access-list L rule N disable`, so the rule becomes active and the description stays. The Web `Expect::Property` read-back then fails, but the router has already changed: a firewall rule was turned on without anyone asking. No test covers `Description(None)` or `Schedule(None)`.
- fix: Render the property from the `RuleProperty` variant, not from which JSON fields happen to be present. Clearing should render `no access-list L rule N description` or `no access-list L rule N schedule`. Add a test that clears the description on a disabled rule and checks the rule is still disabled.
- confidence: high

### D-02 Names and free text go into CLI lines unquoted and unvalidated
- severity: medium
- kind: security
- rule: project rule (b) "raw input validated against the catalog and the identifier validators"; RUST_GUIDELINES.md §10 "Validate and sanitize all external input at system boundaries" (2732)
- evidence: `crates/kcc-domain/src/dns/change.rs:290-315` (`line_2` and `contextual_line` print descriptions and names as is), and `:29-34`, which inserts `name` into `validated.value` after validation.
  `crates/kcc-domain/src/vpn_clients/render.rs:126-133`
  ```rust
  fn context(path: &'static str, name: &str, body: Value, leaf: String) -> ... {
      (path, body, format!("interface {name} {leaf}"))
  }
  ```
  In that file the interface `name` and the peer `public_key` are never in the validated body. `vpn_servers/render.rs:56-92` puts crypto-map `name` only in the line. `policies/change/render.rs:46-49` prints the description unquoted. `firewall/change/render.rs:45-61,136` prints the ACL name, the interface and the schedule unquoted.

  The catalog types these fields as `String` (`access-list` name, `object-group fqdn` name and description, `interface wireguard peer` key, `interface proxy upstream` host). `crates/kcc-catalog/src/validate.rs:301` accepts any string for that type: `ArgumentKind::String => value.is_string()`. The MCP edge only rejects control characters (`kcc-mcp/src/support/validate.rs:41`). Other domains do quote or validate: `wifi/plan.rs:149`, `wan/render.rs:78` and `interfaces.rs:294` go through `cli_token`.
- impact: An MCP client (a prompt-injected agent) sends `fqdn_group` with description `Streaming services`, or an `acl`/`name` containing spaces. kcc sends a line whose words differ from the catalog-validated body, for example `object-group fqdn G description Streaming services`. Descriptions with spaces cannot be set, and the caller controls extra CLI words inside a line kcc reports as validated.
- fix: Run every identifier through `ObjectName` or `cli_token::validate` in the planner, and put every free-text value through `cli_token::quoted_text`, as the firewall rule description already does. Validate the context names (interface, map, group) against the catalog as well.
- confidence: high on what is sent; how the router handles the extra words is INFERRED.

### D-03 Setting an FQDN group description is always refused
- severity: medium
- kind: bug
- rule: none
- evidence: `crates/kcc-domain/src/dns/change.rs:172-175`
  ```rust
  DnsChange::FqdnDescription { name, description } => (
      "object-group fqdn description",
      json!({"name":name,"description":description}),
  ),
  ```
  In catalogs 5.0 and 5.1, `object-group fqdn description` has only `{"description": String}`. `kcc-catalog/src/validate.rs:225-230` turns the extra `name` into `UnknownField`.
- impact: MCP `fqdn_group` with a description (`kcc-mcp/src/domains/write/dns.rs:152`) and the CLI (`kcc/src/cli/dom_dns.rs:172`) always fail with a validation error. No test covers it.
- fix: Validate `{"description"}` only and carry `name` outside the validated value, as `FqdnInclude` does. Add a test.
- confidence: high

### D-04 Clearing a connection-policy description always fails
- severity: medium
- kind: bug
- rule: none
- evidence: `crates/kcc-domain/src/policies/change/plan.rs:36` builds `{"no":true}` for `None`. `crates/kcc-domain/src/policies/change/render.rs:46-49`
  ```rust
  "ip policy description" => vec![
      "description".to_owned(),
      text(request, "description")?.to_owned(),
  ],
  ```
- impact: The Web policy description dialog with an empty field (`kcc-web/src/routing_page/policy_forms.rs:154`) goes through `apply::apply` → `render::request` → `expected_leaf`, which returns `InvalidResponse`. Removing a description is impossible from any surface.
- fix: When `no` is set, render `no ip policy N description` without an argument.
- confidence: high

### D-05 Ports are rendered for ICMP/ESP/GRE/IPIP/IP firewall rules, and the test matrix accepts it
- severity: medium
- kind: bug
- rule: project rule (b); RUST_GUIDELINES.md §3 "Force construction through validated constructors" (424)
- evidence: `firewall/change.rs:193-202` (`plan_rule` inserts ports for any protocol). `crates/kcc-mcp/src/domains/write/filtering.rs:214,227` (`Transport::Ip` → `RuleProtocol::Ip`, then `rule.destination_port = input.port`). The 5.1 catalog synopsis allows ports only after `(tcp | udp)`; the other branch is `permit (icmp | esp | gre | ipip | ip) <source> <source-mask> <destination> <destination-mask>`. The test `tests/firewall_render.rs:25,117-121` runs `Protocol::Icmp` and `Protocol::Ip` with `port eq 443` and `port range`, and asserts they "reach and return".
- impact: An MCP firewall call with `protocol: ip, port: 443` sends `access-list X permit ip … port eq 443`, a line outside the documented grammar. The fake router accepts it, so the matrix pins an invalid command as correct.
- fix: Refuse ports unless the protocol is TCP or UDP, either in `plan_rule` or by making `Rule` carry ports only for TCP/UDP. Drop those cells from the matrix, or assert the refusal.
- confidence: high on the code path; real-router rejection is INFERRED.

### D-06 One unparsable rule makes every CLI/MCP firewall write fail, after the write
- severity: medium
- kind: bug
- rule: project rule (c)
- evidence: `crates/kcc-domain/src/firewall/read.rs:48-51` collects `parse_list(rows)?` across all lists. `read.rs:219` has `[keyword, ..] if keyword == "port" => return Err(DomainError::InvalidResponse)`. The catalog allows `src-port-operator ∈ {eq, gt, lt}`. `change.rs:181-189` runs `preflight` and then `verify` through this reader.
- impact: The router holds `access-list Other permit tcp … port gt 1024` (written by the router's own UI, or the earlier form `rule_words.rs` documents). Every `firewall::change::apply` on any list then returns `InvalidResponse`. For an Add, the line was already sent, so a successful change is reported as failed. This is related to the two-readers item in BACKLOG ("Known gaps", firewall reader entry) but is a separate failure mode. Tagged KNOWN-BACKLOG-adjacent.
- fix: Parse only the targeted list, and keep unknown forms as "unstructured" entries instead of failing, as `rule_words::StoredRule` does.
- confidence: high

### D-07 Read-back cannot detect a no-op when the target already exists
- severity: medium
- kind: bug
- rule: project rule (c) "a write the router accepts but does not apply fails"
- evidence: `firewall/change/verify.rs:98-100,129-133` (Add is verified when any equal rule exists). `vpn_clients/import.rs:172-176` (`PresencePredicate::Present` on `/…/peers/{key}/preshared-key`). `vpn_clients/secrets.rs:154-158` (any non-empty payload of 512 bytes or less passes).
- impact: Several cases pass verification without proving anything:
  - Rotating a peer PSK (`plan_wireguard_peer_psk`) on a peer that already has one.
  - Re-setting a PPP/IKE secret that already exists.
  - Adding a firewall rule identical to one already present.

  In each case, a router that silently ignores the write still passes. With duplicate rules, `Remove` can also fail verification falsely, because one copy is left.
- fix: Snapshot before applying. For secrets, compare the opaque `ns3` payload before and after; it must change, and needs no decoding. For rules, compare the count before and after.
- confidence: high

### D-08 Route removal is checked by routing-table row count, and the wipe recovery is lossy
- severity: medium
- kind: bug
- rule: project rule (c); BRIEF "string matching on error names"
- evidence: `crates/kcc-domain/src/routing/change.rs:83-104`
  ```rust
  let before_table = read::ipv4_table(router).await?;
  ...
  if reports_cleared(&result.responses) {
      for saved in before_table.iter().filter_map(configured_ipv4_route) {
          let restore = plan_add_ipv4(router, &saved?)?;
  ...
  if before.checked_sub(after) != Some(1) {
  ```
  `:122-135` maps 3-word commands as `[network, mask, gateway]`. `:235` checks `item.message.to_ascii_lowercase().contains("cleared")`. The same code is in `change/ipv6.rs:95-118`.
- impact: Several removals go wrong:
  - **Inactive route:** a static route whose gateway is down is not in `show ip route`. Its removal returns `RouteCountMismatch` even though it succeeded.
  - **Concurrent changes:** any DHCP or PPP route change between the two reads does the same.
  - **Interface-only routes:** in the "cleared" recovery, a route like `net mask Wireguard0` is planned with `gateway=Wireguard0` and fails validation. The `?` then aborts the restore loop, so the remaining routes stay deleted.
  - **Inactive routes during a wipe:** these are never restored at all.
- fix: Verify absence of the exact command in `show rc`. Take the restore set from the running config, not the table, and restore every route before returning the first error.
- confidence: medium (INFERRED: the `command` shape of real `show ip route` rows)

### D-09 Segment create does not roll back the step that failed
- severity: medium
- kind: bug
- rule: none
- evidence: `crates/kcc-domain/src/segments.rs:206-224`
  ```rust
  if let Err(source) = step::apply(changes, router, definition, Direction::Create).await {
      for rollback in applied.into_iter().rev() {
  ```
  `segments/step.rs:255-265`: `apply_cli` succeeds, then a missing `context_has_child` returns `VerificationFailed`.
- impact: If the router accepts a step (for example `interface Bridge23 ip address …`) but the read-back does not match, `Bridge23` stays configured. kcc still returns `StepFailed`, whose doc says rollback ran. The test `bridge_failure_rolls_vlan_and_trunks_back` only covers a parse refusal.
- fix: When the step's own request was sent, include that step in the rollback (run its delete line).
- confidence: high

### D-10 `RuleProperty::Order` can never be planned, and the Web builds its own order line
- severity: medium
- kind: dead-code
- rule: BRIEF anti-patterns "dead code", "duplication that drifts"
- evidence: `firewall/change.rs:107` has `RuleProperty::Order(position) => json!({"index":index,"order":position})`. The `access-list rule` arguments in catalogs 4.3, 5.0 and 5.1 are `{description, index, schedule}`, with no `order`, so validation returns `UnknownField`. `crates/kcc-web/src/firewall_page/lines.rs:80-82` validates `{"index"}` alone and formats `access-list {list} rule {index} order {to}` by hand.
- impact: The public variant (with its verifier at `verify.rs:141-156`) always fails. The working order path skips the domain planner and its identity verification.
- fix: Map `Order` to the catalog's `new-index` argument and route the Web through it, or delete the variant.
- confidence: high

### D-11 VPN-client Delete removes any interface and drops the catalog's Destructive risk
- severity: medium
- kind: security
- rule: overlay `mcp-servers.md` least privilege; project rule (b)
- evidence: `vpn_clients/render.rs:21-25` (`no interface {name}`, no type check). `vpn_clients/change.rs:96-101` builds `Risk::Write`, and `:72` sets the operation risk to whatever `classify_generated` returns (`interfaces/management.rs:92-120` returns only Write or Management). The catalog marks interface deletion as `Risk::Destructive` (`kcc-catalog/src/runtime.rs:466-467`), and the operation risk replaces it.
- impact: An MCP `vpn` call with `op=delete, name=ISP` (or `Bridge1`, or a Wi-Fi AP) deletes a non-VPN interface with `Write` only. Deleting `Bridge0` needs just `confirm:true`.
- fix: Read the interface first and refuse names whose `type` is not a VPN client type. Keep `max(catalog risk, classified risk)`.
- confidence: high on the code; whether interface deletion should need `Destructive` across all domains (WAN delete is also Write) is a project-wide question.

### D-12 VPN server status reads the crypto-map virtual IP at the wrong pointer
- severity: medium
- kind: bug
- rule: none
- evidence: `crates/kcc-domain/src/vpn_servers.rs:208,222-225`
  ```rust
  "crypto":{"map":{"virtual-ip":{...}}},
  ...
  ipsec_virtual_ip: root.pointer("/crypto/map/virtual-ip").cloned().unwrap_or_else(|| json!({})),
  ```
  `vpn_servers/verification.rs:37-41` uses `/crypto/map/{name}/virtual-ip/enable`, so maps are keyed by name.
- impact: Any configured IPsec virtual-IP server shows up as `{}`. The read only works if a map is literally named `virtual-ip`.
- fix: Request `crypto map {}` and collect `virtual-ip` per map name.
- confidence: medium (INFERRED from the inconsistency with the verifier)

### D-13 Hand-written config-text walkers, duplicated and already drifted
- severity: medium
- kind: duplication
- rule: BRIEF "copy-paste duplication that drifts"
- evidence: `vpn_clients/secrets.rs:141-161` and `vpn_servers/secrets.rs:58-87` are the same indentation and context loop, but they already differ: one strips `"ns3 "` and bounds the payload at 512 bytes, the other strips `" any"` and has no bound. More walkers are in `segments/step.rs:279-294`, `segments/ownership.rs:107-125` and `segments/discovery.rs:182-213`. `firewall/read.rs:64-68` and `verification.rs:115-116` use `kcc_config::config_text::{parse, flatten}` instead.
- impact: The parsers treat comments, indentation and nesting differently, so the same running config can verify as present in one domain and absent in another. A fix to one copy will miss the others.
- fix: Use `kcc_config::config_text::parse`/`flatten` with one shared "find context and child" helper.
- confidence: high

### D-14 `RevealSecrets` gate is shipped with no production caller, and its scope check is not tied to the router
- severity: medium
- kind: dead-code
- rule: BRIEF "dead or test-only code shipped in production"; project rule (d)
- evidence: `crates/kcc-domain/src/vpn_servers/secrets.rs:38-41`
  ```rust
  pub fn authorize(role: &Role, name: &str, router: &'router RouterCtx) -> Result<Self> {
      authorize(role, Permission::RevealSecrets, name)
  ```
  `RouterCtx` has no id (`lib.rs:61-66`). `read_stored` is only called from `tests/vpn_server_secrets.rs:47,89`.
- impact: This is a secret-reveal API with no audit hook. Its scope check trusts a caller-supplied name that is not bound to the `RouterCtx`, so a future caller can pass a name in scope with a context for a different router.
- fix: Delete it until a surface needs it, or bind the router id inside `RouterCtx` and record an audit entry inside the gate.
- confidence: high

### D-15 Validated requests are changed after validation
- severity: medium
- kind: anti-pattern
- rule: RUST_GUIDELINES.md §3 "Force construction through validated constructors" (424)
- evidence: `vpn_clients/change.rs:95` has `validated.value = json!({"line":line,"arguments":validated.value});`. The same pattern is in `vpn_servers.rs:246`, `vpn_clients/import.rs:170` and `vpn_clients/secrets.rs:107`; it is unpacked again at `vpn_clients/change.rs:111-121` and `vpn_servers.rs:271-283`. `dns/change.rs:29-34` inserts an unvalidated `name` into `validated.value`.
- impact: `ChangeOp.requests[*].value` no longer matches what was validated. Any consumer that reads `.value` (plan previews, audit, classification) sees `{"line":…}`. The line itself, which is what gets sent, was never validated.
- fix: Carry the line next to the `ValidatedRequest` in a typed struct, and never change `value` after validation.
- confidence: high

### D-16 WireGuard parse error can keep a raw key line in a `Debug`-derived error
- severity: medium
- kind: security
- rule: project rule (d) "never in … error text or Debug output"
- evidence: `crates/kcc-domain/src/vpn_clients/wireguard/parser.rs:68-74`
  ```rust
  let (field, value) = line.split_once('=')...
      .ok_or_else(|| WireGuardParseError::Malformed {
          line: line_number,
          field: line.to_owned(),
      })?;
  ```
  `wireguard.rs:102` has `#[derive(Clone, Debug, …)]`.
- impact: A pasted config with `PrivateKey: <key>` (colon typo), or a bare key line, produces `Malformed{field: "<key>"}`. Any `{error:?}` or `tracing` `?error` then prints the key. Today's surfaces use Display or ignore `field`, so this is latent.
- fix: Store only the line number for `Malformed`.
- confidence: high

### D-17 WireGuard ASC: the doc says extra values are ignored, but the line keeps them
- severity: medium
- kind: bug
- rule: BRIEF "comments that lie"
- evidence: `vpn_clients.rs:227-228` says "values past the sixteenth are ignored". `vpn_clients/render.rs:62-66` uses `asc.values.join(" ")` while `asc_body` (`:232-242`) zips only 16 values. The values are unquoted, and the catalog types are `String`.
- impact: `kcc vpn wireguard-asc NAME v1 … v17` (`kcc/src/cli/dom_vpn.rs:185-187`) sends 17 words while 16 were validated. An `I1` value containing spaces (AmneziaWG's `<b 0x…>`) splits into several words.
- fix: Refuse more than 16 values, and quote each value.
- confidence: high

### D-18 Verification and validation failures turned into `InvalidResponse`
- severity: low
- kind: guideline
- rule: project rule (c) "fails with a verification error naming the field"; RUST_GUIDELINES.md §2 "Propagate errors with `?`" (228)
- evidence: `policies/change/apply.rs:55-57` and `nat/change.rs:306-308` return `DomainError::InvalidResponse` on a failed read-back. `segments/step.rs:223-224,244`, `vpn_clients/secrets.rs:134-136` and `firewall/change.rs:93,242,256` convert validation issues or bad input into `InvalidResponse`.
- impact: Users and audit see "invalid response" for a write that did not apply, or for their own bad port range, with no field named.
- fix: Return `VerificationFailed { field }` and `Validation { issues }`.
- confidence: high

### D-19 The same planner helpers are copied across seven modules
- severity: low
- kind: duplication
- rule: BRIEF "copy-paste duplication"
- evidence: The same `validate`/`plan` closure appears in `firewall/change.rs:267-272`, `policies/change/plan.rs:117-122`, `routing/change.rs:184-196`, `nat/change.rs:337-349`, `segments/step.rs:297-302`, `vpn_servers.rs:242-245` and `dns/change.rs:25-28`. The `push`/`text`/`number` render helpers repeat in `nat/change.rs:372-379`, `routing/change.rs:214-221,240-242`, `dns/change.rs:343-359`, `policies/change/render.rs:122-135` and `firewall/change/render.rs:145-155`. `firewall/change.rs:235-243` and `render.rs:99-107` repeat the same `match side` over strings.
- impact: Fixes such as quoting (D-02) have to land in seven places.
- fix: One crate-internal `plan_one(router, path, body, risk)` and one typed word renderer.
- confidence: high

### D-20 One stray `kcc-segment:` description breaks segment discovery
- severity: low
- kind: bug
- rule: router responses are untrusted input
- evidence: `crates/kcc-domain/src/segments/discovery.rs:194-211`
  ```rust
  let record: Ownership = serde_json::from_str(body).map_err(|_error| DomainError::InvalidResponse)?;
  ...
  if context != format!("interface Vlan{}", record.spec.id) {
      return Err(DomainError::InvalidResponse);
  }
  ```
- impact: Any interface description starting with `kcc-segment:` that is malformed or on the wrong interface fails `read_segments`, so the whole Segments view goes down.
- fix: Skip and log a bad record instead of failing the entire read.
- confidence: high

### D-21 Planners signal invalid input through sentinels and string dispatch
- severity: low
- kind: anti-pattern
- rule: RUST_GUIDELINES.md §3 "Use enums instead of …" / §8 "Overreliance on `String`" (1567)
- evidence: `vpn_servers/render.rs:107` has `(None, None) | (Some(_), Some(_)) => json!({"invalid":true})`. `:145-150` and `:170-175` match on a string prefix with a `_ => ""` fallback.
- impact: An invalid end/size combination surfaces as `UnknownField{"invalid"}` with a nonsense nearest-match suggestion.
- fix: Return a typed error, and take an enum for the server kind.
- confidence: high

### D-22 Dead branches and phantom inventory entries
- severity: low
- kind: dead-code
- rule: BRIEF "dead code"
- evidence: `vpn_clients/import_fields.rs:69-71` returns `(address, bits)` for IPv6, which can never pass the `IpMask` check (and the Web refuses IPv6 ranges earlier, at `vpn_conf.rs:138-143`). `firewall/descriptor.rs:18` lists an `ipv6_rule` write, but no planner exists and no catalog has the path.
- impact: The tool descriptions advertise operations that cannot run, and the code suggests IPv6 support that does not exist.
- fix: Remove both, or implement them.
- confidence: high

### D-23 Tests that duplicate, cannot fail, or cost a lot for little
- severity: low
- kind: test-quality
- rule: RUST_GUIDELINES.md §13 (3482); BRIEF "duplicated scenarios, tests that cannot fail"
- evidence:
  - `tests/firewall.rs:153-174` and `tests/firewall_binding.rs:197-218` are the same test.
  - `tests/vpn.rs:173-175` asserts that the serialized `VpnServerStatus` does not contain "password", "preshared" or "private-key". Those fields do not exist on that type (`vpn_servers.rs:48-96`), so the assertion can never fail.
  - `tests/firewall_render.rs:66-101` spawns 864 fixtures per firmware (1,728 in total) for a source/destination address cross-product that adds no branch coverage, while source port ranges, `Description(None)` and `Schedule(None)` (D-01) are never tested.
- impact: Slow CI with false confidence; the D-01 regression is not covered.
- fix: Delete the duplicate and the vacuous assertions, and replace the address cross-product with the property and clear cases.
- confidence: high

## Coverage
- **Read in full:**
  - Firewall: `firewall.rs` and `firewall/{model, rule_words, rule_words_tests, change, change/render, change/verify, read, lists, management, descriptor}.rs`.
  - VPN clients: `vpn_clients.rs` and `vpn_clients/{render, change, secrets, import, import_fields, read, wireguard, wireguard/parser, wireguard/fields}.rs`.
  - VPN servers: `vpn_servers.rs` and `vpn_servers/{render, secrets, verification}.rs`.
  - Segments: `segments.rs` and `segments/{step, step/definitions, ownership, discovery}.rs`.
  - Policies: `policies.rs` and `policies/{read, model, descriptor, change, change/plan, change/apply, change/render}.rs`.
  - Routing: `routing.rs` and `routing/{read, model, descriptor, change, change/ipv6}.rs`.
  - NAT: `nat.rs` and `nat/{read, model, descriptor, change}.rs`.
  - DNS: `dns.rs` and `dns/change.rs`.
  - Tests: `firewall.rs`, `firewall_render.rs`, `firewall_read.rs`, `firewall_binding.rs`, `routing.rs`, `nat.rs`, `segments.rs`, `unavailable_operations.rs`, `vpn_secrets.rs`, `vpn_server_secrets.rs`, `support/mod.rs`.
- **Mostly read:** `tests/dns.rs` (lines 20-124), `tests/vpn.rs`, `tests/persists.rs`.
- **Skimmed (assertions and function lists via grep):** `tests/segment_discovery.rs`, `tests/policies.rs`, `tests/management_detect.rs`, `tests/management_parity.rs`, `tests/firewall_management.rs`, `tests/vpn_credentials.rs`.
- **Outside scope, opened to verify impact:** `cli_token.rs`, `verification.rs`, kcc-catalog `validate.rs`/`runtime.rs`, the `catalog/*/access-list.json` and related catalog entries, the Web `firewall_page/{lines, checks, expect, rule_props}.rs`, `routing_page/policy_forms.rs`, `dns_vpn/vpn_conf.rs`, MCP `write/{filtering, vpn, dns, common}.rs`, `interfaces/management.rs`, and the CLI `dom_vpn.rs`.
- **Not read:** none in scope.

## Clean
- WireGuard parser key validation (32-byte Base64) and duplicate detection; `Debug` on `WireGuardInterface`/`WireGuardPeer` redacts key presence.
- Secret transport: `validate_secret` plus `from_template`, so no secret goes into a plan, request `Debug`, audit or trace (pinned by `vpn_secrets.rs`/`vpn_credentials.rs`).
- Firewall management-risk classification fails closed on unreadable membership (`management.rs:40-43`, `change.rs:44-60`).
- NAT session paging is bounded (`PAGE_SIZE`, the oversized-page refusal at `nat/read.rs:67-69`).
- The segment delete guard (`check_delete`) refuses to delete a whole context when unrelated children exist, and `prepare` refuses existing contexts.
- `firewall::read::firewall` redacts before tokenizing and drops non-word lines.
- Cancel-safety annotations on the lane's async functions are present and match their behavior.
- No `unwrap`, `expect`, panic or bare `as` in lane production code; untrusted text parsing has no unbounded loops.