I checked all 23 lane-D findings against the code at HEAD `349b7fb`; nothing was edited and no `cargo` was run. Nothing is refuted: 11 stand as written and 12 needed corrections. D-01 holds at high severity, and it is worse than reported: in some cases the rule is re-enabled and the read-back still passes.

### D-01 ADJUSTED
- checked: `crates/kcc-domain/src/firewall/change.rs:87-117`, `firewall/change/render.rs:41-82,127-143`, `firewall/change/verify.rs:135-159`, `crates/kcc-catalog/src/validate.rs:172-232`, the `access-list rule` synopsis and arguments in `catalog/{4.3,5.0,5.1}/access-list.json`, `crates/kcc-web/src/firewall_page/{rule_props.rs:73-194, lines.rs:104-138, checks.rs:45-58, expect.rs:85-100}`, `crates/kcc/src/cli/dom_admin.rs:101-105`.
- reasoning:
  - **What is sent.** `Description(None)` and `Schedule(None)` both build `{"index":N,"no":true}`. The catalog accepts `no` because `prefix_no` is true. `render_property` finds no `description`, `schedule` or `order` field, so it falls through to `disable`. `line()` then adds the `no ` prefix, and the router receives `no access-list L rule N disable`, which re-enables the rule. The documented clear form is `no rule <index> (disable | schedule | description)`.
  - **Web reaches it.** An empty or whitespace description gives `checks::description` → `Ok(None)` → `lines::description(.., None)`. The schedule dialog's "no schedule" choice `""` gives `picked = None` → `lines::schedule(.., None)`. The CLI never builds `None`, and MCP refuses `description`/`index`.
  - **The read-back does not always fail, contrary to the finding.** `Expect::Property` only compares description or schedule with `None`. If the rule had no description (or no schedule), saving the dialog as it is enables a disabled rule, and the read-back passes silently.
- severity: high
- correction: The rule is enabled, unrequested, every time. The read-back fails only when a value existed before. When the dialog is saved with nothing to clear (the default empty field, or "no schedule" on a rule without one), the enable is silent and is audited as success. Fix as proposed: render `no access-list L rule N description|schedule`. Add a test for clearing on a disabled rule, both with and without a prior value.

### D-02 ADJUSTED
- checked: `crates/kcc-domain/src/dns/change.rs:23-34,118-193,216-315`, `vpn_clients/render.rs:14-133,228-230`, `vpn_clients/change.rs:57-103`, `vpn_servers/render.rs:56-117`, `policies/change/render.rs:44-89`, `policies/change/plan.rs:111-115`, `firewall/change/render.rs:41-82`, `firewall/management.rs:38-56`, `interfaces/management.rs:91-120`, `kcc-catalog/src/validate.rs:278-306`, `kcc-catalog/src/runtime/data.rs:204`, the catalog argument types (`access-list name`, `interface ip access-group acl`, `object-group fqdn name`, `crypto map name` = String; `access-list rule schedule` = ObjectName; `interface name` = Interface→ObjectName), `kcc-mcp/src/support/validate.rs:39-45`, `kcc-mcp/src/domains/write/{common.rs:177-181, dns.rs:100-160, vpn.rs:89-155, filtering.rs:186-233, routing.rs:200-208}`, `kcc-app/src/workflow_cli/command.rs:128-138`, `kcc-web/src/firewall_page/{checks.rs:15-17, rule_actions.rs:70-73}`, `routing_page/policy_dialogs.rs:24-38`.
- reasoning:
  - **Confirmed sinks.** These values reach the line unquoted, with no check beyond "is a string":
    - MCP firewall `acl` (`text()` only rejects control characters);
    - DNS group, profile and URL names, and profile descriptions;
    - the VPN-client `name` in every context op (`interface {name} …`), which is not in the validated body;
    - the WireGuard peer `public_key` in endpoint, allow-ips and keepalive ops;
    - crypto-map `name`;
    - the policy `description` from MCP and CLI.
  - **No line-break injection.** `expose_for_send` refuses control characters, so the caller adds words inside one line only; it cannot start new lines.
  - **Parts that are wrong.** The firewall `schedule` is catalog type ObjectName. The firewall `interface` is Interface, which maps to ObjectName. Both are validated as one word. The Web firewall pages check list names with `ObjectName` (`list_name`), and the Web policy description is a single word (`word()`). The impact example (`object-group fqdn G description …`) cannot be reached, because that request always fails validation (D-03).
  - **Concrete reachable example.** MCP `fqdn_group name="G include evil.example"` sends `object-group fqdn G include evil.example`, a different command than the one validated.
- severity: medium
- correction: Limit the sinks to MCP and CLI input: ACL name, DNS names and descriptions, VPN context names and peer keys, crypto-map names, and policy description. Remove firewall schedule and interface from the list, and replace the FQDN-description example with the one above.
  - **Possible extra impact (inferred).** `list_risk` matches `acl == list` against bindings. An `acl` containing spaces matches no binding, so the plan is classified `Write`, while the router would act on the first word of the list name. Whether the router accepts the trailing words is unverified.

### D-03 CONFIRMED
- checked: `crates/kcc-domain/src/dns/change.rs:172-175,240,302-315`, `catalog/{5.0,5.1}/object-group.json` (`object-group fqdn description` arguments are only `{description}`), `catalog/4.3` (no such command), `kcc-catalog/src/validate.rs:201-231`, `kcc-mcp/src/domains/write/dns.rs:152-155`, `kcc/src/cli/dom_dns.rs:172-175`.
- reasoning: The body `{"name","description"}` against arguments `{description}` with no children makes `name` an `UnknownField`. On 4.3 the path does not exist at all. Nothing in any test or Web caller exercises the variant.
- severity: medium

### D-04 CONFIRMED
- checked: `crates/kcc-domain/src/policies/change/plan.rs:34-38`, `policies/change/render.rs:24-89`, `policies/change/apply.rs:24-58`, `kcc-web/src/routing_page/{policy_forms.rs:133-160, policy_dialogs.rs:24-38, policy_change.rs:71-81}`, `kcc-mcp/src/domains/write/routing.rs:208`, `kcc/src/cli/dom_policies.rs:49`.
- reasoning: With `None`, the body is `{"no":true}`. `leaf_line` then calls `expected_leaf`, where `text(request,"description")` fails with `InvalidResponse`. Web (empty field → `None`), MCP and CLI all reach this. It fails before `apply_cli`, so nothing is sent; the only cost is that a description can never be cleared.
- severity: medium

### D-05 CONFIRMED
- checked: `crates/kcc-domain/src/firewall/change.rs:193-258`, `firewall/change/render.rs:84-125`, `firewall/model.rs:66-150`, the `access-list permit/deny` synopsis (ports appear only in the `(tcp | udp)` branch; arguments are shared between branches), `kcc-mcp/src/domains/write/filtering.rs:209-231`, `kcc-domain/tests/firewall_render.rs:25,64-121`.
- reasoning: The `Rule` port fields are public and nothing checks them against the protocol. MCP `Transport::Ip`/`Icmp` with a `port` renders `… ip … port eq N`. The matrix test adds ports to `Icmp` and `Ip` and expects that line to reach the fake router. Whether a real router rejects it is inferred from the documented grammar.
- severity: medium

### D-06 CONFIRMED
- checked: `crates/kcc-domain/src/firewall/read.rs:43-52,109-223`, `firewall/change/verify.rs:62-126`, `firewall/change.rs:176-191`, `docs/BACKLOG.md:38`.
- reasoning:
  - **Mechanism.** One unparsable row in any list makes `configured_rules` return an error. Triggers include `port gt/lt` (the `[keyword, ..] if keyword == "port"` arm) and any row that is not `permit`/`deny`.
  - **Sent, then reported failed.** `Add` has an empty preflight, so the line is sent first and verification fails afterwards. `Remove` and `Property` fail in preflight, before anything is sent.
  - **Scope.** Bindings are unaffected (`has_binding`), and the Web uses the separate text reader.
  - **Backlog.** BACKLOG:38 lists only the two-readers duplication, not this failure mode.
- severity: medium

### D-07 ADJUSTED
- checked: `firewall/change/verify.rs:96-133`, `vpn_clients/import.rs:160-176`, `vpn_clients/secrets.rs:82-160`.
- reasoning: All three cited checks are presence-only, as the finding says. They cannot detect an ignored write when the target already existed. A false `Remove` failure with duplicate rules is real, but needs duplicates on the router. The fix for secrets is doubtful: if `ns3` encoding is deterministic, re-setting the same secret would then be reported as a failure.
- severity: low
- correction: This is a weakness in verification strength on re-set or duplicate paths, not a broken flow. For secrets, document it as a known limit, or compare payloads only when the old and new secret are known to differ.

### D-08 CONFIRMED
- checked: `crates/kcc-domain/src/routing/change.rs:75-137,230-238`, `routing/change/ipv6.rs:15-59`, `routing/read.rs:13-21`, `routing/model.rs:28-101`, `kcc-domain/src/verification.rs:99-140`.
- reasoning:
  - **Count check.** `apply_cli` already checks the line's absence through `verification::complete`. The extra `before - after == 1` routing-table count then gives false `RouteCountMismatch` for:
    - inactive routes (not in the table);
    - concurrent DHCP or PPP route changes.
  - **Lossy restore.** The restore treats a 3-word `command` as `[network, mask, gateway]`. An interface-only route fails `IpAddress` validation, and `?` aborts the loop with the other routes still deleted. Routes missing from the table are never restored.
  - **Inferred.** The real shape of the `show ip route` row `command` is inferred.
- severity: medium

### D-09 CONFIRMED
- checked: `crates/kcc-domain/src/segments.rs:98-125,188-242`, `segments/step.rs:216-265`, `kcc-app/src/workflow.rs:1117-1160`.
- reasoning: `applied.push` runs only after `step::apply` returns `Ok`. A step that was sent and then failed the `context_has_child` check (or the `verification::complete` check inside `apply_cli`) is not rolled back. `apply_cli` itself does not undo anything. `StepFailed` is documented as "failed after any required rollback was attempted".
- severity: medium

### D-10 ADJUSTED
- checked: `firewall/change.rs:107,130`, `firewall/change/render.rs:137-138`, `firewall/change/verify.rs:141-156`, the `access-list rule` synopsis and arguments (4.3, 5.1), `kcc-web/src/firewall_page/lines.rs:75-84`, and a grep for `RuleProperty::` across `crates/`.
- reasoning: `Order` produces `{"order":…}`, which is an `UnknownField` because the arguments are `{description, index, schedule}`. No caller uses the variant. The Web order path validates only `{index}`, but its extra values (`list` checked by `ObjectName`, `to` a `usize`) are safe, and the Web verifies with `Expect::At`. The fix as written also fails: `new-index` appears in the synopsis but not in the catalog's arguments.
- severity: low
- correction: The cost is a dead public variant plus a hand-built Web line, with no unsafe value. Mapping to `new-index` first needs the catalog generator to emit that argument. Otherwise, delete the variant.

### D-11 CONFIRMED
- checked: `vpn_clients/render.rs:16-25`, `vpn_clients/change.rs:55-103`, `interfaces/management.rs:91-120`, `kcc-catalog/src/runtime.rs:456-475`, `kcc-mcp/src/domains/write/{vpn.rs:89-95,193-200, common.rs:46-150}`, a grep for `.risk` in `kcc-app/src/workflow.rs`.
- reasoning:
  - **No type check.** MCP `vpn op=delete` accepts any ObjectName and sends `no interface X`.
  - **Risk is replaced.** `classify` overwrites the operation risk with Write or Management. The catalog marks `interface`+`no` as `Risk::Destructive` in `interface_node_risk`, but the workflow never reads per-request risk (only `Risk::Read` at `workflow.rs:999`).
  - **Consequence.** The destructive switch and the confirmation for destructive actions are bypassed.
- severity: medium

### D-12 CONFIRMED
- checked: `crates/kcc-domain/src/vpn_servers.rs:200-238`, `vpn_servers/verification.rs:25-50`, `kcc-testkit/src/projection/vpn_server.rs:61-93`, `kcc-web/src/dns_vpn/vpn_servers_tab.rs:100`.
- reasoning: The verifier and the testkit projection both key maps by name (`/crypto/map/{name}/virtual-ip/...`). The reader asks for, and reads, `/crypto/map/virtual-ip`. So the Web tab shows `{}` unless a map is literally named `virtual-ip`.
- severity: medium

### D-13 ADJUSTED
- checked: `vpn_clients/secrets.rs:126-160`, `vpn_servers/secrets.rs:47-87`, `segments/step.rs:279-294`, `firewall/read.rs:60-69`.
- reasoning: The walker loop is duplicated. Most of the "drift" is deliberate: one walker checks presence, so it strips `ns3 ` and bounds the length; the other returns the stored form, so it keeps `ns3` and strips the IKE ` any`. No case is shown where the same config verifies differently across domains.
- severity: low
- correction: This is a maintenance duplication only. The claim that one config could verify as present in one domain and absent in another is not demonstrated.

### D-14 ADJUSTED
- checked: `vpn_servers/secrets.rs:17-90`, `kcc-domain/src/lib.rs:61-74`, a grep for callers (only `tests/vpn_server_secrets.rs:47,89`).
- reasoning: There is no production caller, `RouterCtx` carries no router id, and the gate has no audit. `read_stored` returns the stored `ns3` representation, not plaintext. Today there is no consequence.
- severity: low
- correction: This is dead, latent API with a scope check that is not bound to the router. Delete it or bind the router id. Its present cost is low.

### D-15 ADJUSTED
- checked: `vpn_clients/change.rs:89-136`, `vpn_servers.rs:240-283`, `vpn_clients/import.rs:160-176`, `vpn_clients/secrets.rs:100-107`, `dns/change.rs:29-34`, a grep for `.requests` consumers in kcc-web, kcc-mcp and kcc.
- reasoning: `value` is changed after validation, as stated. However, no consumer reads `ChangeOp.requests[*].value` of these ops before `request()` unpacks it. The audit sees the unpacked `arguments`, and the web and MCP code does not read these values for previews or classification. The real cost, a line that was never validated, is D-02.
- severity: low
- correction: The "previews, audit, classification see `{line}`" impact is not shown. This is a design smell whose security cost is already counted in D-02.

### D-16 ADJUSTED
- checked: `vpn_clients/wireguard/parser.rs:48-98,160-198`, `vpn_clients/wireguard.rs:100-140`, `kcc-web/src/dns_vpn/vpn_conf.rs:63,86-108`.
- reasoning: Base64 WireGuard keys end in `=`. A line such as `PrivateKey: <key>=` or a bare key line therefore does split on `=`, and inside a section it becomes `UnknownField { field: "<key without padding>" }`, not `Malformed`. The Display of `UnknownField` (`"unknown WireGuard field {field} …"`) prints the key, so it leaks through error text, not only `Debug`. `Malformed` with a key happens only before any section header. Today the Web ignores `field`, and only the Web calls the parser, so the leak is latent.
- severity: medium
- correction: Store only the line number in `UnknownField`, `Malformed` and `Duplicate` (anything that can hold raw line text), or never derive `field` from unparsed text. This is a project rule (d) violation in Display error text.

### D-17 CONFIRMED
- checked: `vpn_clients.rs:218-233`, `vpn_clients/render.rs:62-67,232-243`, `kcc/src/cli/dom_vpn.rs:185-188`, catalog `interface wireguard asc` (16 String arguments on 5.1, 9 on 4.3/5.0).
- reasoning: The line uses every value joined with spaces, while the body zips at most 16. The doc's "ignored" claim is false, and values containing spaces split into several words.
- severity: medium

### D-18 ADJUSTED
- checked: `policies/change/apply.rs:54-57`, `nat/change.rs:82-92`, `segments/step.rs:222-223,244`, `vpn_clients/secrets.rs:133-135`, `firewall/change.rs:93,242,256`.
- reasoning: The pattern is real: failed read-backs and bad user port ranges return `InvalidResponse`. The NAT location is cited wrongly; that file has 167 lines.
- severity: low
- correction: The NAT read-back is at `nat/change.rs:90-92`, not 306-308.

### D-19 ADJUSTED
- checked: `firewall/change.rs:229-272`, `policies/change/plan.rs:117-122`, `routing/change.rs:184-196,214-221,240-242`, `nat/change.rs:121-133,156-163`, `segments/step.rs:297-302`, `vpn_servers.rs:242-245`, `dns/change.rs:25-28,343-359`, `firewall/change/render.rs:99-107,145-155`.
- reasoning: The duplication exists as described, but the NAT line numbers point past the end of the file.
- severity: low
- correction: The NAT copies are at `nat/change.rs:121-133` (`plan`) and `156-163` (`push`).

### D-20 CONFIRMED
- checked: `segments/discovery.rs:177-214`.
- reasoning: Any `description kcc-segment:…` line that fails JSON or ownership checks, or sits under a context other than `interface VlanN`, fails the whole `read_segments`. Any user with Write can set such a description through ordinary interface or policy descriptions.
- severity: low

### D-21 CONFIRMED
- checked: `vpn_servers/render.rs:97-118,143-184`.
- reasoning: `{"invalid":true}` is used as a sentinel, and the `_ => ""` string dispatch is as cited. The `""` arms cannot be reached with the fixed callers, but the sentinel can (MCP pool with neither `end` nor `size`).
- severity: low

### D-22 ADJUSTED
- checked: `vpn_clients/import_fields.rs:62-81`, `kcc-catalog/src/validate.rs:338-347`, `firewall/descriptor.rs:8-19`, `kcc-domain/src/lib.rs:157-200`, `kcc-mcp/src/domains/write/filtering.rs:29`, `kcc/tests/cli_domain_writes/excluded.rs:21-27`.
- reasoning: The IPv6 branch of `parse_prefix` is dead, because `IpMask` accepts only IPv4 masks. However, `ipv6_rule` is filtered by `available()` (no catalog has the path), MCP does not offer it (`FIREWALL_OPS = ["rule","binding"]`), and the CLI lists it as a documented exclusion. Nothing advertises it.
- severity: info
- correction: Only the dead IPv6 `parse_prefix` branch remains. The "tool descriptions advertise operations that cannot run" impact is false.

### D-23 ADJUSTED
- checked: `kcc-domain/tests/firewall.rs:153-174`, `tests/firewall_binding.rs:1-57`, `tests/vpn.rs:160-178`, `vpn_servers.rs:48-96`, `tests/firewall_render.rs:24-101`, `tests/support/mod.rs:46`.
- reasoning:
  - **Duplicate test: real.** It matches `firewall_binding.rs:36-57`; the file has only 57 lines, so 197-218 is wrong.
  - **"Cannot fail": false.** `VpnServerStatus` holds raw router `Value` subtrees (`ServerConfigStatus` `Option<Value>` fields, `wireguard_interfaces: Vec<Value>`, `ipsec_virtual_ip: Value`), so a secret-bearing projection would trip the check.
  - **Fixture counts: correct.** 2×4×3×3×3×2×2 = 864 per firmware, ×2 profiles.
  - **Missing coverage: confirmed.** No test uses `Description(None)` or `Schedule(None)`.
- severity: low
- correction: Drop the "vacuous assertion" sub-claim and fix the duplicate's line numbers. The coverage gap for D-01 stands.

## Summary
- CONFIRMED: 11 (D-03, D-04, D-05, D-06, D-08, D-09, D-11, D-12, D-17, D-20, D-21)
- ADJUSTED: 12 (D-01, D-02, D-07, D-10, D-13, D-14, D-15, D-16, D-18, D-19, D-22, D-23)
- REFUTED: 0
- DUPLICATE: 0

NEW issues, to be validated separately:
- **NEW-1 (D-01 sibling, high):** the Web schedule or description dialog, saved with nothing to clear (the default empty field, or "no schedule" on a rule without a schedule), sends `no access-list L rule N disable`. `Expect::Property` (`expect.rs:85-100`) still holds, so a disabled firewall rule is silently re-enabled and audited as success.
- **NEW-2 (medium, partly inferred):** `firewall/management.rs:38-56`. `list_risk` matches bindings by the exact `acl` string. An MCP `acl` with spaces (allowed by `text()`) matches no binding, so the change is classified `Risk::Write` and skips fail-safe and Management permission. The rendered line still acts on the list named by its first word. Whether the router executes such a line is unverified.
- **NEW-3 (medium):** `vpn_clients/wireguard/parser.rs:173-176,194-197`. `UnknownField.field` is the text before the first `=`. For a mistyped key line it contains the key minus its padding, and Display prints it. This is the realistic form of D-16.
- **NEW-4 (low):** the `access-list rule` synopsis has `order <new-index>`, but the catalog's arguments map lacks `new-index` (4.3, 5.0, 5.1). No catalog-validated reorder is possible until the generator emits it.