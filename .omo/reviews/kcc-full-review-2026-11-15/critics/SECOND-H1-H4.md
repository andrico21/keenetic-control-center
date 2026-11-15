### H1 CONFIRMED (split into H1a–H1d below)
- checked: see the sub-claims.
- reasoning: A role with only `Read` reaches router secrets on two surfaces, MCP and the Web explorer. A third, separate defect sits in the Web masker. The CLI part does not hold. The real router's reply shape is still INFERRED (`docs/BACKLOG.md:18` lists the shape only, not this exposure). Nothing on these paths redacts configuration text, so the leak happens whatever the shape. The ns3 blobs can be decoded without any key (`kcc-config/src/ns3.rs:42-60`: base64 plus marker swaps).
- severity: high

### H1a CONFIRMED (MCP `kcc_rci_read` with a Read principal)
- checked: `kcc-mcp/src/registry/definitions.rs:116-122`, `generic/router.rs:228-245`, `generic/rci.rs:44-60,186-210`, `support/access.rs:66-75`, `support/errors.rs:114-124`, `support/shape.rs:49,160-239`, `kcc-catalog/src/runtime.rs:118-147`, `runtime/data.rs:99-133`, `catalog/5.1/show.json:7812-7860` (the same command exists in 4.3 and 5.0), `kcc-rci/src/lib.rs:606-629`, `kcc-rci/src/engine.rs` `show()`, `kcc-app/src/permissions.rs:162-180`, `kcc-app/src/settings.rs:188,202`.
- reasoning:
  - **Permission:** the tool is in the `core` toolset and needs only `Permission::Read`. `show running-config` has `kind: Show`, takes no arguments, and is on none of the destructive or management lists, so its risk is Read. The built-in `viewer` role holds exactly `Read`.
  - **What goes over the wire:** `client.show` sends `GET /rci/show/running-config`, falling back to POST. `RciResponse::from_value` keeps the whole value, and `rci_body_value` returns `value` or `text` as it came.
  - **Redaction:** `shape → redact_secrets` matches object key names only. Configuration lines inside strings or `message` arrays pass through untouched.
  - **One limit the first critics did not mention:** the default `max_result_bytes` is 32 KiB. A running-config bigger than that comes back only as `{"truncated":true}`. Paging is impossible: there is no cursor input, and the `fields` input is ignored (see NEW-1). So by default the full leak covers configurations under about 32 KiB, or any size if the operator raises the cap. That limits who is affected but is not a control.
  - **Minor sub-claim from E-01:** the MCP denylist does miss `key`, `private-key`, `community` and `pin` in JSON answers (`private-key` contains a hyphen, not `private_key`). Whether real `show` answers carry those keys is unverified.
- severity: high

### H1b CONFIRMED (Web explorer read with the Read role)
- checked: `kcc-web/src/authz.rs:248-262`, `advanced.rs:151,158`, `page_kit/gate.rs:17-25`, `advanced/execute.rs:39-110`, `advanced/request.rs:60-80,119-131`, `advanced/deliver.rs:96-106,212-214,330-337`, `advanced/viewer.rs:72-118`.
- reasoning:
  - **Permission:** `/ui/r/{r}/explorer/execute` falls through to `Permission::Read`. The handler re-checks only `command_permissions(Risk::Read) = [Read]`.
  - **What goes over the wire:** `Delivery::Read` leads to `read_root`, which POSTs `{"show":{"running-config":{}}}` to `/rci/`.
  - **What reaches the page:** `Rendered::body` passes a `Text` body verbatim. A JSON body goes through `mask`, which matches names only, so string lines with `wpa-psk ns3 …` or `password ns3 …` are shown. `RevealSecrets` decides only whether that name-based masking runs.
  - **Contrast:** every sibling path to the same data redacts it or needs `RevealSecrets` (`firewall/read.rs:55-70` redacts the parsed configuration, the preview uses `ns3_redacted`, the backup download needs `RevealSecrets`).
  - **Console:** the Web console leak (W4-01) also holds, but only for a custom role that has `RawRci` without `RevealSecrets`. No built-in role has that combination, and `RawRci` can already rewrite those secrets, so that part on its own is low.
- severity: high

### H1c CONFIRMED (nested-object gap in `page_kit/secret.rs` `mask`)
- checked: `kcc-web/src/page_kit/secret.rs:14-47`, `kcc-testkit/src/projection/interface.rs:50-75`, `kcc-domain/src/wan.rs:167-190`, `kcc-domain/src/wifi/plan.rs:74`, `kcc-mcp/src/support/shape.rs:207-239`.
- reasoning:
  - **The gap:** `mask` replaces a secret-named member only when its value is neither an object nor an array. Otherwise it recurses, and the inner key `ns3` is not in `is_secret`. So `{"password":{"ns3":"<blob>"}}` and `{"wpa-psk":{"ns3":"<blob>"}}` reach the page unmasked. A secret-named array also passes.
  - **This shape is not a guess:** the project's own read-backs expect a real `show interface` to carry the blob at `/<if>/authentication/password/ns3` and `/<if>/authentication/wpa-psk/ns3`. `plan_password` checks a length range of 24-256, which only a real blob satisfies.
  - **Reachable:** `show interface` is a Read command, so a viewer gets the PPP password and the Wi-Fi PSK through the explorer, with no assumption about the shape of `show running-config`.
  - **Separate fix needed:** fixing text redaction for H1b does not close this. The MCP redactor handles this case correctly, because it replaces the whole member whose name contains `password` or `psk`.
- severity: high (an independent vector, with its own fix in `mask`)
- correction: Mask the whole member when its name is secret, whatever its type, and add `ns3` to `is_secret`.

### H1d REFUTED (the CLI)
- checked: `kcc/src/cli/rci.rs:38-60`, `cli/fleet.rs:127-145`, `cli/context.rs:274-313`, `cli/principal.rs:1-60`, `kcc-app/src/settings.rs:290-305`.
- reasoning:
  - **The behaviour is real:** `kcc rci get show running-config` needs `RawRci` and `Read`, and prints the body unredacted.
  - **It is not a boundary:** every `services()` call loads `master.key` and opens the credential store in the caller's own process. The `[cli] role` (default `admin`) comes from the operator's own config file.
  - Whoever runs the CLI can therefore unseal the router password and read the configuration directly, so the permission check is not a confidentiality boundary.
- severity: info at most

### H2 CONFIRMED
- checked: `kcc-web/src/auth.rs:47-55,170-233,355-367,463-475,495-510`, `kcc-app/src/accounts.rs:28-30,378-422,649-675`, `kcc-app/src/audit.rs:25-40,140-160`, `kcc-web/src/lib.rs:220,562`, `kcc/src/server.rs:136-147`, `docs/CONFIG.md:252`, `deploy/podman/kcc.toml.example:8`.
- reasoning:
  - **The path:** `LoginForm.username` is an unbounded `String`. An unknown user goes through dummy Argon2 to `Invalid`, then `login_failure`, `audit()` and `Actor::new(ActorKind::Web, username.to_owned())`, with no truncation anywhere. The only bound is the 1 MiB request body limit.
  - **No other guard stops it:** lockout counts only existing accounts. Retention is by age (365 days), and nothing caps total size.
  - **The fix already exists unused:** `validate_username` (1..=64 bytes, `accounts.rs:667`) is never called by `authenticate`.
  - **Throughput:** each attempt runs Argon2 (19 MiB, t=2) inside the users-file update, which serializes attempts. That still leaves tens of MiB of audit log per second.
  - **Exposure:** the default bind is loopback, but the shipped Podman example binds `0.0.0.0`, so a LAN attacker without credentials can reach it there.
- severity: high (unauthenticated: fills the disk and stops `kcc serve` once the audit writer dies)

### H3 CONFIRMED (D-01, and critics/D NEW-1 holds)
- checked: `kcc-domain/src/firewall/change.rs:72-140`, `firewall/change/render.rs:23-82,127-143`, `firewall/change/verify.rs:135-159`, `kcc-domain/src/verification.rs:99-142`, `kcc-web/src/firewall_page/rule_props.rs:70-185,230-250`, `checks.rs:45-58`, `lines.rs:104-135`, `expect.rs:85-100`, `catalog/{4.3,5.0,5.1}/access-list.json` `access-list rule` (`prefix_no: true`; arguments: description, index, schedule).
- reasoning:
  - **What is sent:** `Description(None)` and `Schedule(None)` both build `{"index":N,"no":true}`, which passes catalog validation. `render_property` finds no `description`, `schedule` or `order`, so it falls through to `disable`. `line()` adds `no `, and the router receives `no access-list L rule N disable`.
  - **Web reaches it:** the description field is `.optional()`, and empty or blank input becomes `Ok(None)`. The schedule dialog's first choice is `""`, which becomes `picked = None`.
  - **The workflow check passes:** `verification::complete` checks that `access-list L rule N disable` is now absent, which holds because the rule was just enabled.
  - **The Web check passes in the common case:** `Expect::Property` compares only description or schedule. When there was nothing to clear, it holds too, so a disabled rule is enabled silently and audited as success (NEW-1 confirmed). When a value existed, the rule is enabled and only the description check fails, after the router has already changed.
- severity: high (a deliberately disabled firewall rule turns on without being asked; wrong router command)

### H4 CONFIRMED (G-01; the radio sub-claim is H4a)
- checked: `kcc-migrate/rules/rules.toml:142-168`, `src/rules.rs:380-435,494-560,640-690`, `src/maps.rs:63-115`, `src/inventory.rs:426-440`, `src/presets/plan/classify.rs:20-50`, `kcc-web/src/migrate_wizard/maps.rs:115-175`, `migrate_wizard/names.rs:40-43`.
- reasoning:
  - **Rule order:** the first matching rule wins. `copy-wireguard-private-key` and `copy-ns3-secret` come before `remap-mapped-reference` and `scalar-conflict`.
  - **Copy ignores mappings:** `explicit_item` calls `apply_mappings` only for `Remap`. A secret line keeps the source interface name while its sibling lines are remapped. It also skips the scalar-conflict check, so it silently overwrites the target's secret.
  - **The Wi-Fi PSK case does hold, contrary to the G critic's correction:** the Web wizard puts `WifiMaster0/AccessPoint0` into the *interface* map, because `is_radio` requires digits only after `WifiMaster`. If the operator maps an access point there, `ssid` moves and the `wpa-psk ns3` line stays on the source access point.
  - **No backlog entry** covers this.
- severity: high

### H4a CONFIRMED (radio mappings never rewrite access-point tokens)
- checked: `kcc-config/src/config_text.rs:295-345`, `kcc-rci/src/capabilities.rs:590-635`, `kcc-migrate/src/rules.rs:682-690`, `presets/plan/classify.rs:28-46`, `kcc-web/src/migrate_wizard/maps.rs:140-160`.
- reasoning:
  - **The tokenizer does not split on `/`:** it splits on whitespace (and quotes) only, so `WifiMaster0/AccessPoint0` is one `Token::Word`.
  - **Radio ids are the bare radio:** they are the part before `/` (`capabilities.rs` `split_once('/')`), for example `WifiMaster0`.
  - **Both planners replace exact tokens only:** `apply_mappings` and the preset classifier rewrite a token only when it equals a mapping key exactly.
  - **No code derives access-point mappings from the radio map:** nothing in `kcc-migrate` or `migrate_wizard` turns a radio mapping into access-point mappings.
  - **Consequence:** a radio mapping such as WifiMaster0 → WifiMaster1, which `RadioMap::propose` can choose by band, moves the radio settings but leaves SSID, schedule and PSK lines on the source-numbered access point, which may be on the other band.
  - **Why only medium:** the wizard does list access points as separate interface-map entries, so an operator can fix this by hand.
- severity: medium (wrong band or AP on the target with a plausible default proposal; the operator can work around it)

## Summary
- **CONFIRMED (7):** H1a, H1b, H1c, H2, H3, H4, H4a. The H1 umbrella is confirmed high.
- **ADJUSTED:** 0. H1a is confirmed with one stated condition: by default only configurations under the 32 KiB MCP result cap leak through `show running-config`.
- **REFUTED (1):** H1d (CLI). The CLI principal holds the master key and sets its own role, so there is no boundary to bypass.
- **NEW-1 (low):** in `kcc-mcp/src/generic/rci.rs:192`, `kcc_rci_read` validates `input.fields` and then drops it. `shape` (`support/shape.rs:174-183`) reads `fields` from the *result* value instead of the input. The documented projection never applies, and an over-cap answer returns `next_cursor: "1"` that no input accepts. The read is therefore all or nothing.
- **Note for the H2 fix:** `accounts.rs:667` `validate_username` (1..=64 bytes, `[a-z0-9._-]`) already exists. Calling it at the start of `authenticate`, and treating a failure as `Invalid` with the actor name truncated or replaced, closes H2.