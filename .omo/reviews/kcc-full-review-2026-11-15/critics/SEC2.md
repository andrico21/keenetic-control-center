The review is complete and I changed no files. I opened every cited location at HEAD `349b7fb`, along with the reqwest 0.13.5, hyper-util 0.1.21 and url 2.5.8 sources and `catalog/5.1`.

### SEC2-01 CONFIRMED
- checked: `crates/kcc-rci/src/outbound.rs:137-150,186-238`, `crates/kcc-rci/src/session.rs:256-282`, `crates/kcc-telemetry/src/logs/sink.rs:76-88`, `elastic_sink.rs:76-88`, `crates/kcc/src/cli/tls.rs:99-102`, `reqwest-0.13.5/src/async_impl/client.rs:310,409-419,1425-1438`, `hyper-util-0.1.21/src/client/proxy/matcher.rs:227-236`, `Cargo.toml:38`, `crates/*/Cargo.toml`
- reasoning: `auto_sys_proxy` defaults to true. `build()` adds `ProxyMatcher::system()`, which reads `ALL_PROXY`, `HTTP(S)_PROXY` and `NO_PROXY`. There is no localhost exclusion, and the CGI check only suppresses `HTTP_PROXY`. The repo calls `.no_proxy()` exactly once, in `tls.rs:102`. Nothing scrubs proxy variables: the only `remove_var`/`env_clear` hits are unrelated. `resolve_to_addrs` only overrides DNS for the router host, so with a proxy the TCP connection goes to the proxy, and the `allows()` check is made against an address that is never dialled.
- Nuance: for `https` routers the CONNECT tunnel keeps TLS verify or pin end-to-end, so the proxy sees only host:port. The clear-text exposure (ndw2 hash, cookie, `startup-config` with ns3) is for `http://` routers, which is the usual LAN case. With an IP-literal router such as `192.168.1.1`, the proxy connects to that address on its own network, which can be a different router. A loopback `http` log sink would also go through the proxy.
- severity: medium

### SEC2-02 CONFIRMED
- checked: `crates/kcc-domain/src/clients/command.rs:120-170`, `clients.rs:135-143,255-290`, `dhcp/command.rs:32-104`, `dhcp.rs:85-180`, `vpn_clients/render.rs:14-75,126-147`, `vpn_clients/change.rs:57-130`, `interfaces/management.rs:92-121`, `kcc-catalog/src/validate.rs:278-303`, `catalog/5.1/{known,ip,interface}.json`, `kcc-app/src/workflow_cli/command.rs:38-160`, `kcc-app/src/workflow.rs:1110-1124,1270-1290`, `kcc-mcp/src/domains/write/clients.rs:140-250`, `common.rs:177-181`, `support/validate.rs:39-45`, `vpn.rs:85-112`, `kcc/src/cli/dom_core.rs:135-160,231-233`, `kcc-web/src/clients_pages/client_act.rs:220-250`, `kcc-domain/src/cli_token.rs`, `docs/rust-guidelines/overlays/projects/keenetic-control-center.md:42-45`
- reasoning:
  - **Catalog types.** `known host` name, `ip dhcp pool` name, `ip dhcp host` host, `interface wireguard peer` key and every `wireguard asc` field are typed `String`, and `valid_argument` only checks `is_string()`.
  - **MCP input.** `text()` checks only length (1-256 characters) and control characters.
  - **Sending.** A non-template `CliCommand::expose_for_send` sends the line verbatim after the same control-character check, and `apply_cli` passes it to `client.parse(line)`. Spaces therefore become extra router CLI tokens, which the router splits on whitespace and protects only inside double quotes. This is why `cli_token::quoted` exists.
  - **Rule (b).** The rule requires "the identifier validators" for tool and CLI arguments, and they are not applied on these paths.
  - **Mitigation.** Injection is limited to tokens after a fixed prefix at the same permission. For VPN lines, `classify_generated` still checks the first interface token for management risk.
- severity: medium
- correction (adds to the finding):
  1. MCP `dhcp` static-lease `mac` is free text, used unvalidated in `ip dhcp host "{mac} {address}"` (`dhcp.rs:157`). The `host` field contains a space by design, so catalog validation could not reject one there anyway.
  2. The VPN interface `name` goes into `format!("interface {name} …")`, but for most VPN paths it is not in the catalog body (`render.rs:126-133`).
  3. The CLI `clients access|policy|…` path uses `label()` = the router-reported client name (`dom_core.rs:231-233`), unsanitized, as the `known host` name. Unlike the Web's `registration_name`, this lets router- or LAN-supplied text into the line.
  4. The audit `params` record the full injected string, so the mismatch is in the catalog path and risk classification, not hidden text.

### SEC2-03 CONFIRMED
- checked: `crates/kcc-app/src/registry.rs:620-655,733-785`, `poller.rs:28-35,345-370`, `poller/extended.rs:70-90`, `kcc-rci/src/auth_ndw4.rs:95-120`, `ndw4_keys.rs:17-75`, `kcc-rci/src/session.rs:499-502` (grep: no `impl Drop` in kcc-rci)
- reasoning: When `read_login` is set, `poll_client` builds a new `RciClient` on every call. `fetch` calls it every light round, and `fetch_heavy` calls `poll_info` → `poll_client` again. The ndw4 key cache is per manager, so each new client runs Argon2 under the global semaphore. `logout()` exists but no drop path calls it. The router-side session-table effect is still unverified, as the reviewer says.
- severity: medium

### SEC2-04 CONFIRMED
- checked: `crates/kcc-app/src/audit.rs:440-470,580-630,745-785`, `audit/writer.rs:40-100`, `audit.rs:537-541`, `docs/SECURITY.md:300-336`
- reasoning: `verify_files` rejects any line that does not parse, and it runs in both `spawn_with_policy` and every `append_locked`. A failed `write_all` (ENOSPC or a crash) can leave a partial line. The writer then stops, `require_alive` refuses router work, and the next start fails at `AuditLog::spawn`. `SECURITY.md:325-327` says `kcc serve` exits non-zero "so its supervisor can restart it". The torn line turns that recovery into a crash loop that needs a manual edit. Neither BACKLOG nor the owner decisions cover it.
- severity: medium

### SEC2-05 CONFIRMED
- checked: `crates/kcc-app/src/audit.rs:34-39,580-590,657-742,750-856`, `docs/SECURITY.md:313-318`
- reasoning: Each `append_locked` lists all rotated files plus the active one, parses every line, recomputes each canonical hash, and holds all entries in a `Vec`. This happens under the cross-process lock. With a 365-day retention and 50 MiB rotation, the cost per append grows with the whole retained log. Failed Web logins are audited too (`kcc-web/src/auth.rs:363`), so even rate-limited traffic grows it. The docs say the writer "re-read[s] its tail", but the code re-reads everything.
- severity: medium

### SEC2-06 ADJUSTED
- checked: `crates/kcc-rci/src/outbound.rs:96-123`, `engine.rs:80-96,252-261`, `kcc-migrate/src/source.rs:120-140,195-210`, `inventory.rs:50-65`, `kcc-app/src/registry.rs:298-312,380-396,754-785`, `kcc/src/server_outbound.rs:7-14`, `README.md:66-75`, `docs/CONFIG.md:81-99`, project overlay rule (h)
- reasoning: The code is as the finding describes: the default is permissive and `from_live`, `load_source` and `InventoryClient::connect` add loopback. However, there are no production callers. Grep finds only tests and `planner/buildability_tests.rs`. Every production `RciClientOptions::default()` (`registry.rs:304,754,772`) overwrites `outbound` with the operator policy, and `registry.rs:392-395` replaces the networks, suffixes and loopback. The README and CONFIG "empty by default" statement describes `[outbound]` in `kcc.toml`, which is accurate. Rule (h) says the crates are not a published library, so "a future caller" is a latent risk with no demonstrated consequence.
- severity: low
- correction: This is latent dead code and a footgun, not a weakened control today. The fix is still sound: a deny-all `Default`, plus deleting the unused entry points or making them take `&OutboundPolicy`.

### SEC2-07 ADJUSTED
- checked: `crates/kcc-config/src/secrets.rs:62-100,140-175`, `catalog/5.1/crypto.json` (`crypto ike key` synopsis is name, psk, …; profile `preshared-key`/`xauth-password`), `kcc-app/tests/cli_templates.rs:24-38`, `kcc-domain/src/vpn_clients/secrets.rs:50-75`, `kcc-web/src/advanced/preview.rs:165,235-263`, `config_page/text.rs:64-80`, `presets_page/lines.rs:20-45`, `wizard/analysis.rs:32-39`, `migrate_wizard/analysis.rs:139-150`, `kcc-mcp/src/config_tools/backups.rs:156-170`, `kcc/src/cli/redact.rs`
- reasoning: The registry bug is real. `["crypto","ike","key", rest @ ..]` → `argument_index` points at `rest[0]`, which is the key name. Nothing matches `crypto ipsec profile <n> preshared-key|xauth-password`, and the fixture `crypto ike key theta` pins the wrong shape. However, every surface I opened also masks all `Token::Ns3` payloads: preview, config text and download, preset lines (through `shown_line`), migration leftovers, MCP backups and the CLI redact. So exposure happens only if the firmware stores these PSKs as plain words, which is unverified. Also, `presets_page::lines::secret()` still flags the line as secret, because redacting the name changes the line.
- severity: low
- correction: This is a defect in the redaction registry, backstopped by ns3 masking. Raise it to medium only if live firmware is shown to store IKE or profile PSKs as plaintext words.

### SEC2-08 REFUTED
- checked: `crates/kcc-rci/src/ndw4_keys.rs:17-75`, `auth_options.rs:37,47` (the default cap is at `:47`, not `:85`), `session.rs:313-318`, `auth_ndw4.rs:103-118`, `docs/BACKLOG.md:62`
- reasoning: The mechanism (one global Argon2 permit, so derivations run one after another across the fleet) is already `docs/BACKLOG.md:62`, and the reviewer labels it KNOWN-BACKLOG itself. The hostile-parameters angle is the same root cause. The cap is operator-tunable through `max_argon2_memory_kib` (8..=262144), and the reviewer's own derivation times are inferred. Under CRITIC rule 3 this is not a new finding. The adversarial angle could be added as a note to the backlog item.

### SEC2-09 ADJUSTED
- checked: `crates/kcc-app/src/registry.rs:620-637,767-806`, `registry/stored.rs:1-30`, `kcc-app/src/credentials.rs:330-346`, `kcc-rci/src/engine.rs:262-290`, `outbound.rs:186-208`, `docs/rust-guidelines/RUST_GUIDELINES.md:1112-1180`
- reasoning: The guideline allows "use tokio::sync::Mutex if you must hold across await" (`RUST_GUIDELINES.md:1165`), and `clients` is a tokio mutex. The "locks across await" rule is therefore not violated. What holds:
  1. `client()` for every router is serialized behind one router's DNS resolution, which is `spawn_blocking` but awaited under the fleet mutex.
  2. `std::fs` reads plus `create_private_dir` (mkdir and chmod) run on a runtime worker (`credentials()` → `stored::secret` → `CredentialStore::open/directory`). This does violate "DON'T: Call blocking I/O in async functions" (`:1112`).
- severity: low
- correction: Cite rule `:1112` (blocking I/O) and the head-of-line blocking, not lock-across-await.

### SEC2-10 CONFIRMED
- checked: `crates/kcc-rci/src/outbound.rs:137-150,186-208`, `url-2.5.8/src/lib.rs:1162-1168`, `kcc-rci/src/lib.rs:65-95`
- reasoning: `host_str` returns the slice `host_start..host_end`, which for IPv6 includes the brackets. `RouterUrl` accepts `http://[fd00::1]`. `("[fd00::1]", port).to_socket_addrs()` does not parse as an IP and goes to the resolver, which fails, so the result is `RciError::Policy`. No repo test covers an IPv6 router. It fails closed.
- severity: low

### SEC2-11 ADJUSTED
- checked: `crates/kcc-rci/src/outbound.rs:24-29,242-260`, `kcc-rci/src/lib.rs:77-95`, `docs/SECURITY.md:19-25`, overlay rule (a)
- reasoning: The deny list is as described, and allowing `169.254.0.0/16` would admit `169.254.170.2`. Two things limit the impact:
  - `RouterUrl` is origin-only: the path must be `/`, with no query or userinfo, and kcc requests only fixed RCI and auth paths. The ECS credential endpoint needs a secret per-task path (`/v2/credentials/<id>`), so kcc cannot fetch credentials from it.
  - `169.254.169.253` is a DNS resolver, not an HTTP credential service. Reaching either also needs an admin-configured link-local allowlist.
- severity: info
- correction: Treat this as defence-in-depth hardening (also deny `169.254.170.2`). It does not open a credential-exfiltration path.

### SEC2-12 ADJUSTED
- checked: `crates/kcc-app/src/accounts.rs:371-422`, `persist.rs:205-222`, `kcc-web/src/auth.rs:183,195-236,300-320,356-385`
- reasoning: `authenticate` runs inside `StateStore::update`, which always calls `write_locked` (rewrite plus fsync), including for unknown users. Argon2 runs under the exclusive `users.json` lock. Disabled accounts skip Argon2 and get the same "invalid" response, so timing does reveal them. However, `Locked` already gets a distinct `"locked"` outcome in the response (`auth.rs:232-233`), so its timing reveals nothing extra.
- severity: low
- correction: Drop the "locked answers fast" part. Keep the unconditional write, the Argon2 under the lock, and the timing leak for disabled accounts.

### SEC2-13 ADJUSTED
- checked: `crates/kcc-migrate/src/presets/store.rs:140-165,230-262`, `kcc-app/src/persist.rs:160-170,428-431,550-568`
- reasoning: Durability gap confirmed: plain `fs::write`, no fsync and no directory sync, and `list` fails on the first malformed record (`read_record(...)?`). The permission part is weak. `StateStore::open` makes the state directory 0700 (`persist.rs:167`), so umask-mode files below it cannot be reached by other users, and the records are AEAD-sealed. The suggested fix is also not directly available: `write_atomic` and `create_private_dir` are `pub(crate)` in kcc-app.
- severity: low
- correction: The impact is crash durability and `list` failing on a torn record. The fix needs a public atomic-write API on `StateStore` (or exporting the helper) before kcc-migrate can use it.

### SEC2-14 CONFIRMED
- checked: `crates/kcc-telemetry/src/logs/sink.rs:76-88`, `elastic_sink.rs:76-136`, `pipeline_delivery.rs:190-250`, grep of `timeout` in `logs/` (only the shutdown deadline at `pipeline.rs:91`)
- reasoning: Neither builder sets `timeout` or `connect_timeout`, reqwest has no default timeout, and nothing wraps `client.send` in a timeout. `response.json::<BulkResponse>()` buffers the whole body, while Loki has a cap. Sinks are operator-configured, which keeps this low.
- severity: low

### SEC2-15 CONFIRMED
- checked: `crates/kcc-app/src/credentials.rs:100-116,170-240,300-330,375-385`
- reasoning: `open`, `exists`, `manages`, `sealed_path` and `legacy_path` join `router` into a path without calling `lock_name`. Their docs promise `CredentialError::Record` for an invalid id, which never happens. Today registry ids are validated upstream and the AEAD binding resists planted files, so this is a docs and robustness issue.
- severity: low

### SEC2-16 CONFIRMED
- checked: `crates/kcc-app/src/secrets.rs:265-286`, `kcc-config/src/ns3.rs:35-70`, `kcc-rci/src/engine.rs:550-565,690-710`, overlay rule (d) (`keenetic-control-center.md:48-49`)
- reasoning: On the error path, the decrypted `Vec` is dropped inside `FromUtf8Error` without zeroizing. ns3 `padded` and `bytes` are plain buffers. `read_capped` grows a plain `Vec` (realloc copies), and the upload does `expose_secret().to_vec()`. Some copies cannot be avoided (hyper and reqwest `Bytes`), which keeps this low.
- severity: low

### SEC2-17 CONFIRMED
- checked: `crates/kcc/src/cli/files.rs:31-55`, `cli/migrate.rs:53-57,105`, `cli/migrate_apply.rs:84-90`, `kcc-app/src/credentials/wipe.rs:15-58`, `credentials.rs:245-262`
- reasoning: With `fresh=false`, the code opens the predictable `path.with_extension("kcc-tmp")` with `create(true).truncate(true)`. That follows a planted symlink or reuses a planted regular file, and mode 0600 applies only on creation, so a file pre-created by someone else stays readable to them. `secure_remove` uses `fs::metadata` and opens without `O_NOFOLLOW`, but only inside the kcc-owned 0700 credentials directory. Linux `protected_symlinks`/`protected_regular` mitigate the problem in sticky directories.
- severity: low

### SEC2-18 CONFIRMED
- checked: `crates/kcc-app/src/credentials.rs:108-116,194,361`, `accounts.rs:346,405,465`, `accounts/reset.rs:30`, `backups/store.rs:96,148`
- reasoning: A router password record uses AD = the bare router id, and an account hash uses AD = the bare username, under the same key. Swapping records needs state write access and gains nothing: a router password would fail PHC parsing, and a PHC hash sent as a router password fails the login.
- severity: info

### SEC2-19 CONFIRMED
- checked: `crates/kcc/src/privileges.rs:236-262` (grep: no `Gid`/`Groups` parsing), `README.md:59-61`
- reasoning: Only `uids.contains(&0)` is checked. Note that OpenShift deliberately runs with GID 0, so the "log it" variant of the fix is the safe one.
- severity: info

### SEC2-20 CONFIRMED
- checked: `crates/kcc-app/src/secrets.rs:183-215,302`, `persist.rs:550-568`
- reasoning: `load_or_create` calls `create_private_dir(parent)`, which runs `set_permissions(0o700)` on an existing parent. For a custom `KCC_MASTER_KEY_FILE` path, that silently re-modes the parent, or fails with EPERM when the parent is owned by someone else.
- severity: info

## Summary
- CONFIRMED: 13 (01, 02, 03, 04, 05, 10, 14, 15, 16, 17, 18, 19, 20)
- ADJUSTED: 6 (06 → low, 07 → low, 09 low with the rule corrected, 11 → info, 12 low narrowed, 13 low narrowed)
- REFUTED: 1 (08, already `docs/BACKLOG.md:62`)
- DUPLICATE: 0
- NEW (to validate separately), low:
  - **Router-supplied client name reaches a CLI line.** `crates/kcc/src/cli/dom_core.rs:231-233` `label()` passes the router-reported client name (for an unregistered client, possibly a LAN device's DHCP hostname) unsanitized into `known host {name} {mac}`. This is an injection path from a router response or the LAN, not only from the operator, and the Web path sanitizes the same value with `registration_name` (`client_act.rs:225-245`). It could be merged into SEC2-02.
- NEW (to validate separately), info:
  - **Account enumeration and lockout.** The Web login answers `"locked"` distinctly (`crates/kcc-web/src/auth.rs:232-233`), but only existing accounts can reach `Locked` (`accounts.rs:386-420`). Repeated bad passwords therefore enumerate usernames and can lock out an admin. This is a common trade-off and should be checked against the owner's intent.