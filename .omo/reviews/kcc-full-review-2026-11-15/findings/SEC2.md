## SEC2 review: secrets, crypto, outbound requests, CLI injection and files on disk

I found **0 critical/high, 8 medium, 9 low and 3 info** issues. The most important ones:
- Router and log-sink HTTP clients follow proxy environment variables, which bypasses the outbound IP policy.
- MCP and CLI input reaches router CLI lines without quoting.
- A read-only polling login opens a new router session every poll.
- One torn audit line permanently stops the audit writer.

Everything below was read in this session without running cargo or touching the repository.

---

### SEC2-01 Router and log-sink HTTP clients honour HTTP(S)_PROXY / ALL_PROXY, bypassing the resolved-IP policy
- severity: medium
- kind: security
- rule: overlay project rule (a) "the resolved address must fall inside allowed_networks"; http-services SSRF rule
- evidence: `crates/kcc-rci/src/outbound.rs:220-224`
  ```rust
  let mut builder = Client::builder()
      .redirect(Policy::none())
      .connect_timeout(timeouts.connect)
      .read_timeout(timeouts.read)
      .resolve_to_addrs(host, resolved);
  ```
  - `session.rs:264-269` only adds the redirect policy and timeouts before `build()`.
  - `kcc-telemetry/src/logs/sink.rs:76` and `elastic_sink.rs:76` use `Client::builder().redirect(Policy::none())` with no `.no_proxy()`.
  - In reqwest 0.13.5, `async_impl/client.rs:417-418` (`if config.auto_sys_proxy { proxies.push(ProxyMatcher::system()) }`) reads `ALL_PROXY`/`HTTPS_PROXY`/`HTTP_PROXY` (hyper-util 0.1.21 `matcher.rs:228-236`).
  - The only call that opts out is `crates/kcc/src/cli/tls.rs:99-102` (`.no_proxy()`), which shows the gap is unintended.
- impact: When kcc runs with `HTTP_PROXY` set (common on corporate hosts and in containers), every router request goes to the proxy instead of the pinned address.
  - That includes the ndw2 login hash, session cookie, `/ci/startup-config.txt` with ns3 secrets, and writes.
  - The `allowed_networks` and metadata checks are run against an address that is never connected to.
  - The proxy resolves the name itself, so the DNS pin is lost.
  - For `http://` routers the proxy sees everything in clear text.
- fix: Add `.no_proxy()` in `OutboundPolicy::pinned_builder` and in both sink builders. If proxies must be supported, make that an explicit per-sink setting.
- confidence: high

### SEC2-02 Free-text catalog values go unquoted into router CLI lines (MCP and CLI reachable)
- severity: medium
- kind: security
- rule: project rule (b) "validated against the catalog and the identifier validators before it reaches a router"
- evidence:
  - `crates/kcc-domain/src/clients/command.rs:133`
    ```rust
    "known host" => Ok(format!("known host {} {}", text("name")?, text("mac")?)),
    ```
  - `crates/kcc-domain/src/dhcp/command.rs:64-65`
    ```rust
    "ip dhcp host" => Ok(format!("ip dhcp host {}", text("host")?)),
    "ip dhcp pool" => Ok(format!("ip dhcp pool {}", text("name")?)),
    ```
    The same pool name is repeated in every later pool line (66-103).
  - `crates/kcc-domain/src/vpn_clients/render.rs:39-44, 62-67`: `format!("wireguard peer {public_key}")` and `format!("wireguard asc {}", asc.values.join(" "))`.
  - The catalog types these arguments as `String`, so validation only checks `value.is_string()` (`kcc-catalog/src/validate.rs:301`). In `catalog/5.1`: `known host` name, `ip dhcp pool` name, `ip dhcp host` host and `interface wireguard peer` key are all `String`.
  - `CliCommand::new(line, validated)` (`kcc-app/src/workflow_cli/command.rs:42-48`) never checks the line against the validated value.
  - MCP passes raw text: `kcc-mcp/src/domains/write/clients.rs:156,174,235-237` and `vpn.rs:89-108`. The CLI passes raw text at `kcc/src/cli/dom_core.rs:150`.
  - The Web clients page sanitizes (`client_act.rs:225-245`); other domain modules use `cli_token::validate`/`quoted`.
- impact:
  - A name with a space (common, for example "Anna phone") produces extra router arguments, so the command fails or is misparsed.
  - A prompt-injected MCP agent can choose the tokens after a fixed prefix. For example `name="Home range 10.0.0.2 10.0.0.3"` becomes a different `ip dhcp pool Home …` subcommand, while the audit log and risk classification record the validated `ip dhcp pool` name.
  - The MCP `access` op on an unregistered client with no `value` sends `known host  <mac>` (empty name).
- fix: Pass these values through `cli_token::quoted` (names and free text) or `cli_token::validate` (keys, ids), as `interfaces.rs`, `mesh.rs` and `wan/render.rs` already do. Consider making `CliCommand::new` re-run `validate_cli` on the rendered line.
- confidence: high on the mechanism. INFERRED: the exact router-side effect of injected tokens is not verified on hardware.

### SEC2-03 A profile with a read-only login opens a new router session (and ndw4 Argon2) on every poll and never logs out
- severity: medium
- kind: bug
- rule: none (session and resource leak)
- evidence: `crates/kcc-app/src/registry.rs:646-655`
  ```rust
  pub async fn poll_client(&self, id: &str) -> Result<Arc<RciClient>, RegistryError> {
      let profile = self.get(id)?.profile;
      if profile.read_login.is_some() {
          return Ok(Arc::new(
              self.connect_client(&profile, CredentialUse::ReadOnly)
                  .await?,
          ));
      }
      self.client(id).await
  ```
  - The poller calls this every 15 s (`poller.rs:358`, `LIGHT_INTERVAL` at `poller.rs:29`).
  - `fetch_heavy` calls `registry.poll_info` again (`poller/extended.rs:78`), which builds a second client.
  - Web facts and MCP access call `poll_info` too.
  - The ndw4 key cache lives inside each `Manager` (`session.rs:176`, `auth_ndw4.rs:105-118`), and `Manager` has no `Drop`/logout.
- impact:
  - Each poll performs a full login: 1-2 fresh router sessions every 15 s per router, never closed.
  - On ndw4 firmware each login runs an Argon2 derivation with router-chosen cost under the single global permit (`ndw4_keys.rs:18`), which delays every other router's login.
  - This floods the router's login log. INFERRED: it may exhaust the router's session table and block the admin's own UI logins.
- fix: Cache the read-only client per id like `client()` does (invalidate on reload/update), and use it in both `poll_client` and `poll_info`.
- confidence: high on the code path; INFERRED for router-side session limits.

### SEC2-04 One torn or partial audit line permanently stops the audit writer and stops `kcc serve` from starting
- severity: medium
- kind: bug
- rule: RUST_GUIDELINES error handling (recoverability of persisted state)
- evidence:
  - `crates/kcc-app/src/audit.rs:587-588` (every append) and `:444-445` (startup):
    ```rust
    let files = audit_files(&self.dir)?;
    let verified = verify_files(&files)?;
    ```
  - `:761-762`: `serde_json::from_str(&line).map_err(|error| json_error(&error))?;`
  - `audit/writer.rs:71-74`: any error other than lock contention is fatal (`stop(...); break;`).
- impact:
  1. A disk full or crash during `write_all` (`audit.rs:621-624`) leaves a partial JSON line.
  2. The writer stops at once, and every later change is refused because `require_alive` fails.
  3. After a restart, `AuditLog::spawn` fails on the same line, so the server does not start until someone edits `audit.jsonl` by hand.
- fix: Treat an unterminated last line of the active file as torn. Truncate it, or move it to a quarantine file and log that, before verifying. Do this both in `spawn_with_policy` and before each append.
- confidence: high

### SEC2-05 Every audit append re-reads and re-hashes the entire retained chain (O(N) per entry)
- severity: medium
- kind: bug
- rule: RUST_GUIDELINES performance / unbounded growth
- evidence: `crates/kcc-app/src/audit.rs:587-588` (above) runs inside `append_locked` for every entry, with defaults at `:34-39`:
  ```rust
  pub const DEFAULT_ROTATE_BYTES: u64 = 50 * 1024 * 1024;
  pub const DEFAULT_RETENTION: Duration = Duration::from_hours(365 * 24);
  ```
  Each pass parses every line and re-serializes it to compute SHA-256 (`:750-783`, `:807-856`).
- impact: Cost grows with a year of audit data, multiplied by the number of appends. Logins, forbidden attempts and each change append. Once hundreds of MB are retained, each append takes seconds while holding the cross-process lock, and change receipts time out into "pending".
- fix: Verify the full chain only at startup or `kcc audit verify`. Before each append, read only the tail of the active file (or the last rotated file when the active one is empty) to get `seq` and `prev_hash`.
- confidence: high

### SEC2-06 `OutboundPolicy::default()` is permissive, and public migration entry points connect with it plus loopback
- severity: medium
- kind: security / dead-code
- rule: project rule (a); AI anti-pattern "dead code shipped in production"
- evidence:
  - `crates/kcc-rci/src/outbound.rs:96-123`: the default admits 10/8, 172.16/12, 192.168/16, 100.64/10, fd00::/8 and eight cloud suffixes.
  - `engine.rs:80-95`: `RciClientOptions::default()` uses it, and `RciClient::connect` uses that default (`:259-261`).
  - `crates/kcc-migrate/src/source.rs:129-133`:
    ```rust
    pub async fn from_live(profile: &LiveRouterProfile) -> Result<Self, SourceError> {
        let options = RciClientOptions::default()
            .with_outbound(OutboundPolicy::default().with_loopback(true));
    ```
  - Same at `kcc-migrate/src/inventory.rs:57-59` (`InventoryClient::connect`).
  - grep finds no production caller of `load_source`/`from_live`/`InventoryClient::connect`; only tests use them.
  - The README says both lists are empty by default.
- impact: These are `pub` APIs. Any future caller ignores the operator's `allowed_networks` and adds loopback. A secure-looking default (`RciClient::connect`) quietly admits all private space.
- fix: Make `OutboundPolicy::default()` deny everything (empty lists, matching settings). Delete the unused `from_live`/`load_source`/`InventoryClient::connect`, or make them take a `&OutboundPolicy`. Keep the permissive set behind a `#[cfg(test)]` helper.
- confidence: high

### SEC2-07 Redaction registry blanks the IKE key name instead of the PSK, and misses ipsec-profile secrets
- severity: medium
- kind: security / test-quality
- rule: project rule (d) "secrets never reach … tool results"
- evidence: `crates/kcc-config/src/secrets.rs:76-90`
  ```rust
  | ["crypto", "ike", "key", rest @ ..]
  ...
  ] => Some(argument_index(offset, command, rest)),
  ```
  - The real syntax is `crypto ike key office <psk> any` (`kcc-app/tests/cli_templates.rs:24,71`). `argument_index` points at `rest[0]`, the name `office`, so the PSK stays.
  - No entry covers `crypto ipsec profile <name> preshared-key|xauth-password` (`vpn_clients/secrets.rs:59-66` writes these).
  - The unit test pins the wrong shape: `"crypto ike key theta\n"` (`secrets.rs:154`).
- impact:
  - When the router stores these values as plaintext words rather than `ns3`, they are shown to Read users. The affected surfaces are the explorer "stored lines" (`kcc-web/src/advanced/preview.rs:165`), presets and migration lines (`presets_page/lines.rs:30`, `migrate_wizard/analysis.rs:147`), downloads and MCP backups.
  - Those surfaces also mask `ns3` tokens, which protects only the ns3 form.
- fix: Map `crypto ike key` to `rest[1]` (the `psk`, accounting for `ns3`). Add `crypto ipsec profile _ preshared-key|xauth-password`. Fix the fixture to the real syntax.
- confidence: medium (INFERRED: whether firmware stores these as ns3 is not verified).

### SEC2-08 KNOWN-BACKLOG: one hostile LAN router can stall ndw4 logins for the whole fleet
- severity: medium
- kind: security
- rule: project rule "router responses are untrusted input" (BRIEF trust boundaries)
- evidence: `crates/kcc-rci/src/ndw4_keys.rs:17-18, 62-73`
  ```rust
  static BUDGET: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(1)));
  ...
  let permit = budget.acquire_owned().await...;
  task::spawn_blocking(move || { let result = Self::derive_sync(...); drop(permit); result })
  ```
  - The cap defaults to `max_argon2_memory_kib: 0x0004_0000` (256 MiB, `auth_options.rs:85`), with router-chosen iterations up to 64.
  - The cache is keyed on parameters, so a new salt forces re-derivation (`auth_ndw4.rs:107-115`).
- impact:
  - BACKLOG calls this "derives one after another". The worse case is a compromised router, or a MITM on an `http://` router, answering every challenge with 256 MiB, t=64 and a fresh salt.
  - That holds the single global permit almost continuously; a cancelled derivation keeps the permit (detached).
  - Every other router's ndw4 login waits, and polls, changes and brackets time out. SEC2-03 makes logins frequent.
- fix: Lower the default memory cap to what real firmware uses. Bound iterations and memory per router id, or fail the router's login when it exceeds a per-router time budget.
- confidence: high (code); INFERRED derivation times.

### SEC2-09 `RouterRegistry::client` holds the fleet-wide client mutex across DNS resolution and blocking file I/O
- severity: low
- kind: guideline
- rule: RUST_GUIDELINES async "no blocking in async / locks across await"
- evidence: `crates/kcc-app/src/registry.rs:626-637`
  ```rust
  let mut clients = self.clients.lock().await;
  ...
  self.connect_client(&profile, CredentialUse::Primary).await?,
  ```
  - `connect_client` does `spawn_blocking` DNS (`outbound.rs:195-205`).
  - It also does synchronous `read_secret_file`/`fs::read` and `create_private_dir`+`chmod` on every call (`stored.rs:17-29`, `credentials.rs:342-346`).
- impact: One router whose hostname resolves slowly (seconds to tens of seconds) stops `client()` for every other router. Every connect also runs `mkdir`+`chmod` and file reads on a runtime worker.
- fix: Build the client outside the lock with a per-id `OnceCell`, and move the credential reads into `spawn_blocking`.
- confidence: high

### SEC2-10 IPv6-literal router URLs always fail the outbound policy
- severity: low
- kind: bug
- rule: none
- evidence: `crates/kcc-rci/src/outbound.rs:192-201`
  ```rust
  let host = parsed.host_str().ok_or(RciError::Policy)?.to_owned();
  ...
  (resolver_host.as_str(), port).to_socket_addrs()
  ```
  `url` 2.5.8 `host_str` slices the serialization, so it returns `"[fd00::1]"` with brackets. `to_socket_addrs` then tries DNS on the bracketed string and fails.
- impact: `http://[fd00::1]` is refused as `Policy`, even though the default networks include fd00::/8. This fails closed, but the error is misleading and no test covers it.
- fix: Use `parsed.host()` and match `Host::Ipv6`/`Ipv4` directly instead of resolving the bracketed text.
- confidence: high

### SEC2-11 The metadata deny list misses other link-local cloud credential endpoints
- severity: low
- kind: security
- rule: project rule (a) "cloud-metadata addresses (169.254.169.254 and equivalents) are always refused"
- evidence: `crates/kcc-rci/src/outbound.rs:25-29` lists only 169.254.169.254, fd00:ec2::254 and 100.100.100.200.
- impact: If an operator allows 169.254.0.0/16 (link-local routers), kcc can still reach the AWS ECS task-credential endpoint 169.254.170.2 and the AWS DNS address 169.254.169.253.
- fix: Add 169.254.170.2 and 169.254.169.253 (and the ECS IPv6 equivalent), or always refuse 169.254.169.0/24 and 169.254.170.0/24.
- confidence: medium

### SEC2-12 Every login attempt, including unknown users, rewrites and fsyncs `users.json` under its exclusive lock; disabled and locked accounts answer fast
- severity: low
- kind: security
- rule: http-services DoS bounds; timing uniformity
- evidence: `crates/kcc-app/src/accounts.rs:386-400`
  ```rust
  self.state.update(|document: &mut UsersDocument| {
      let Some(account) = ... else {
          verify_dummy_password(password)?;
          return Ok(Authentication::Invalid);
      };
      if account.disabled {
          return Ok(Authentication::Disabled);
      }
  ```
  `StateStore::update` always runs `write_locked` (`persist.rs:221-222`), and Argon2 (19 MiB) runs inside the lock.
- impact:
  - Unauthenticated requests cause a disk write plus fsync and a serialized Argon2 each, under the per-IP rate limit.
  - A legitimate admin's login waits behind the queue.
  - Disabled or locked accounts skip Argon2, so response timing reveals them.
- fix: Run the Argon2 verification before taking the lock, and write only when counters change. Run the dummy hash for the disabled and locked branches too.
- confidence: high

### SEC2-13 Preset records bypass the state store's private atomic writer
- severity: low
- kind: duplication / guideline
- rule: project overlay owner-only state; RUST_GUIDELINES reuse existing abstractions
- evidence: `crates/kcc-migrate/src/presets/store.rs:239,259-261`
  ```rust
  fs::create_dir_all(&directory).map_err(PresetError::Io)?;
  ...
  let temporary = directory.join(format!(".{}.tmp", preset.id));
  fs::write(&temporary, bytes).map_err(PresetError::Io)?;
  fs::rename(&temporary, self.path(&preset.id)).map_err(PresetError::Io)
  ```
  This uses the process umask (no 0700/0600), no fsync, and no directory sync. `list` stops at the first malformed record (`:157`).
- impact: After a crash a preset file can be empty or torn, and then `list` fails for every preset. Permissions differ from the rest of state.
- fix: Use `kcc_app::persist::write_atomic` and `create_private_dir`, as the credential and backup stores do. Skip and log a malformed record in `list`.
- confidence: high

### SEC2-14 Log-sink clients have no timeouts, and the Elasticsearch reply body is unbounded
- severity: low
- kind: bug
- rule: http-services "timeouts on every outbound client"; DoS bounds
- evidence:
  - `crates/kcc-telemetry/src/logs/elastic_sink.rs:76` (`Client::builder().redirect(Policy::none())` with no `timeout`/`connect_timeout`).
  - `:132-135` (`response.json::<BulkResponse>()` with no cap). Same builder in `sink.rs:76`.
  - Loki error bodies are capped at 64 KiB (`loki_reply.rs:10`).
- impact: A sink that accepts the connection and never answers stalls its delivery worker indefinitely, so logs pile up and are dropped. A misbehaving sink can return a huge body that is read fully into memory.
- fix: Set `connect_timeout` and `timeout` on both builders, and read the Bulk reply through a capped reader like `loki_reply::read_body`.
- confidence: high

### SEC2-15 `CredentialStore` path methods build paths from an unvalidated router id, and their docs say otherwise
- severity: low
- kind: guideline / docs
- rule: RUST_GUIDELINES "validated constructors / newtypes"; comments that lie
- evidence: `crates/kcc-app/src/credentials.rs:316-327`
  ```rust
  /// Returns [`CredentialError::Record`] for an invalid router id.
  pub fn sealed_path(&self, router: &str, kind: CredentialKind) -> Result<PathBuf, CredentialError> {
      Ok(self.directory()?.join(kind.file_name(router)))
  }
  ```
  - `open` (`:175-196`), `exists`, `manages` and `legacy_path` have the same pattern.
  - Only `store`/`remove_kind`/`migrate` call `lock_name`, which is the validator.
- impact: Today registry ids are validated upstream, and the AEAD binding to the id prevents opening a planted file. A future caller passing `../x` would read outside `router-credentials/`. The doc promise is false.
- fix: Call `lock_name(router)?` (or take a `RouterId` newtype) at the top of every public method.
- confidence: high

### SEC2-16 Gaps in zeroizing decrypted and downloaded secrets
- severity: low
- kind: guideline
- rule: project rule (d) "Secrets live in secrecy/zeroize types"
- evidence:
  - `crates/kcc-app/src/secrets.rs:277-285`: decrypted `plaintext: Vec<u8>` goes into `String::from_utf8(plaintext)`; on error the bytes are dropped inside `FromUtf8Error` without zeroizing.
  - `kcc-config/src/ns3.rs:43-49,67-69`: `padded` and `bytes` are not zeroized on error paths. ns3 is reversible, so these bytes are effectively the password.
  - `kcc-rci/src/engine.rs:698-711`: `read_capped` grows a plain `Vec` for `download_config`, leaving realloc copies of the full config.
  - `engine.rs:561`: `bytes.expose_secret().to_vec()` for the upload.
- impact: Copies of plaintext configs and passwords stay in freed heap memory longer than the type contract promises.
- fix: Wrap the buffers in `Zeroizing<Vec<u8>>`. Pre-size `read_capped` from `Content-Length` or zeroize on growth.
- confidence: high

### SEC2-17 Two write and delete helpers follow symlinks with predictable temp names
- severity: low
- kind: security
- rule: RUST_GUIDELINES §10 file handling (TOCTOU and symlinks)
- evidence:
  - `crates/kcc/src/cli/files.rs:32-39`
    ```rust
    let temporary = path.with_extension("kcc-tmp");
    ...
    let _: &mut OpenOptions = options.create(true).truncate(true);
    ```
    Used with `fresh=false` for `migrate plan --out`, `migrate report --out` and `--report` (`cli/migrate.rs:53,105`, `migrate_apply.rs:85`).
  - `crates/kcc-app/src/credentials/wipe.rs:32-38`: `fs::metadata(path)` and `OpenOptions::new().write(true).open(path)` follow a symlinked legacy `.password` file and zero its target.
- impact: When the output is placed in a shared writable directory, another local user can pre-create `<out>.kcc-tmp` as a symlink to overwrite the victim's files. Linux's `protected_symlinks` blocks this in sticky world-writable directories; macOS has no such protection. `secure_remove` is reachable only by the same user.
- fix: Open the temp file with `create_new(true)` and a random suffix (as `persist::write_atomic` does). Use `symlink_metadata` and `O_NOFOLLOW` in `secure_remove`.
- confidence: medium

### SEC2-18 info: AEAD associated data has no record-type prefix for router passwords and account hashes
- severity: info
- kind: security
- rule: none
- evidence:
  - `crates/kcc-app/src/credentials.rs:110-112`: `Self::Password => router.to_owned()`
  - `accounts.rs:346`: `self.key.seal(&new.username, …)`
- impact: A router `home` and a user `home` share the associated data, so a sealed record can be moved between the two stores. This needs state write access and gains nothing today. Backups, presets and wizards already use prefixes.
- fix: Prefix with `router:` and `account:` (plus a migration step).
- confidence: high

### SEC2-19 info: The privilege floor ignores GID 0
- severity: info
- kind: security
- rule: none (README "refuses to run as root")
- evidence: `crates/kcc/src/privileges.rs:249-251` checks only `status.uids.contains(&0)` and never parses `Gid:` or `Groups:`.
- impact: `--user 1000:0` (the OpenShift style) runs with root-group file access.
- fix: Refuse GID 0 too, or at least log it.
- confidence: high

### SEC2-20 info: `MasterKey::load_or_create` forces the key file's parent directory to mode 0700
- severity: info
- kind: bug
- rule: none
- evidence: `crates/kcc-app/src/secrets.rs:197-198` calls `create_private_dir(parent)`, which runs `set_permissions(dir, 0o700)` on an existing directory (`persist.rs:562-566`).
- impact: `KCC_MASTER_KEY_FILE=$HOME/kcc.key` with no file yet silently changes `$HOME` to 0700. A root-owned parent returns EPERM and startup fails.
- fix: Change the mode only on directories kcc creates itself.
- confidence: high

---

## Coverage
- **Read in full:**
  - kcc-app: `secrets.rs`, `secrets/files.rs`, `credentials.rs`, `credentials/wipe.rs`, `persist.rs`, `accounts.rs`, `accounts/reset.rs`, `backups.rs`, `backups/store.rs`, `registry.rs`, `registry/{stored,auth,budgets}.rs`, `audit/{writer,append_lock}.rs`
  - kcc-rci: `outbound.rs`, `auth.rs`, `auth_digest.rs`, `auth_ndw4.rs`, `auth_token.rs`, `auth_options.rs`, `ndw4_keys.rs`, `session.rs`, `engine.rs`, `engine/background.rs`
  - kcc-config: `config_text.rs`, `quoting.rs`, `ns3.rs`, `secrets.rs`
  - kcc-catalog: `validate.rs`, `secret_value.rs`, `runtime.rs`, `cli.rs`
  - kcc-domain: `cli_token.rs`
  - kcc: `cli/{files,secret,tls,routers,redact}.rs`, `privileges.rs`, `server_tls_key.rs`
  - kcc-telemetry: `logs/{sink,elastic_sink,loki_reply}.rs`
  - Stores and presets pages: `kcc-migrate/src/presets/store.rs`, `kcc-web/src/wizard/store.rs`, `presets_page/{reveal,downloads}.rs`
- **Skimmed:**
  - `audit.rs` (lines 1-460 and 560-900)
  - `kcc-catalog/src/request.rs` (30-260)
  - `kcc-rci/src/lib.rs` (`RouterUrl`/`RciPath`/`ObjectName`)
  - `kcc-app/src/workflow_cli/command.rs`, `workflow.rs` (1240-1300), `poller.rs` (340-380), `poller/extended.rs`
  - kcc-domain: `clients/command.rs`, `clients.rs`, `dhcp/command.rs`, `dhcp.rs`, `vpn_clients/{render,change}.rs`, `router_users.rs`/`schedules.rs` (validate_token use), plus the full `format!` CLI-builder inventory via grep
  - MCP `domains/write/{clients,vpn}.rs`
  - kcc-web: `clients_pages/client_act.rs`, `config_page/text.rs`, `advanced/{preview,cli}.rs`, `router_check.rs`, `presets_page/lines.rs`
  - `kcc/src/cli/{outbound,migrate,migrate_apply,persist}.rs` (call sites), `kcc-testkit/src/anonymize.rs` (config), the reqwest, hyper-util and url sources, and the `catalog/5.1` argument kinds
- **Not read:**
  - `audit/receipt.rs`, `registry/transition_tests.rs`
  - `kcc-catalog/src/runtime/{data,query,schema,rule_tests}.rs`, `cli_grammar.rs`
  - `kcc-rci/src/session/transport.rs`
  - `kcc-telemetry/src/logs/pipeline*.rs` beyond grep
  - kcc-domain renderers (wifi, wan, policies, segments, services, firewall, routing, nat, dns) beyond the grep inventory
  - `kcc/src/cli/router_secrets.rs`
  - the remaining `presets_page/*` and `migrate_wizard/*`

## Clean
- **Sealing at rest:** fresh random 192-bit XChaCha20-Poly1305 nonce per seal; the algorithm label is checked; associated data binds every record (credentials per kind, backups per router and name, presets, wizard parts).
- **Master key:** exact 32 bytes, refused if group/other readable, generated from the OS RNG, published race-free via hard link, zeroized and redacted in `Debug`.
- **State writes:** `create_new` + 0600 + fsync + rename + directory sync; the temp file is pre-removed under the domain lock; lock and lease names are validated.
- **Backup paths:** router id and `<ts>-<reason>.txt` names are validated before any path join, so there is no traversal; `write_exclusive` never overwrites.
- **Other ids:** preset ids (`[A-Za-z0-9_-]{1,64}`) and wizard ids (`is_id`) are validated on load, save and discard.
- **RCI paths:** `RciPath` segment grammar, `RouterUrl` origin-only, `ObjectName` charset; the background `id` is the only unencoded router value and only reaches the query string.
- **Outbound:** redirects disabled on every client; DNS pinned via `resolve_to_addrs`; IPv4-mapped, compatible, NAT64 and 6to4 embedded addresses checked against metadata, unroutable and loopback; the Web and CLI pre-checks use the registry policy.
- **TLS:** SPKI pin compared in constant time with full handshake-signature verification; the CLI healthcheck pins the exact leaf and uses `no_proxy`.
- **ndw4:** endpoint path checked (`/`, not `//`, no `\`/`#`); server signature checked in constant time before the confirmation proof.
- **Argon2 for accounts:** OWASP parameters (19 MiB, t=2, p=1, v0x13); a dummy hash for unknown users; password policy is length, control characters and not equal to the username.
- **Debug and Display redaction:** `Credentials`, `Session`, `Options`, `MasterKey`, `CredentialStore`, `Account`, `Auth`, `Ndw2Challenge` session id, `RciClient`, `WireValue`.
- **CLI validation:** `quote_cli_word`/`quote_cli_text` reject control characters and escape `"` and `\`; `validate_cli` rejects quotes, `;`, `|`, `&`, `$`, backticks, `<` and `>`; secret templates require exactly one slot per secret pointer.
- **Request secrets:** `SecretValue` moves secret arguments out of printable JSON and scrubs router echoes in raw and escaped forms.
- **Reveal:** needs `RevealSecrets` plus source scope; it is audited with a line count only; preset run report downloads carry no setting values.
- **Log sinks:** https required (http only for loopback); secret files permission-checked; Loki error body capped at 64 KiB.
- **Privilege floor (Linux):** root UIDs refused; all capability sets cleared and re-verified from `/proc`; `no_new_privs` and a single thread verified.