# Security

This document describes what kcc protects, against whom, and where its limits are.

## Assets and actors

kcc holds the keys to a fleet of routers: router passwords, API keys for AI
assistants, encrypted backups that contain every router secret, and the right to change
or reset those routers. The actors are:

- **Web UI users and MCP clients**, authenticated and limited by role.
- **AI assistants**, which act through MCP with an API key and may be steered by text
  they read (prompt injection). Treat them as untrusted users of their key's role.
- **The LAN**, where routers usually live and where other devices can observe or
  impersonate traffic.
- **Local users** on the kcc host.

## Outbound policy (LAN SSRF stance)

kcc's job is to make HTTP requests into private networks, so it must not become a
proxy into them for whoever controls a router URL. Every router connection goes through
one policy in `kcc-rci`:

- A router address must fall inside `[outbound] allowed_networks` or match an
  `allowed_suffixes` host-name suffix. The default lists are empty, so no router is
  reachable until you list your networks.
- Loopback addresses need `allow_loopback = true` (test setups only).
- Cloud metadata addresses (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`) are
  always refused.
- Host names are resolved once, every resolved address is checked, and the connection
  is pinned to the checked addresses, so a DNS answer can't swap in another target.
- Redirects are never followed.
- The policy is checked before a router profile is stored and on every connection.

Log sinks are configured only in `kcc.toml`, must use HTTPS (plain HTTP is accepted only
for a loopback test sink) and don't follow redirects either.

## Secrets at rest

- **Master key.** A 32-byte key file (`KCC_MASTER_KEY_FILE`, else
  `<config dir>/kcc/master.key`) created with mode 0600 in a 0700 directory. kcc refuses
  a key file readable by group or others. Anyone with this file and the state
  directory can decrypt everything below; back it up separately.
- **Encrypted with the master key** (XChaCha20-Poly1305, a random nonce per record, the
  owner name as associated data): web account password hashes, configuration backups,
  stored presets, migration sources, typed migration passwords and router passwords
  entered through the Web UI or CLI. Managed router records are
  `<state>/router-credentials/<id>.sealed`, with the router id as associated data.
- **Hashed**: web account passwords (Argon2id) and API keys (Argon2id, the key is shown
  once and never stored).
- **Operator-managed files**: `password_file`, `read_password_file` and `token_file`
  paths supplied in configuration or with `--password-file` remain files controlled by
  the operator and are read unchanged; kcc does not copy them into state.
- **Migration and recovery**: startup and first CLI use seal, reopen and compare legacy
  `<id>.password` files before overwriting and unlinking them. A wrong/corrupt key,
  damaged record or comparison failure leaves plaintext in place and fails closed.
- **Backup and restore**: back up the master key separately from state. Restoring only
  state makes sealed credentials, backups and presets unrecoverable; restoring only the
  key provides no secrets. `KCC_MASTER_KEY_FILE` selects the key location.
- **Windows ACLs**: kcc requests protected owner-only DACLs for the key and every state
  file/directory. This Windows-only path is not executable or verified on the Linux host
  used for this change.

## Secrets in transit

- **Web UI and MCP.** Plain HTTP is accepted only on a loopback listener. Any other
  listener needs TLS (`[server] tls_cert_path`/`tls_key_path`) or an https
  `[web] public_url` behind `[server] trusted_proxies`; kcc refuses to start otherwise.
- **RCI to the router.** Routers usually offer plain HTTP on the LAN. kcc's ndw2/ndw4
  sign-in is a challenge-response, so the password itself isn't sent, but the session
  cookie, every configuration read (including encrypted `ns3` blobs and Wi-Fi keys in
  responses) and every secret kcc writes (Wi-Fi keys, VPN keys, user passwords) cross
  the LAN in clear text over HTTP. Anyone on that network path can read them and can
  hijack the session.
- **Prefer HTTPS.** Use an `https://` router URL. With `tls = "verify"` the certificate
  must chain to a trusted root; routers usually have self-signed certificates, so pin
  the certificate's public key instead (`tls = { pin_sha256 = "..." }`, or
  `--pin-sha256` in `kcc router add`). A pin stops a LAN attacker from impersonating
  the router.

## Sessions and CSRF

- Session ids and CSRF tokens are 32 random bytes. Cookies are `HttpOnly`,
  `SameSite=Strict`, `Path=/`, and on TLS listeners `Secure` with the `__Host-` prefix.
- Sessions end after `[web] session_idle` (30 minutes) of inactivity and
  `session_absolute` (12 hours) after login. Login replaces the session id; a password
  or role change ends the account's other sessions.
- Every state-changing request needs the session-bound `X-CSRF-Token` header, exactly
  one allowed `Origin` and a same-origin `Sec-Fetch-Site`.
- `[web] login_max_failures` failed logins (5) lock the account for `lockout`
  (15 minutes). Failed logins answer with one generic message.
- The HTTP layer also checks `Origin` against the Web UI listener and
  `[web] public_url` origins derived by kcc, plus any extra trusted origins in
  `[server] allowed_origins` (see [CONFIG.md](CONFIG.md)).

## Permissions (RBAC)

Permissions are Read, Write, Save, Destructive, Migrate, RawRci, RevealSecrets,
ManageRouters, ManageUsers and ViewAudit. Built-in roles: `viewer` (Read), `operator`
(Read, Write, Save, Migrate) and `admin` (everything); custom roles add router-name
globs. Every front end checks the exact permission and router scope before any router
request, and the change workflow checks again. A user can grant only roles whose
permissions they hold, and the last enabled admin can't be removed.

MCP adds its own gates: write tools need their toolset enabled in `[mcp] toolsets`,
`[mcp] read_only = true` registers only read tools, and destructive tools also need
`[mcp] allow_destructive = true` plus `confirm: true`. `kcc mcp stdio` bypasses HTTP
authentication by design, so it's off by default and runs as `[mcp] stdio_role`.

Role changes take effect without a restart. A custom role created, edited or reduced in
the Web UI, or changed in `roles.json` followed by `SIGHUP`, binds the next MCP call (the
transport's RBAC and the MCP handlers' own permission and scope checks share one role
set) and the next Web UI request of every signed-in session holding it.

The last use of an API key is recorded on its next MCP tool call, at most once a minute
per key; failed authentication records nothing. The firmware-update check sends the
catalog-validated `components check-update` action, which changes no configuration,
outside the change workflow and without an audit entry.

## Audit chain

Every change, refusal, login and secret reveal appends an entry to `audit.jsonl`. Each
entry carries a sequence number and `sha256(previous hash || canonical JSON of the
entry)`, so editing or removing an entry breaks the chain; `kcc audit verify` names the
first broken sequence. Entries never hold secret values. Appends from several processes
(`kcc serve`, CLI runs, `kcc mcp stdio`) take a cross-process lock on the log and
re-read its tail before writing, so they extend one chain. Files rotate at 50 MiB. The
chain detects tampering; it doesn't prevent someone with write access to the state
directory from rewriting the whole log.

## Privilege floor

kcc refuses to run as root, under sudo, or elevated on Windows, and exits with code 77
before reading any configuration. On Linux it also clears its capability sets and sets
`no_new_privs`. kcc never starts subprocesses.

## Container hardening

The OCI image ([deploy/podman/README.md](../deploy/podman/README.md)) runs a static
binary on a distroless base as UID 65532 with a read-only root file system, no
capabilities, `no-new-privileges`, memory and process limits, and a seccomp allowlist
traced from the binary's real system calls (`deploy/podman/seccomp-kcc.json`). The
Prometheus listener is unauthenticated and stays on loopback unless
`[metrics] allow_non_loopback = true`.

## Out of scope

- A compromised kcc host or a stolen master key with the state directory.
- Router firmware vulnerabilities.
- Traffic between routers and their clients.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability reporting on
the repository (Security, Report a vulnerability). Don't open a public issue with
details. Include the kcc version (`kcc --version`), the affected front end and the
steps to reproduce, and never attach real router configurations or secrets.
