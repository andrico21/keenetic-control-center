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
- Cloud metadata, credential, DNS and time endpoints (`169.254.169.0/24`,
  `169.254.170.0/24`, `fd00:ec2::/64`, `100.100.100.200`) are always refused.
- Host names are resolved once, every resolved address is checked, and the connection
  is pinned to the checked addresses, so a DNS answer can't swap in another target. A
  literal IPv4 or IPv6 address in the URL is checked as it is, without a lookup.
- Proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) are ignored:
  every connection goes straight to the checked address.
- Redirects are never followed.
- The policy is checked before a router profile is stored and on every connection.

Log sinks are configured only in `kcc.toml`, must use HTTPS (plain HTTP is accepted only
for a loopback test sink), ignore proxy environment variables and don't follow redirects
either.

## Secrets at rest

- **Master key.** A 32-byte key file (`KCC_MASTER_KEY_FILE`, else
  `<config dir>/kcc/master.key`) created with mode 0600. A directory kcc creates for it
  is 0700; an existing directory keeps its mode. kcc refuses
  a key file readable by group or others. Anyone with this file and the state
  directory can decrypt everything below; back it up separately.
- **Encrypted with the master key** (XChaCha20-Poly1305, a random nonce per record, and
  the record type and owner as associated data): web account password hashes
  (`account:<username>`), configuration backups (`backup:<router>:<file>`), stored
  presets (`preset:<id>`), migration sources and typed migration passwords
  (`migration:<id>:source`, `migration:<id>:passwords`, `preset-run:<id>:preset`) and
  every router credential given to the Web UI or to `kcc router add/edit`. Managed router
  records are `<state>/router-credentials/<id>.sealed` (password, `router:<id>`),
  `<id>.token.sealed` (login token, `router:<id>:token`) and `<id>.read.sealed`
  (read-only polling password, `router:<id>:read`), JSON records of schema 2. Every
  record type has its own prefix and router ids hold no `:`, so a value copied into a
  record of another type, owner or kind fails to open. A migration that changes the
  management password of a Web UI or CLI router seals the new password the same way.
- **Sealed state of earlier builds is not readable.** kcc has no deployments to carry
  over, so there is no upgrade path: a router credential record of schema 1 is refused as
  an unsupported record, and a web account password hash sealed by an earlier build
  (bound to the bare username) does not open, so signing in to that account fails with an
  error (the Web UI answers a server error, not "invalid username or password") and its
  sessions end. Backups, presets and migration runs keep their associated data.
- **Hashed**: web account passwords (Argon2id) and API keys (Argon2id, the key is shown
  once and never stored).
- **Operator-managed files**: `password_file`, `read_password_file` and `token_file`
  paths of `kcc.toml` routers remain files controlled by the operator and are read
  unchanged; kcc does not copy them into state, and a migration that changes such a
  router's password rewrites its `password_file` (mode 0600). CLI `--password-file`,
  `--token-file` and `--read-password-file` given to `kcc router add/edit` are input
  only: the contents are sealed and the file is never referenced again. A Web UI or CLI
  router stored by an older kcc that still names an external password file keeps
  working; the CLI and `kcc serve` warn about it once per run with the
  `kcc router edit <id> --new-password --password-file <file>` command that seals it,
  and kcc never deletes or rewrites that file.
- **Owner-only secret files.** On Unix kcc applies the master-key rule to every secret
  file it reads: router `password_file`, `read_password_file` and `token_file`, CLI
  `--password-file`, `--current-password-file`, `--token-file` and
  `--read-password-file` input, WireGuard `.conf` imports, log
  sink `password_file`, `bearer_token_file` and `api_key_file`, and `[server]
  tls_key_path`. A file group or others can access (any bit of mode 077) is refused
  before it is read: the router connection or `kcc serve` startup fails, and a CLI
  command exits 3, naming the file and the `chmod 600` that fixes it. The file contents
  never reach logs or errors. Modes 0600 and 0400 (the Podman secret mounts) pass.
  Windows has no mode check, as for the master key.
- **Private files.** State files, preset records and CLI output files (`kcc migrate plan
  --out`, `kcc migrate report --out`, `kcc migrate apply --report`) are written to a new
  owner-only temporary file in the same directory, synced and renamed into place. The
  temporary file is created exclusively (CLI output files get a random name), so a
  symbolic link or a file planted there is never followed or reused; a CLI output path
  that is a symbolic link is refused.
- **Migration and recovery**: startup and first CLI use seal, reopen and compare legacy
  `<id>.password` files before overwriting and unlinking them. Only a regular file is
  overwritten; a symbolic link there is unlinked without touching the file it names. A wrong/corrupt key,
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
  `SameSite=Strict`, `Path=/`, and `Secure` with the `__Host-` prefix when the browser reaches kcc over TLS:
  either the listener has TLS, or `[web] public_url` is an `https` URL (the HTTPS reverse
  proxy). The CSP gains `upgrade-insecure-requests` in the same cases. Only plain HTTP on
  loopback uses the unprefixed cookie without `Secure`.
- Sessions end after `[web] session_idle` (30 minutes) of inactivity and
  `session_absolute` (12 hours) after login. Login replaces the session id. Your own
  password change also moves your session to a new id and CSRF token (the login time,
  and so the 12-hour limit, stays); a password or role change ends the account's other
  sessions.
- Opening the login page without a session creates a session before login. These end
  after 5 minutes without use (or `session_idle`, if shorter). kcc holds at most 64 of
  them per client address and 10 000 in total; one more evicts the oldest (of that
  address when it holds 64, otherwise of anyone), so a flood of login-page requests
  cannot grow memory without bound and never ends a signed-in session. The client
  address is the one kcc's rate limiter uses: the direct peer, or the forwarded client
  when the peer is in `[server] trusted_proxies`. An evicted or expired login form is
  refused with 403 on submit; reloading the login page gives a new one.
- `kcc serve` checks `api_keys.json` and `users.json` every 2 seconds, so a change made
  outside the server (the CLI, an edited or restored state file) applies within about
  2 seconds without `SIGHUP`: a revoked key is refused, and the Web sessions of an
  account that was deleted or disabled, got another role, or got another password end.
  Your own password change keeps the session you made it in (under its new id). A rewrite that changes no
  key, role, disabled flag or password (a key's last-use time) reloads nothing. A file
  kcc cannot read keeps the last good state, logs one warning and is retried.
- Live views (fleet, dashboard, router log, interface traffic, job and apply progress)
  are server-sent event streams, at most 4 per session. Each stream checks its session
  again before every event and at least every 5 seconds, and ends when the session is
  gone (logout, expiry, an account change that ends it) or its role no longer is the one
  the stream opened with (a role edit, or a `SIGHUP` reload that changes it). A stream
  also ends at the session's absolute expiry. These checks do not count as use: an open
  live view alone does not keep a session from its idle timeout.
- Every state-changing request needs the session-bound `X-CSRF-Token` header, exactly
  one allowed `Origin` and a same-origin `Sec-Fetch-Site`.
- `[web] login_max_failures` failed logins (5) lock the account for `lockout`
  (15 minutes). Failed logins answer with one generic message, HTTP 422, in the sign-in
  page's language. An unknown name, a disabled account and a locked one run the same
  Argon2id work as a wrong password, so the answer's timing does not tell them apart.
- A login checks the password without holding the `users.json` lock and writes the file
  only when the account's failure count or lockout changes; simultaneous failed logins
  each count once. At most one Argon2id run per CPU kcc may use goes on at a time (each
  takes 19 MiB), for logins, password changes and new passwords alike; more wait.
- The HTTP layer also checks `Origin` against the Web UI listener and
  `[web] public_url` origins derived by kcc, plus any extra trusted origins in
  `[server] allowed_origins` (see [CONFIG.md](CONFIG.md)).

## Permissions (RBAC)

Permissions are Read, Write, Save, Destructive, Migrate, RawRci, RevealSecrets,
ManageRouters, ManageUsers and ViewAudit. Built-in roles: `viewer` (Read), `operator`
(Read, Write, Save, Migrate) and `admin` (everything); custom roles add router-name
globs. Every front end checks the exact permission and router scope before any router
request, and the change workflow checks again. Raw router answers (explorer, consoles,
`kcc show`, `kcc rci`, the MCP raw tools) show stored secrets only to a role holding
RevealSecrets on that router; every other role sees them redacted. A user can grant
(to an account or an API key, in the Web UI or the CLI) only roles whose permissions and
routers they hold; the CLI principal's routers are its role's scope narrowed by `[cli]
router_scope`. A custom role cannot be deleted while an account or API key holds it, and
the last enabled admin can't be removed. A background job (a diagnostic, an explorer
background command, the component commit) can be followed or stopped only by the user
who started it or a role holding ManageUsers on its router; to anyone else it answers
like a missing job, and job ids are 128 random bits.

`Migrate` permits planning and reviewing migrations, presets and settings copies. A stored
preset belongs to the scope of its source router: only a role holding `Migrate` there may
open, apply, delete or recapture (replace) it, a damaged record only a role scoped to
every router, and to every other role it answers like a missing preset. Every
apply is authorized before any router request by one function shared by the CLI, the Web
UI and MCP: `Read`, `Migrate`, `Write` and `Save` cover the initial workflow read, the
replay, the keep or save finish, and the recovery timer, which the engine arms, keeps
alive and disarms under the run's `Migrate`. `Destructive` is added only when the apply
installs components (the component commit reboots the router), restores a saved
configuration as it is (the router restarts), or is told up front to finish with a
rollback. The built-in `operator` role can therefore apply and keep or save; a role
without `Migrate` still cannot apply. Recovery after a failed apply (a rejected or
indeterminate line, a failed verification) needs nothing more: kcc either waits out the
armed timer and verifies the restored configuration by reads, or rolls the failed run
back under its own `Migrate`.

`Destructive` stays required for an explicit, user-chosen rollback finish (`kcc migrate
finish rollback`, `kcc preset finish <run> rollback`, `--finish rollback`, the Web UI's
rollback buttons, `kcc_migration_finish` with `rollback`) and for explicit standalone
timer control: `kcc config failsafe arm|rollback`, `kcc config keep-alive`, and the Web
UI's standalone rollback on the configuration page. These checks also happen before any
router request.

MCP adds its own gates: write tools need their toolset enabled in `[mcp] toolsets`,
`[mcp] read_only = true` registers only read tools, and destructive tools, and raw management changes, also need
`[mcp] allow_destructive = true` plus `confirm: true`. `kcc mcp stdio` bypasses HTTP
authentication by design, so it's off by default and runs as `[mcp] stdio_role`.

Raw request risk is the maximum risk of every command node visited in its nested
body, including virtual prefixes and ancestors. Moving a destructive or management
command from the request path into its body does not lower its risk or remove the
corresponding permission and confirmation checks. A raw delete is always destructive and
needs the same permission. POST `"no": true` and CLI `no <command>` removals have
the same destructive risk floor as DELETE. Whole-path root keys, such as
`{"system reboot":{}}`, retain each command prefix's risk and the leaf's persistence.
An empty root object is read-only. An empty object at a virtual namespace (a catalog
path prefix that is not itself a command) contributes Write risk and an ordinary
change leaf. This rule applies per subtree, including beside a Show command in the
same item; accepted namespace changes are reported and audited as `applied_unsaved`.
Nonempty namespaces defer to their descendants. `{"show":{}}` remains Read because
`show` is itself a catalogued Show command; `{"show":{"clock":{}}}` is Write because
`show clock` is only a namespace, while `show clock date` remains Read. A nonempty
unclassified body also fails closed as a write. These are conservative authorization
and accounting rules, not claims about a real router's effect for an empty namespace.

All mutating raw MCP tools, including `kcc_cli_parse`, require `RawRci` and the router
scope, plus the `Destructive` permission when the request's risk is destructive. A
management or destructive request also needs explicit confirmation and the server
switch. A role that may make a management change may also arm and disarm the recovery
timer around it, so management risk alone never needs `Destructive`. Preliminary authorization uses the maximum risk
from every embedded firmware catalog that accepts the input; router-specific validation
still runs afterwards. A management node always requires the recovery timer, including
when a destructive sibling determines the request's maximum risk. This applies to raw
MCP, CLI and Web requests; curated operations retain their domain plans and gates.

Raw classification is deliberately coarser than curated classification: interface
firewall bindings, access-list rules, security levels and bridge membership changes always have Management
risk, regardless of the interface's current role. SSH, Telnet, HTTP service toggles and
cloud-control exposure likewise protect management access. Curated firewall operations
can still classify an ordinary interface as Write using runtime topology. Raw recovery
timer and keep-alive commands are Destructive instead: they control recovery itself and
must not be automatically disarmed by an enclosing management bracket. IPv6 access-group
commands are not present in the embedded catalogs and remain rejected by validation.

Whole-interface creation and removal are Management changes: creation fails closed because
raw classification has no runtime topology with which to prove that the new interface cannot
replace a management path. A removal stays Management when its body also carries sibling
leaves. Operating-mode switches are Management changes too. Raw `interface <name> up` and
`interface <name> down` are Management for every interface, including WAN ports and secondary
access points, because raw classification cannot prove which interface carries management.
Raw interface
role, IPv4 or IPv6 address, DHCP-client route, global-route priority, MAC address/clone and
IPv4 static route changes are also Management because any of them can replace the address,
return route or link identity through which kcc reaches the router. The raw classification
works on the command path, so it cannot tell a default route from any other static route:
every raw `ip route` item has Management risk and runs under the recovery timer, while the
curated routing operation remains an ordinary Write. The `no`, DELETE or CLI-removal
spellings of all of these keep the Destructive floor (they need `Destructive` and the
server switch) while still running under the recovery timer. Client hotspot deny/policy selection and DNS-proxy assignment remain ordinary Write:
they affect client forwarding or name resolution, not kcc's management path. Interface
description, SSID, radio/RF settings, MAC band/BSSID/VHT tuning and other non-address
interface writes likewise remain ordinary Write and run without the recovery timer; the
`interface` command is only their structured ancestor and does not raise their risk. The
deliberate raw over-classification as Management, which runs under the recovery timer, therefore covers
every interface creation/removal and up/down operation, every static route, and the raw
interface security, address, route, identity, membership, role, access-group and schedule
families listed above, even when runtime topology could prove a particular target ordinary.
Interface schedules
are Management on the raw route because applying a schedule can disable the management access
point, and the CLI-line and structured spellings receive the same verdict.

The recovery mechanism of every bracket (Web, CLI, MCP, migration, presets) comes from one
rule applied to the system mode and `show last-change` that the change set read when it
began, never from a cache: router mode arms the native fail-safe timer; extender,
access-point and repeater modes arm a scheduled reboot; a router that reports no mode
(KeeneticOS 4.3 and 5.0, read-only credentials) gets the native timer only when its
`fail-safe` object has a boolean `active` member. A mode kcc does not know, or an
unreported mode without that object, is refused before anything is sent: exit code 10
on the CLI, `router_mode_unknown` over MCP, a refusal message in the Web UI and
`ModeUnknown` for migration and preset applies. The timer is 300 seconds on every surface.

The recovery timer kcc arms, keeps alive or disarms around a management change is
authorized by that change's own permission (`Write` for curated and raw changes,
`Migrate` for migration, preset and settings-copy runs), so a role that can open a
bracket can close it; persistence still requires `Save`. Curated MCP management writes use the same mode-aware bracket
as raw writes, with their existing confirmation policy. After arming succeeds, any
unsuccessful cleanup reports that recovery remains armed and will restore the saved
configuration, discarding all unsaved router changes. A batch's recovery message reports
the management subset as applied only when at least one management change item succeeded;
successful ordinary siblings and reads do not count. A partial batch retains its item
refusals and identifies only the successful changes as applied. When every management
change is refused, the refusal information accompanies the unknown-outcome armed-timer
message. CLI batch refusals retain exit 7 and item output even when cleanup fails (an
applied batch with failed cleanup exits 6). In `--json` mode, the error object adds
`fail_safe_armed: true` and uses the same localized recovery message. MCP recovery
errors retain the batch's `responses`, including `ok: false` items. Web retains the
router's refusal text and reserves loss-of-connectivity wording for transport failures.
Successful cleanup preserves the original work error without an armed note.
The failed-change audit parameters include `fail_safe_armed: true` when recovery
remains armed. Curated interface changes (up, down, description, security level) run
inside the same surface bracket as every other management change, with the recovery
mechanism of the router's mode and the change's own `Write` permission: after refused or
failed work it disarms, and it reports the armed timer only when that cleanup cannot be
confirmed. No permission failure is described as loss of router connectivity.

Migration and preset closing steps preserve the same armed fact when commit, save or
explicit rollback fails before disarm can be confirmed. Their failed CLI, MCP and Web audit entries
include `fail_safe_armed: true` without setting values. The CLI exits 6; MCP finish
returns `management_outcome_unknown_fail_safe_armed`. A lost native commit reply is
reported conservatively even if the router actually committed. A confirmed save
followed by failed disarm is identified as saved: scheduled recovery then reloads the
new saved configuration, rather than promising to restore the pre-migration state.
When a late role edit removes `Save`, MCP reports
`management_not_committed_fail_safe_armed`: no commit request was sent, the timer is
still armed, and the migration is retained for retry.
When native commit is confirmed but its following startup save fails, MCP reports
`management_applied_not_saved` and keeps the finish retryable instead of claiming that
nothing changed.

Runtime management risk belongs to `kcc-domain`: firewall plans classify every
affected interface and treat failed discovery as management risk; every WAN setting
classifies its connection; HTTP, SSH and Telnet service toggles carry the same risk as
the Web's existing policy. Detection compares interface addresses with the addresses the
RCI client pinned when it connected (no second DNS lookup), and a bridge or bridge member
whose evidence cannot decide counts as management. A change that would move, close or
redirect the listener of the router profile's URL is refused before any request. CLI, MCP
and Web consume that shared classification for confirmation and recovery. Curated
MCP planned writes enter a common executor that selects recovery from `ChangeOp`.

Role changes take effect without a restart. A custom role created, edited or reduced in
the Web UI, or changed in `roles.json` followed by `SIGHUP`, binds the next MCP call (the
transport's RBAC and the MCP handlers' own permission and scope checks share one role
set) and the next Web UI request of every signed-in session holding it; an open live
view of such a session ends within 5 seconds.

The last use of an API key is recorded on its next MCP tool call, at most once a minute
per key; failed authentication records nothing. The firmware-update check sends the
catalog-validated `components check-update` action, which changes no configuration,
outside the change workflow and without an audit entry.

## Audit chain

Root batch completion follows the ordered per-item router responses, including
error statuses inside HTTP 200. Only successful items contribute persisted paths
and unsaved-change flags. Reads are never counted as applied or unsaved changes.
Fully successful batches retain `applied_persisted` when
every successful command persists immediately, otherwise `applied_unsaved`.
A batch with no applied changes and a refusal records `failed`. Partial batches record
`partially_applied_persisted` or `partially_applied_unsaved` using the same rule for
the successful subset. Failed and partial batch parameters contain only
`error: "router_rejected"`, `succeeded` and `failed` counts, never request values.
The CLI returns exit code 7 for any item refusal and prints a localized refusal
note instead of a completed-change note. MCP retains each item's `ok` result and
derives its persistence notice from successful items only.

Every change, handler-level refusal, login and secret reveal appends an entry to
`audit.jsonl`. MCP records successful changes, failed changes as `failed` with an error
kind, and each refusal that reaches a kcc handler as `forbidden` or `refused` with a
reason. The CLI and MCP share one format for these attempts: outcome `forbidden`
(`reason: "forbidden"`), `refused` (a `reason` code; the CLI records a missing
confirmation as `refused` with `reason: "confirm_required"` and an apply onto a router
whose lease another process holds as `refused` with `reason: "router_busy"`) or
`failed` (an `error` code), plus `fail_safe_armed: true` only when the recovery timer
may still be armed.
The Web records a change that may have left the timer armed, and a failed migration or
preset finish, the same way: outcome `failed` with its `error` code, plus
`fail_safe_armed: true` when the timer may still be armed. Refusals are audited per
call; there is no per-key MCP tool-call rate limit, and audit retention is age-based. Over HTTP, rmcp-server-kit's role check also applies the
router scope to the `host` argument. A denied tool or out-of-scope `host` is refused with
HTTP 403 before kcc code runs; the kit logs `user`, `role`, `tool` and `host` at warn
level, but that event is not appended to the hash-chained audit. Stdio calls, and HTTP
calls whose routers are named in other arguments such as `source` or `target`, reach
kcc's own scope check and are audited. The audit entry's `router` field names the router
the call addressed first; it is not necessarily the router whose scope check refused the
call. Each audit entry carries a sequence number and
`sha256(previous hash || canonical JSON of the entry)`, so editing or removing an entry
breaks the chain; `kcc audit verify` names the first broken sequence. Entries never hold
secret values. Appends from several processes
(`kcc serve`, CLI runs, `kcc mcp stdio`) take a cross-process lock on the log and
re-read its tail before writing, so they extend one chain. Files rotate at 50 MiB. The
chain detects tampering; it doesn't prevent someone with write access to the state
directory from rewriting the whole log.

The append lock uses a longer bounded backoff with per-process phase jitter. Mutual
exclusion still covers tail verification and the complete durable append, so contention
cannot fork the chain. A busy lock never drops an entry: the one writer of each process
keeps it at the head of its queue and retries until the lock is free, so entries are
written in the order they were submitted, and the sequence number and previous hash are
assigned under the lock. Chain, serialization, join, or log I/O failures terminate the
writer. New router work is then refused before its first router request, and `kcc serve`
exits non-zero so its supervisor can restart it.

Audit guarantees: while the process runs, every entry is kept and written in order; an
entry is lost only if the writer fails or the process exits first (`kcc serve` and `kcc
mcp stdio` give the writer 5 s at exit and log the count of entries still queued; a CLI
run exits right after its change). Callers wait for their entry a bounded time (30 s for
a change; inside a management change's recovery bracket the disarm is sent without
waiting, then the bracket waits 20 s). A change the router applied whose entry is still
queued is reported as done with a note that the entry will be written once the audit log
is free, never as a router failure. A Web sign-in waits at most 5 s for its entry, then
signs the user in with the entry still queued.

Keep the shipped production filter `info,rmcp=warn,rmcp_server_kit=info`. Raising the
`rmcp` target above `warn` makes the MCP SDK log tool arguments at debug or trace,
including secret fields.

## Privilege floor

kcc refuses to run as root, under sudo, or elevated on Windows, and exits with code 77
before reading any configuration. On Linux it also clears its capability sets and sets
`no_new_privs`. kcc never starts subprocesses.

A root group (GID 0) is not refused, because platforms such as OpenShift run unprivileged
containers with GID 0. kcc logs a warning when any real, effective, saved-set or
filesystem GID is 0. Once tracing starts, kcc logs the applied floor: the real UID, whether
the capability bounding set was cleared, and the bounding mask that remains.

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
