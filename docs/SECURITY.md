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

The Telegram notifier is the other non-router destination. Its Bot API base URL comes
only from `[notify.telegram] api_url` in `kcc.toml` (the Web UI, MCP and state files can't
set it) and must use HTTPS, or plain HTTP to a loopback host. Its client ignores proxy
environment variables, follows no redirect (a redirect counts as a failed attempt) and
resolves the host itself, dropping every address that no outbound-policy setting could
admit (cloud metadata, unspecified, multicast and broadcast addresses); a literal address
of that kind is refused outright. It calls only `sendMessage` and never receives anything
from Telegram. The bot token travels in the request URL path, so kcc never logs a request,
its URL or its body, and strips the URL from every HTTP client error before mapping it to
a plain delivery outcome. The token is sealed under the master key; the Web page and
`kcc notify show` only say whether one is set, and audit entries record that it changed,
never its value.

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
  (`migration:<id>:source`, `migration:<id>:passwords`, `preset-run:<id>:preset`), the
  Telegram bot token (`notify:telegram`, in `<state>/notify/telegram.token.sealed`) and
  every router credential given to the Web UI or to `kcc router add/edit`. Managed router
  records are `<state>/router-credentials/<id>.sealed` (password, `router:<id>`),
  `<id>.token.sealed` (login token, `router:<id>:token`) and `<id>.read.sealed`
  (read-only polling password, `router:<id>:read`), JSON records of schema 2. Every
  record type has its own prefix and router ids hold no `:`, so a value copied into a
  record of another type, owner or kind fails to open. A router's SSH state lives in
  `<state>/router-ssh/` as `<id>.sealed` (enrolment record, `router:<id>:ssh-state`),
  `<id>.key.sealed` (kcc's private key, `router:<id>:ssh-key`) and `<id>.ticket.sealed`
  (single-use probe ticket, `router:<id>:ssh-ticket`), and router removal deletes them.
  The signing key of kcc's own MCP sign-in (Ed25519) is sealed as
  `<state>/mcp/oauth-signing.sealed` (`mcp:oauth-signing`) and never rotated.
  A migration that changes the management password of a Web UI or CLI router seals the
  new password the same way.
- **Sealed state of earlier builds is not readable.** kcc has no deployments to carry
  over, so there is no upgrade path: a router credential record of schema 1 is refused as
  an unsupported record, and a web account password hash sealed by an earlier build
  (bound to the bare username) does not open, so signing in to that account fails with an
  error (the Web UI answers a server error, not "invalid username or password") and its
  sessions end. Backups, presets and migration runs keep their associated data.
- **Hashed**: web account passwords (Argon2id) and API keys (Argon2id, the key is shown
  once and never stored). An API key may carry an expiry, checked on every MCP request;
  an expired key is refused with HTTP 401.
- **Operator-managed files**: `password_file`, `read_password_file` and `token_file`
  paths of `kcc.toml` routers remain files controlled by the operator and are read
  unchanged; kcc does not copy them into state. A migration that changes such a
  router's password rewrites its `password_file` (mode 0600) while the router stays at
  its address; one that would move it to another address is refused before anything is
  written, because the new address could be kept in memory only. Set the `url` in
  `kcc.toml` and reload instead. CLI `--password-file`,
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
- **Windows ACLs**: kcc makes the process user the owner of the key and of every state
  file and directory and gives each a protected DACL with one ACE: full access for OWNER
  RIGHTS. Nothing is inherited from the parent directory; a state directory's ACE is
  inherited by the entries created inside it. A failure to apply this is an error, never
  a fallback to the default permissions.

## Secrets in transit

- **Web UI and MCP.** Plain HTTP is accepted only on a loopback listener. Any other
  listener needs TLS (`[server] tls_cert_path`/`tls_key_path`) or an https
  `[web] public_url` behind `[server] trusted_proxies`; kcc refuses to start otherwise.
  The Entware root password typed on the Entware page's SSH enrolment therefore reaches
  kcc only over TLS or loopback; it is used once for the password session that installs
  kcc's key and is never stored, logged, audited or shown again.
- **RCI to the router.** Routers usually offer plain HTTP on the LAN. kcc's ndw2/ndw4
  sign-in is a challenge-response, so the password itself isn't sent, but the session
  cookie, every configuration read (including encrypted `ns3` blobs and Wi-Fi keys in
  responses) and every secret kcc writes (Wi-Fi keys, VPN keys, user passwords) cross
  the LAN in clear text over HTTP. Anyone on that network path can read them and can
  hijack the session. kcc keeps one session per login and signs the read-only polling
  sessions and background-operation sessions out of the router when they end.
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
- Wizard runs (migration, presets and copy settings) are opened only by the account
  that started them; kcc keeps a run's in-memory side only after that check, so another
  user's requests cannot push it out. A user keeps at most 10 unfinished runs of each
  wizard (a run unchanged for a day no longer counts), and runs unchanged for 30 days are
  deleted, so run directories cannot fill the state disk without bound. A run's sealed
  source, copied settings and typed passwords are deleted when it finishes or expires and
  after a day without a change; choosing the source or target again deletes its typed
  passwords. An apply holds the
  target router (the Web wizard's reservation and the change workflow's write lease) only
  until it is finished or the router's fail-safe interval has passed; MCP finishing
  stays limited to the identity that planned the migration.
- Every state-changing request needs the session-bound `X-CSRF-Token` header, exactly
  one allowed `Origin` and a same-origin `Sec-Fetch-Site`.
- `[web] login_max_failures` failed logins (5) lock the account for `lockout`
  (15 minutes). Failed logins answer with one generic message, HTTP 422, in the sign-in
  page's language. An unknown name, a disabled account and a locked one run the same
  Argon2id work as a wrong password, so the answer's timing does not tell them apart.
  A username that breaks the account name rule (1 to 64 bytes of `a-z`, `0-9`, `.`, `_`,
  `-`) is refused like an unknown name; its audit entry names the fixed
  actor `<invalid-username>`, so a failed login cannot write submitted text to the log.
- A login checks the password without holding the `users.json` lock and writes the file
  only when the account's failure count or lockout changes; simultaneous failed logins
  each count once. At most one Argon2id run per CPU kcc may use goes on at a time (each
  takes 19 MiB), for logins, password changes and new passwords alike; more wait.
- The HTTP layer also checks `Origin` against the Web UI listener and
  `[web] public_url` origins derived by kcc, plus any extra trusted origins in
  `[server] allowed_origins` (see [CONFIG.md](CONFIG.md)).

## Permissions (RBAC)

Permissions are Read, Write, Save, Destructive, Migrate, RawRci, RevealSecrets,
ManageRouters, ManageUsers, ViewAudit, ManageNotifications, ManageSchedules and
ManageMcp. Built-in roles: `viewer` (Read), `operator` (Read, Write, Save, Migrate) and
`admin` (everything); custom roles add router-name globs. ManageNotifications,
ManageSchedules and ManageMcp, which open the notification, scheduled-action and MCP
settings pages (`/ui/admin/notifications`, `/ui/admin/scheduled`, `/ui/admin/mcp`),
belong to `admin` only by default. The role name `kcc-account` is reserved: no custom
role may use it, and the RBAC layer always holds it with every tool on every router for
MCP clients signed in with a kcc account, whose own role is checked on every call. A role
the MCP settings name (`stdio_role`, `[mcp.auth.mtls] default_role`, an OIDC mapping
target) must be one the configuring admin's role covers, and cannot be deleted while
named. Whoever decides where those identities come from must cover every role they get,
not only the roles the change names: re-pointing the identity provider (issuer, audience,
JWKS URL, role claim), switching a listener to it or replacing its CA bundle needs a role
covering every mapping target (kcc.toml mappings included), and switching a listener to
client certificates or replacing the client CA needs a role covering the certificates'
role. A scheduled action also needs
the permissions of the action itself on its router, when it is created and again when it
runs: a policy switch needs Write; a backup needs Write; a reboot needs Destructive; a
preset needs Read, Migrate, Write and Save on the target router, plus Read and Migrate
on the preset's source router when it names one. Every front end checks the exact
permission and router scope before any router request, and the change workflow checks
again.

A scheduled run acts as audit actor `system`/`schedule:<id>` (no actor kind of its own)
with its owner's authority as it is when the run starts, not when the schedule was
created: a Web owner's account must exist and be enabled and its role is read from the
roles in force; a CLI owner uses the `[cli] role` and `[cli] router_scope` of the
`kcc.toml` the server loaded. A missing, disabled or out-of-scope owner pauses the
schedule (`owner_unavailable`); a role without ManageSchedules or a permission of the
action on the router pauses it (`forbidden`); either pause is audited (`schedule.pause`)
and reported, and nothing is sent to the router. Each slot runs at most once: the run is
recorded as started in `schedule_runs.json` (one locked update that also marks the slot
fired) before the first router request, a slot at or before the last fired one is
dropped (so a wall clock stepped back repeats nothing), and a run found started when a
server starts is marked interrupted, reported and never run again. Only `kcc serve` runs
schedules. A scheduled change is never saved: it stays in the running configuration
until a save or a router restart, which undoes it; a failed policy switch is reported
and leaves at most that one host line changed, unsaved.

Raw router answers (explorer, consoles,
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

The catalog itself sets two floors, so no front end has to: every DELETE is Destructive,
and a CLI line the catalog cannot map, which only a role holding `RawRci` and
`ManageRouters` may send unvalidated (MCP `kcc_cli_parse`, the Web CLI console's "Send
without catalog validation" box), is Destructive and runs under the recovery timer. Such a
line therefore also needs the `Destructive` permission; over MCP the server switch and
`confirm: true`, in the Web console the router name typed in the dialog.

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

## Entware and SSH to the router

Entware runs software as root on the router, so what kcc may do there is held tighter
than what it may do over the RCI API. No part of it has run against a real router yet
([BACKLOG.md](BACKLOG.md)).

**Over the RCI API.** Reading Entware's status needs `Read`. Chroot, the Entware time
zone and DNS override need `Write`; the drive setting (setup and removal), the startup
script (`opkg initrc`, a script the router runs as root from the drive) and initializing
a drive need `Destructive`. Ejecting or initializing the drive Entware runs from is
refused until acknowledged. The guided setup is one write job that never saves, and the
installer comes from a closed table chosen by kcc (the MCP `setup` takes an architecture,
never a URL or a path). Migrations and presets never copy the router's
Entware settings.

**What kcc sends over SSH.** kcc reaches Entware's SSH server (dropbear) only through
`kcc-ssh`, in one shape:

- The address comes from the outbound policy, and only from `allowed_networks` or an
  admitted loopback ([CONFIG.md](CONFIG.md)); a connection is never made to an address the
  policy did not admit.
- A host key is mandatory. kcc pins one ed25519 key per router and ends the handshake,
  before any authentication, when the router presents another (byte for byte). Such a
  refusal is audited as `entware.ssh.hostkey_mismatch` with both fingerprints and shows
  both on the Web page.
- The commands are a closed set: `opkg` list, update, install, remove and upgrade,
  init-script list and `start|stop|restart|check`, and adding and removing kcc's own
  `authorized_keys` line. Every argument is parsed by a token grammar (a package name is
  `[a-z0-9][a-z0-9+._-]{0,63}`, a service is `S` and two digits and a name); no function
  takes command text. An install, removal, upgrade or service action names only a package
  or service the same session listed first, and is read back afterwards.
- One session per router and four in all; connect, sign-in, read and mutation time out
  after 5, 10, 30 and 600 seconds; a command's output is cut at 256 KiB, parsed into
  values and never stored: the audit records its byte count and SHA-256 only.
- `Destructive` on the router is needed for every SSH operation, reads included, because
  each one signs in as root on the router. The Web, the CLI and MCP check it before any
  router or SSH contact, and MCP also needs `allow_destructive = true` and `confirm:
  true`. The router's `opkg chroot` must be off: chroot moves the paths kcc relies on, so
  kcc refuses every SSH action that contacts the router while it is on.

**Enrolment.** The first connection could be answered by anything on the network, so kcc
never trusts the first key it sees. The enrolment has two separate steps:

1. A **probe** (`Destructive`) connects, reads the router's ed25519 host key without
   authenticating, and returns its `SHA256:` fingerprint and a ticket. The ticket is a
   256-bit random nonce sealed under the master key (`<state>/router-ssh/<id>.ticket.sealed`),
   bound to the router, the SSH port and the acting account, valid for 5 minutes, and one
   per router: a new probe replaces it. The administrator must compare the fingerprint
   **out of band**: from a trusted computer in the router's local network connect with
   `ssh -p <port> root@<router>` and compare the fingerprint it shows (without signing
   in), or run `ssh-keyscan -t ed25519 -p <port> <router> | ssh-keygen -lf -`, or read the
   key on the router itself with `dropbearkey -y -f
   /opt/etc/dropbear/dropbear_ed25519_host_key`. If the drive also holds the public key as
   `/opt/etc/dropbear/dropbear_ed25519_host_key.pub`, running `ssh-keygen -lf` on a copy
   of it shows the same fingerprint; whether Entware's dropbear writes that file is not
   verified ([BACKLOG.md](BACKLOG.md)).
2. The **bootstrap** presents the ticket, the fingerprint the administrator confirmed and
   the Entware root password. kcc redeems the ticket (expiry, port, account, nonce, then
   the confirmed fingerprint must match), pins exactly the host key the ticket holds, and
   never re-reads it from the network, so the key pinned is the one that was compared. It
   then generates a new ed25519 key, saves it sealed (`<id>.key.sealed`) and the enrolment
   as Pending, signs in once with the password, adds the key to
   `/opt/etc/dropbear/authorized_keys` as `<key> kcc:<router id>` (replacing any older kcc
   line for that router, and keeping every other key byte for byte), signs in again with
   the key alone to prove it works, and marks the enrolment Active. From then on kcc uses
   the key only; the password is never used again.

A ticket is consumed by every redeem attempt, a refused one included (wrong
fingerprint, wrong account, expired). So another account holding `Destructive` can make
the owner of a ticket probe again by redeeming it wrongly; that fails closed (nothing is
pinned) and costs a repeat of the probe. A changed host key (a reinstalled Entware) is
pinned the same way with **re-pin**, which also needs a ticket and the password; changing
the router's address in kcc clears the pin and needs a new probe and bootstrap. Enrolling
an Active router again, or re-pinning, saves the new key and marks the enrolment Pending
before the router is contacted, so one wrong password or an unreachable router leaves it
Pending and SSH operations stop until a new probe and bootstrap succeed (`disable`
always works).

**The password.** The Entware root password reaches kcc only over TLS or loopback
([Secrets in transit](#secrets-in-transit)). It travels in a secret string that is moved
into the one password session and wiped with it, and is never stored, logged, audited or
shown again. It is not wiped everywhere: russh copies it into a plain `String` for its
authentication request and does not zeroize that copy when it drops it, and the Web form
buffers that carried the typed password are not zeroized (as for the login form). A
process memory dump during an enrolment can therefore contain it. The CLI never takes it
as an argument: `--password-file`, `KCC_PASSWORD` or a hidden prompt.

**MCP.** The enrolment steps are never offered over MCP; an MCP caller is refused before
any contact, so the Entware password cannot pass through a model. The `entware-ssh` tools
need an enrolled router, `Destructive`, `allow_destructive` and `confirm: true`, and every
call is audited as `entware.ssh.<operation>`. MCP reports every SSH failure as
`router_unreachable` (host key mismatch and rejected sign-in included); the audit entry
keeps the exact reason.

**Revoking.** **Revoke** removes kcc's line from the router's `authorized_keys` first
and then the local files, and fails with the record kept when the router cannot be
reached or refuses the key. **Disable** (`Forget here`) only deletes the local key and
pin; the router keeps kcc's line until someone removes it there. Removing the router in
kcc deletes the local SSH files and warns while the router still authorizes kcc's key.

**Two protections, two audiences.** The router's fail-safe timer protects kcc's access:
the DNS override change is a management change, so it runs under the timer and the router
restores its saved configuration if kcc loses it. It does not protect the household:
DNS override hands port 53 to a DNS server in Entware, and when that server does not run,
every device at home loses name resolution while kcc is still connected and nothing rolls
back. The Web page and the CLI therefore warn beside the control. The Web page also warns
that removing Entware stops the router's DNS filter when that filter uses the `opkg`
engine.

**Known limits.** The shared masker that hides secrets in a service's log records is the
config-text masker: for a role without `RevealSecrets` it leaves forms such as
`password=<value>` visible, because it masks `wpa-psk`, `ns3` and `user ... password
md5`. Sealed SSH files are read without a size limit and a ticket's expiry uses the wall
clock, so a clock stepped back extends it. Changing the SSH port or switching SSH management
on or off is not audited, and an audit write failure in the SSH flows is logged and does
not change the step's result. A dropped request can leave a
command's audit entry unwritten. Planting kcc's `authorized_keys.kcc` temporary file as a
symbolic link needs root on the drive, so it crosses no boundary. See
[BACKLOG.md](BACKLOG.md).

## Administering MCP settings

The MCP page (permission `ManageMcp`, held by `admin` only by default) is how listeners,
sign-in methods and tools change while `kcc serve` runs; `kcc mcp settings show` prints
the values and where each comes from.

- **Who wins**: per key an environment variable, then a key listed in `[mcp] locked`, then
  the value saved on the Web (`mcp_settings.json`), then `kcc.toml`, then the default. A
  locked key and an environment value are read-only on the page. Values that decide
  where a request may go (`ssrf_allow_hosts`, `ssrf_allow_cidrs`) exist only in
  `kcc.toml`, and no CA, certificate or key is ever named by a path.
- **Password re-entry**: a change that reduces safety (destructive tools on, read-only
  off, a toolset marked as reducing safety on, stdio on or a stronger stdio role, an
  OAuth method on, client certificates added or `required` dropped, any identity provider
  setting, the certificate role, longer token lifetimes, plain HTTP or a non-loopback
  address on the dedicated listener) asks for the administrator's password again. A wrong
  password counts toward the sign-in lockout; a lockout ends no session.
- **Role ceiling**: a role the settings name, or a sign-in source hands out, must be one
  the acting role covers; the page refuses before it asks for the password. A reset to
  `kcc.toml` carries the same ceiling for the value that applies again.
- **Applying**: a listener change builds the new listener first, health-checks it and
  reverts on any failure; the settings file is written only after that. A change is audited
  as `web.mcp_settings` with the changed key names, the restarted listeners and the
  outcome: key names, not values.

## MCP client certificates (mTLS)

An MCP listener with TLS can admit clients by a TLS client certificate
(`[mcp.auth.main|dedicated] mtls`, through rmcp-server-kit). `optional` verifies a
certificate when one is presented and lets other clients use an API key; `required`
refuses, during the TLS handshake, every client without a certificate from the uploaded
CA. `required` is refused on the main listener, which also serves the Web UI: browsers
without a certificate must keep reaching it.

- **The CA** is uploaded on the Web (Administration > MCP); no path is ever taken from
  the Web, a state file or kcc.toml. It is checked before it is stored: PEM of at most
  64 KiB holding one to ten certificates and nothing else (a private key block is
  refused and never echoed), each a parseable X.509 certificate whose basic constraints
  mark it as a CA, framed so the MCP listeners' PEM reader loads the same certificates
  (a file it would read differently is refused when uploaded, not when a listener
  starts). The validity period is not checked: a CA past it admits no client.
  It is written to `<state>/mcp/mtls-ca.pem` by renaming a new file over the old one (a
  symbolic link in its place is replaced, never followed), mode `0644` on Unix:
  certificates are not secret, and the state directory stays owner-only. The page lists
  the stored certificates' subjects (escaped).
- **Replacing the CA** changes who may sign in. While a listener uses client
  certificates it therefore asks for the administrator's password (a wrong one counts
  toward the sign-in lockout) and runs in the listener supervisor's serialized section:
  the CA is stored, every listener using it restarts and is health-checked, and a
  failure puts the previous CA file back and serves the previous listeners again. While
  no listener uses it, the upload stores it without a password. Each upload is audited
  as `web.mcp_settings` with `changed: ["auth.mtls.ca"]`, the restarted listeners and the
  outcome.
- **Revocation** uses the kit's CRL defaults: CRL distribution points named by the CA
  and by client certificates are fetched under the kit's SSRF screening, and a
  certificate whose CRLs are all unavailable is refused. A certificate with no
  distribution point, under a CA that names none, is never revocation-checked: a CA
  without CRL points cannot revoke a certificate it issued, short of replacing the CA.
- **Identity**: the kit names the client by the certificate's first non-blank common
  name (else its first DNS name); the name may hold only letters (Unicode ones included),
  digits and `-._@`, and a certificate whose name has other characters gets no identity
  (the request then falls back to an API key and answers 401 without one). The client gets
  `[mcp.auth.mtls] default_role` (`viewer` when unset), which the configuring admin's
  role must cover. Its audit actor is `mcp`/`mtls:<cn>`; API key names cannot contain
  `:`, so a certificate never passes for a key, and only API-key callers mark a key used
  (a certificate whose common name equals a key's name does not). An audit actor id is cut
  at 64 bytes, `mtls:` included, so two certificates whose names share a 59-byte prefix
  are audited alike, and look-alike Unicode letters stay inside the `mtls:` namespace
  without being told apart from their twins.
- **Health check**: kcc holds no client certificate, so its probe presents none and
  checks the listener's rule instead: an `optional` listener must ask for a certificate
  and answer `/healthz` without one; a `required` listener must ask and then refuse with
  the `certificate_required` (or `handshake_failure`) alert; a listener without client
  certificates must not ask. A listener that does not enforce its rule fails the check
  and the restart is reverted.
- **Start-up**: a main listener whose saved settings turn client certificates on while
  the CA file is missing or fails the checks starts with kcc.toml's sign-in settings and
  logs why; the MCP page shows the fallback.

## MCP sign-in with kcc accounts (OAuth 2.1)

With `[mcp.auth.main|dedicated] oauth = "kcc"`, kcc is an OAuth 2.1 authorization server
for its own MCP listeners (RFC 6749, 7591, 7636, 8252, 8414, 8707, 9068, 9207, 9700,
9728).

- **Issuer**: `web.public_url` when its host is a DNS name, else `http(s)://localhost:<port>`
  of a loopback main listener; no issuer otherwise (and none without the Web UI), and the
  MCP page then refuses kcc sign-in. While no listener uses kcc sign-in, every OAuth route
  answers 404.
- **Clients** are public (no secret), registered without authentication: at most 10 per
  address an hour (memory only), 50 in all (admin-registered ones count), names of at most
  64 characters shown as unverified, at most 5 redirect URIs: loopback `http` (any port),
  `https` exactly, or reverse-domain private-use schemes; `javascript:`, `data:`, `file:` and
  other `http` are refused. `logo_uri` and `client_uri` are never fetched.
- **Authorization requests** need a registered client and one of its exact redirect URIs;
  otherwise the browser gets an error page and is never redirected. PKCE S256 only (`plain`
  is refused), `resource` must be an MCP URL of a listener using kcc sign-in, `state` is
  echoed and `iss` is added to every answer. Requests live 10 minutes in memory, at most
  1024; one address (an IPv6 /64 counts as one) may open 30 per 10 minutes and holds at
  most 16 at once (its oldest gives way). When the store is full, the oldest request of the
  address holding the most gives way, so a flood from many addresses evicts the flooders'
  requests first. Only a keyed hash of the address, under a random per-process key, is
  kept, in memory. An attacker controlling at least 1024 distinct addresses (or /64s) can
  still evict a pending request (the store is bounded); the 10-minute lifetime and the
  per-address limit bound the damage, and the client then starts the sign-in again.
  Unicode format characters (bidi controls, zero-width characters) are removed from a
  client's name at registration.
- **Consent** needs a Web session: without one the login page carries the request id,
  and the login resumes only at a live request (never a URL). Approve and deny are
  same-origin htmx POSTs with the session's CSRF token, under the pages' CSP with
  `frame-ancestors 'none'` and `no-store`. The account must be enabled and need not change
  its password, checked when the page opens, at the approval and again when the code is
  redeemed (a code is valid 60 seconds and once; it is bound to the client, redirect URI,
  resource, PKCE challenge and the password it was approved with). Decisions are audited
  as `web.oauth_consent`.
- **Tokens**: access tokens are EdDSA JWTs (`typ: at+jwt`) with `iss`, `sub` (the
  account), `aud` (the resource), `client_id`, `scope: "mcp"`, `kcc_grant`, `exp` (15
  minutes by default); the signing key is sealed under the master key and never rotated
  (BACKLOG). Refresh tokens are opaque, stored as SHA-256 only and rotated on every use;
  using a rotated one again revokes its whole family and is audited as
  `mcp.oauth_refresh_reuse`. Token answers are `Cache-Control: no-store`, `Pragma:
  no-cache`, the answer to an oversized protocol request (`413`, `invalid_request`)
  included; issuance is audited as `mcp.oauth_token_issued` (account, client, grant; no
  token). No token, code, verifier or signing key reaches a log, an audit entry, an error
  or a page.
- **Validation**: rmcp-server-kit validates every token (issuer, audience, EdDSA only, a
  subject required, expiry) with keys from kcc's internal JWKS listener: plain HTTP on
  one port of both 127.0.0.1 and [::1] (`localhost` resolves to both, so no other local
  process can answer the kit's fetch; five ports are tried, else kcc sign-in is refused
  and logged), serving `GET /jwks` only.
- **Per-call authority**: a kcc token grants nothing by itself. Its kit role
  `kcc-account` is reserved (no API key, certificate or other provider can hold it); on
  every MCP call kcc re-reads `users.json`, `mcp_oauth_grants.json` and
  `mcp_oauth_clients.json` when they changed on disk and requires the grant to exist and
  not be revoked, its client to be still registered, the account to exist, be
  enabled, need not change its password and have the password the grant was issued with.
  The call then runs with the account's current role (tools, router scope, list) and kcc
  refuses a tool that role does not grant. A refusal answers `forbidden` until the
  token expires (then 401). Callers are audited as `oauth:<account>`.
- **Revocation latency**: a revoked grant, a deleted client or account, a disabled
  account, a role or password change binds the very next call; an issued access token
  stays valid at the kit until it expires (an access token is a signed JWT and cannot be
  recalled), but every call it makes is refused, and its refresh token stops working at
  once. An administrator holding `ManageMcp`
  revokes grants (one, or every grant of an account) and deletes clients on
  Administration > MCP > Connections or with `kcc mcp connections revoke|revoke-account`
  and `kcc mcp clients delete`, also while another process runs `kcc serve`: a deleted
  client's grants are revoked in the same change, so its open sessions are refused at their
  very next MCP call too, and the OAuth endpoints read the clients file on every request.
  These pages and commands never show a token or a stored hash, and cannot change a
  grant's account or role; they are audited as `web.mcp_grant_revoke`,
  `web.mcp_client_delete`, `web.mcp_client_register`, `cli.mcp_grant_revoke` and
  `cli.mcp_client_delete` with the account and ids only. A `ManageMcp` holder may revoke
  the grants of any account, an administrator's included: revoking only removes access, so
  no role comparison applies.
- **Known limits**: a code used twice is refused, but the grant already issued from it is
  not revoked (RFC 9700 recommends it); reuse detection keeps 16 rotated refresh token
  hashes per grant, so an older one is just unknown; the 50-client limit counts
  admin-registered clients, so registrations from many addresses can fill it for up to
  24 hours; an account that must change its password cannot resume a pending request after
  changing it (the client starts again). Browser-based clients are refused by the kit's
  Origin check on `/oauth/token`. The authorization limiter bounds requests per address, so
  an attacker with 1024 or more distinct addresses (or IPv6 /64 networks) can still evict
  a pending request. `/oauth/token` checks a refreshed grant's resource against the running
  listeners after rotating its token: if a listener stopped serving that resource, the client
  gets `invalid_target`, never receives the rotated token, and its grant is dead until it
  expires or is revoked. Deleting an account does not revoke its grants: kcc refuses their
  calls, but the Connections tab keeps listing them under the old name until they are
  revoked there (`kcc mcp connections revoke-account <user>`). A grant issued at the same
  moment its client is deleted can be listed under the bare client id until revoked, though
  its calls are refused. An open MCP session on a listener that restarts is dropped.

## MCP sign-in with another identity provider (OIDC resource server)

- **Mode**: kcc is only a resource server. The provider of `[mcp.auth.oidc]` registers
  clients, signs users in and asks for consent; kcc never proxies its endpoints. A
  listener's `oauth` is `kcc` or `external`, never both. The protected-resource metadata
  names the provider's issuer as the authorization server.
- **Token validation** is the kit's: the signature with a key from the provider's JWKS
  (fetched over https, at most once every 10 seconds on an unknown key id, cached for 10
  minutes; an unreachable JWKS refuses the token), `iss` equal to the issuer, `aud` equal
  to the audience (strict: `azp` alone does not count), `exp` and `nbf`, and a `sub`.
  Only asymmetric algorithms can be allowed (`ES256`, `ES384`, `EdDSA`, `RS*`, `PS*`);
  `HS*` and `none` are refused when configured and never accepted in a token, so a token
  keyed with the public key (algorithm confusion) fails. A token whose group or scope maps
  to no role is refused (401).
- **Roles**: every mapping target must be a role the configuring admin's role covers
  (permissions and routers), as for the client-certificate role; a claim value or scope
  may be mapped only once, because the first match would win. A token's role comes from
  whoever controls the provider, so changing the issuer, audience, JWKS URL or role claim,
  switching a listener to the provider, or uploading its CA bundle is refused unless the
  acting role covers every role the mappings name, also mappings it did not write (for
  example kcc.toml's); the same holds for the client CA and the certificates' role.
- **SSRF**: the JWKS host is resolved when a listener is built; a private, loopback,
  link-local, CGNAT, unique-local or internal-suffix address refuses the listener unless
  `ssrf_allow_hosts` or `ssrf_allow_cidrs` admit it, and a cloud metadata address is
  always refused. Those two keys exist only in kcc.toml: the Web, MCP and state files
  cannot set them. The kit screens every fetch and redirect again.
- **CA bundle**: the provider's CA bundle decides which certificate the JWKS fetch trusts
  and so which tokens are valid. It is uploaded on the Web only (no path anywhere),
  checked like the client CA (at most 64 KiB, one to ten CA certificates, framed as the
  kit reads them; a refused file is never written) and stored as
  `<state>/mcp/oidc-ca.pem` beside the built-in roots. While a listener signs in with the
  provider, replacing it asks for the administrator's password and restarts those
  listeners in the supervisor's serialized section; a failure puts the previous bundle
  back before the previous listeners serve again. Audited as `web.mcp_settings` with
  `changed: ["auth.oidc.ca"]`.
- **Identity**: callers are audited as `oidc:<preferred_username>` (else the subject),
  with every byte other than ASCII letters, digits and `-._@` written as `%XX`, cut to 64
  bytes; the token is never logged or audited. The name is not unique: it is the
  provider's free-text claim, so two users the provider gives the same
  `preferred_username` are audited alike, and so are two long names that share their first
  64 bytes. The role comes from the claim or scope mapping, not from this name.
- **Algorithms**: an empty `allowed_algorithms` means every algorithm the kit accepts,
  RSA ones (`RS*`, `PS*`) included, because Keycloak signs with RS256 by default; list
  `ES256` or `EdDSA` to refuse RSA-signed tokens. See "Signature algorithms and accepted
  advisories" below.
- **Known limits**: a mapping to a role that does not exist yet is skipped by the role
  ceiling (it grants nothing today), so creating a role under that name later would hand
  it to the provider's users without anyone checking the provider again; the Web checks
  the CA upload ceiling once, against the roles at that moment, and the supervisor stores
  the file without an actor, so a role change in the milliseconds between the two is not
  re-checked (settings changes re-check at commit); the kit trusts the uploaded bundle in
  addition to the built-in roots, so a publicly trusted certificate for the provider's host
  is accepted too; the JWKS host is resolved when the listener is built and a host that
  does not resolve then passes that screen (the kit screens every fetch, so the first fetch
  fails closed); a provider whose `iss` has no trailing slash on a bare host never matches,
  because the issuer is kept as a URL, which adds one.

## Signature algorithms and accepted advisories

kcc signs its own MCP access tokens with Ed25519 through `ring` and the kit verifies them;
for an external provider the kit verifies RSA, ECDSA and EdDSA signatures with the
provider's public keys. Enabling the kit's `oauth` feature brings `jsonwebtoken` 11 and
with it two advisories that `deny.toml` and `.cargo/audit.toml` ignore with an owner
decision dated 2026-11-22 and a review by 2027-02-18: RUSTSEC-2023-0071 (`rsa` 0.9.10,
the Marvin timing attack, which needs private-key operations) and RUSTSEC-2026-0387
(`crypto-bigint` 0.5.5, timing variability, reached only through ECDSA). Neither applies:
kcc and the kit only verify with public keys, so no private RSA or ECDSA operation runs.
The fix needs a kit release on `jsonwebtoken` 12 ([BACKLOG.md](BACKLOG.md)).
`humantime` and `chrono` are two unmaintained notices ignored by an earlier owner decision
(2026-11-18), with the same review date.

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
reason. Actions outside the change workflow (backup creation, preset capture and
deletion, job cancellation, a diagnostic start) record their success as `success` under
the tool's own action `mcp.<tool>`. A change of several CLI lines that the router refuses
part of records the applied lines like a partial batch. The CLI and MCP share one format for these attempts: outcome `forbidden`
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

An append reads only the last line of the newest file (the active file, or the newest
archive when the active file is empty), so its cost doesn't grow with the retained log.
It checks that entry's own hash, not its link to the entries before it. The whole chain
is verified when an audit writer starts (`kcc serve`, `kcc mcp stdio` and every audited
CLI run), by `kcc audit verify` and on the Web audit page. Damage to an older entry or
archive therefore shows at the next start or verification, not at the next append.

The Web audit page and its export honour the viewer's router scope. An entry that names a
router is listed only when that router is in the role's `router_scope`; an entry that names
no router (sign-ins, user, role and key changes, repairs) is listed only to a role whose
scope covers all routers (empty or `*`). Fleet-wide visibility is therefore a property of an
unscoped role, not of the ViewAudit permission alone. The page verifies the chain once and
reuses the result until the length or modification time of an audit file changes; a tampered
or torn log shows its failure, and the export is streamed entry by entry.

A last line without its newline is not an entry: a crash or a full disk cut it short
mid-append, so no hash protects it. kcc moves it to `audit.jsonl.torn-<unix-ts>` in the
state directory before the writer starts or before its next append. The file is
owner-only and holds the cut bytes unchanged. kcc logs a warning and records an
`audit.repair` entry whose params name the file and its size (`file`, `bytes`), never its
content, and the chain continues from the last complete entry. Verification skips such an
unterminated last line of the active file. A complete line that doesn't verify is still
tampering: the writer refuses to start, or stops at its next append, and the line is left
in place.

The append lock uses a longer bounded backoff with per-process phase jitter. Mutual
exclusion still covers the tail read, the repair of a torn line and the complete durable
append, so contention cannot fork the chain. A busy lock never drops an entry: the one writer of each process
keeps it at the head of its queue and retries until the lock is free, so entries are
written in the order they were submitted, and the sequence number and previous hash are
assigned under the lock. Chain, serialization, join, or log I/O failures terminate the
writer. New router work is then refused before its first router request, and `kcc serve`
exits non-zero so its supervisor can restart it.

Audit guarantees: while the process runs, every entry is kept and written in order; an
entry is lost only if the writer fails or the process exits first (`kcc serve` and `kcc
mcp stdio` give the writer 5 s at exit and log the count of entries still queued; a CLI
run exits right after its change). Queuing an entry never waits: the queue to the writer
has no length limit, so while another process holds the append lock, entries (failed MCP
calls, Web actions, change receipts) pile up in memory until the lock is free; none is
dropped. Callers then wait for their entry a bounded time (30 s for a change; inside a
management change's recovery bracket the arm, the work and the disarm are sent without
waiting, then the bracket waits 20 s). A change the router applied whose entry is still
queued is reported as done with a note that the entry will be written once the audit log
is free, never as a router failure.

The Web sign-in, sign-out and own password change must not happen without their entry.
They share 128 queue slots; a slot stays taken until its entry is written. A sign-in waits
at most 5 s in all, first for a slot and then for its entry: with the entry still queued
then it signs the user in, but when no slot freed in time the entry is not queued and the
sign-in is refused with HTTP 500 and no session. A failed sign-in, a sign-out or a
password change waits at most 30 s the same way and answers HTTP 500 when its entry was
not written by then (a sign-out has already ended the session; a password change stays
made).

Audit entries carry a correlation `request_id` of the form `<prefix>-<nonce>-<n>`: a
per-process random 64-bit nonce in hex and a per-process counter, so no two requests share
one, within a process or across processes. All entries of one change set share its id;
every entry of a CLI run carries the run's id (`cli-...`), change entries included. An MCP
tool call draws its id (`mcp-...`) before its work: its change sets and entries carry it,
every line it logs runs in an `mcp_tool` span with `request_id` and `tool`, and a failed
call returns it to the client.

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
traced from the binary's real system calls (`deploy/podman/seccomp-kcc.json`), which
names only the `x86_64` and `aarch64` system call ABIs. The
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
