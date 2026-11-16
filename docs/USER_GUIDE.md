# User guide

This guide covers the kcc Web UI page by page. The UI lives under `/ui/` on the
address `kcc serve` listens on (default `http://127.0.0.1:8443/ui/`). Every page checks
your role: pages and buttons you have no permission for are hidden or answer
"Forbidden", and every change is written to the audit log.

## Common patterns

- **Router switcher.** The masthead's Router menu opens the dashboard of another router.
  Router pages live under `/ui/r/<router>/...`.
- **Side navigation.** On a router's page, Clients, Network, Wi-Fi, Routing, Firewall,
  DNS, VPN and System open that router's page of the section. On other pages they open
  the only router you may read, or a list of the routers you may read to pick from.
- **Changes.** A change dialog sends one validated request through the change workflow:
  kcc backs up the startup configuration, checks nobody else changed the router in the
  meantime, applies the change, reads it back and audits it. The result appears as a
  toast; the "Unsaved" badge in the masthead means the running configuration differs
  from the startup configuration. Nothing is saved until you press Save.
- **Risky changes.** Changes that can cut kcc off from the router (disabling or
  re-zoning the interface or access point kcc reaches the router through, its Wi-Fi
  schedule, firewall rules on it, releasing the KeenDNS name kcc uses) ask first on every
  page and run under the router's fail-safe timer, which the change's own permission
  authorizes; nothing is sent before you confirm. Rolling the timer back yourself needs
  the Destructive permission. Deletions ask for confirmation; the most dangerous ones
  need the router or object name typed, and a destructive change from any page asks for
  the router name unless the page already asked for a name.
- **Tables** sort by a column header, filter with the search field and page at the
  bottom. On phones they scroll sideways without a visual cue.
- **Secrets** (Wi-Fi keys, VPN keys, passwords) show only as Set or Not set, and the
  fields that change them are write-only: a dialog asks for the new value twice and
  never shows the stored one. Leaving both fields empty keeps the stored value and sends
  nothing. The new value goes only to the router, never into a page, a toast, the audit
  log (it records field names only) or the server log, and kcc verifies it by reading
  back that the router reports a stored value of a plausible length, never the value
  itself. Reading a stored secret is a separate Reveal action where a page offers one:
  it needs the RevealSecrets permission, is audited whether allowed or not, and shows
  the value only in its own dialog.

## Dashboard and fleet

![Fleet dashboard](images/dashboard.png)

`/ui/` shows one card per router with its status, model, firmware, support tier and
unsaved state, refreshed live. Admins with ManageRouters add, edit, test and remove
routers here (Add router). The router form takes the name, address, login, sign-in
mode, password or API token, certificate check (verify, or pin one certificate), an
optional read-only polling account, tags and the `test_device` flag. The sign-in mode is
Automatic (the scheme the router offers), ndw2, ndw4, HTTP digest or API token; the
token field appears only for API token and replaces the password. The read-only login
and password are entered together; the poller then signs in with them instead of the
management login, and "Remove read-only login" on the edit form drops both. The pin is
the SHA-256 of the router certificate's public key (SubjectPublicKeyInfo) and applies to
https addresses only. Test connection logs in with the typed password, or with the
stored credentials when the field is empty, without storing anything. Routers defined in
`kcc.toml` are read-only here.

Passwords, tokens and read-only passwords entered in this form are encrypted in the state
directory and are never shown again: an empty field keeps the stored secret, and the
form only says that one is stored. Changing the address, login or certificate check
needs the password (or the token) again and drops the read-only login unless it is
entered again in the same save; switching to API token needs a token and removes the
stored password, switching back needs a password and removes the stored token.
`kcc router add` and `kcc router edit` use the same sealed store for every
credential they take: the password (`--password-file`, `KCC_PASSWORD` or the hidden
prompt), a login token (`--auth token --token-file <file>`) and a read-only polling
login (`--read-login <name> --read-password-file <file>`). The files are input only and
can be deleted afterwards. Changing a router's address, login or certificate pin needs
its password or token again (`--new-password` or `--new-token`) and drops the read-only
login unless it is given again. Only `password_file` paths in `kcc.toml` stay under
operator control and are read in place. Back up the master
key selected by `KCC_MASTER_KEY_FILE` separately from state; without it, restored sealed
credentials and encrypted backups cannot be opened.

A router's dashboard (`/ui/r/<router>`) shows host name, firmware, memory, internet and
WAN link state, WAN connections, radios and access points, the WAN traffic chart (the
last 30 minutes, kept in memory), the unsaved-changes banner with Save, and the
support-tier notice for documentation-based firmware. The firmware line says "Update
available" or "Up to date" once kcc has asked the router (`components check-update`, in
the background, at most every six hours per router and only while the router answers
its polls); until then it says "Not checked".

## Clients

![Clients page](images/clients.png)

`/ui/r/<router>/clients` lists connected and registered clients with filters for
online/offline and wired/wireless. Row actions: register or rename, allow or deny
access, assign a connection policy or schedule, set priority, wake-on-LAN, remove.

## DHCP

`/ui/r/<router>/dhcp` has tabs for pools, static leases, current bindings and ARP
neighbours. You can edit a pool and add a static lease ("Make static" on a binding fills
the form). Removing pools or static leases isn't offered yet.

## Segments

`/ui/r/<router>/segments` lists the segments kcc created on the router: bridge, VLAN ID,
address, DHCP range, NAT, whether new devices are allowed, Wi-Fi access point, the ports
carrying the VLAN and the connection policy. A segment that lost some of its objects is
marked Incomplete. Segments made outside kcc aren't listed; their bridges and VLANs are
on the Network page.

Create segment builds a new one (VLAN, bridge, address, DHCP pool, ports, access point,
policy) step by step, rolling back finished steps if one fails. Delete lists the router
objects that go and the ports that stay (only the segment's VLAN leaves them), and asks
you to type the router's name. It deletes nothing if the segment changed after the
dialog opened. Incomplete segments delete what is left. Deleting needs the same Write
permission as creating.

## Network

![Network page](images/network.png)

The network area has tabs:

- **Interfaces** (`/network`): every interface with state, address and traffic; a
  drawer shows details and a live traffic chart. Bring up or down, set the description
  or security level. Taking down the management interface is a risky change.
- **Internet** (`/internet`): WAN connections with priority order, default route,
  address mode (DHCP or static), MTU, identity and "connect via"; create and delete
  connections. A PPP connection's (PPPoE, L2TP, PPTP) password is set from its settings
  (Edit beside Password).
- **Wi-Fi** (`/wifi`): access points and radios; turn an access point on or off, hide
  the SSID, edit settings. The Wi-Fi password is set from an access point's settings
  (Edit beside Wi-Fi password): 8 to 63 characters, checked before anything is sent.
- **Mesh** (`/mesh`): mesh members with check, update and restart actions.

## Routing

The Routing section has tabs for static routes (IPv4 and IPv6, add and remove), the
routing table, and connection policies (create, description, permitted interfaces and
their order, multipath, delete). Removing a route runs a guard: if the router clears
more than the one route, kcc puts every other static route back and says so.

## NAT and port forwarding

`/ui/r/<router>/nat` lists port forwards (add, remove), NAT interfaces (add, remove) and
the active connection table, read in pages of 200.

## Firewall

![Firewall page](images/firewall.png)

`/ui/r/<router>/firewall` shows the IPv4 access lists with their rules, the interface
bindings and UPnP redirects. You can add, remove, move, enable or disable rules, set a
rule's description or schedule, and bind or unbind a list. A change that touches the
interface kcc reaches the router through is a risky change. IPv6 access lists are
read-only, because no firmware catalog has `ipv6 access-list`.

## DNS

![DNS page](images/dns.png)

`/ui/r/<router>/dns` has tabs for upstream servers (plain, DNS over TLS, DNS over
HTTPS), filtering (engine, profiles, assignments, intercept), static records, FQDN
lists and DNS routes. Removing upstreams, records, lists, routes or profiles isn't
offered yet.

## VPN

`/ui/r/<router>/vpn` lists VPN client connections (turn on or off, delete) and VPN
servers (service state, address pool, DNS, IPsec). WireGuard connections can be created
or imported from a `.conf` file. The import sends the file's private key, preshared keys
and obfuscation keys to the router and verifies that the router reports each one; a file
without a private key gets one the router generates. kcc reports which fields of the
file it didn't send (address, DNS, ASC). Peers of a WireGuard tunnel are listed and
added on their own page; a peer's preshared key is set in its dialog (left empty, the
peer keeps its key). Client types other than WireGuard have no create form, but their
credentials can be set: the password of an L2TP/IPsec, PPTP or SSTP connection, the
IPsec key of an L2TP/IPsec connection, and the pre-shared key and XAuth password of an
IPsec connection's profile (row actions). On the servers tab, Set pre-shared key sets
the IPsec/IKEv2 server's IKE key, and Set an account's password sets the password a
router account uses with the PPTP/L2TP, SSTP and OpenConnect servers.

## System

![System page](images/system.png)

`/ui/r/<router>/system/...` has tabs:

- **General**: host name, description, time zone, NTP server, restart, factory reset.
  Host-name, description and time-zone changes are verified by a fresh read. Their
  simulator projection is documentation-derived; the real firmware shape is unconfirmed.
- **Router users**: router accounts and their tags; add (with an optional password),
  set a password, and delete. These are risky changes run under the fail-safe timer.
  kcc refuses to delete the account it logs in with or to change its password: change
  that password on the router, then enter it in kcc with Edit router.
- **Services**: turn router services on or off.
- **Components**: installed components; check for updates, queue installs or
  removals, commit (a background job that may reboot the router).
- **Storage**: attached media; eject, check, format.
- **Schedules**: create schedules and their actions.
- **KeenDNS**: book or drop a name, set the access level, add proxy entries. The
  current access level and proxy entries aren't readable.
- **Log**: the router log, live, with search and download. With `[logs] enabled` the
  page follows the router's log collector, so viewers add no router requests; otherwise
  each viewer reads the router at most every 5 seconds.
- **Diagnostics**: ping and traceroute as background jobs with live output and Stop.

## Configuration and backups

`/ui/r/<router>/config` shows the unsaved state and the fail-safe timer (Save, and
Commit or Roll back while the timer is armed), and lists the router's backups. You can
back up the startup configuration, upload a configuration file as a backup, download a
backup redacted (or in full with RevealSecrets, audited), compare two backups (secrets
redacted on both sides), delete one, and restore one. Restore offers the migration
wizard, or a raw restore onto the same model: kcc uploads the file, reboots the router,
reconnects and checks the router's checksum. A raw restore has no live progress, and a
backup that changes the management address ends with "the router did not answer".
Backups are pruned by `[backups] keep_last` and `max_age`.

## Presets and settings copy

![Preset review](images/presets.png)

`/ui/presets` stores named presets: groups of settings captured from a router, a backup
or an uploaded file, encrypted at rest. Open a preset to see its redacted lines, reveal
them (RevealSecrets, audited), apply it to a router, or delete it. Copy settings
(`/ui/copy`) does the same without storing a preset. Both walk through source, target,
options (Merge or Mirror, WireGuard keys), review, inputs, apply under the fail-safe
timer, then Keep unsaved, Save or Roll back. Unsaved drafts of a new preset live in
memory for an hour and are lost on restart. [MIGRATION.md](MIGRATION.md) explains the
groups and rules.

## Migration wizard

![Migration wizard](images/migration.png)

`/ui/migrate` moves a whole configuration onto another router in nine steps: source
(router, backup or file), target, inventory and port, radio and interface mapping,
review of every line with its disposition, inputs (passwords, reconnect address),
preview with downloadable plan and report, apply with live progress and Stop, results
with Commit or Roll back, and the final report. [MIGRATION.md](MIGRATION.md) covers the
rules.

## Advanced: command explorer and consoles

`/ui/r/<router>/explorer` searches the router's command catalog for its firmware and
model, shows each command's arguments and runs it with validated input. Background
commands run as jobs. The RCI and CLI consoles send raw requests that are still
validated against the catalog; they need the RawRci permission. Writes go through the
change workflow. Answers, the configuration lines of `show running-config` included,
show secrets as `********` unless you hold RevealSecrets on that router. On the CLI,
`kcc show` and `kcc rci` print them as `<redacted>` under the same rule.

## Administration

![Audit log](images/audit.png)

`/ui/admin` holds:

- **Users**: create accounts, change roles, disable, unlock, delete. The last enabled
  admin can't be removed, and nobody can act on their own account here.
- **Roles**: custom roles with permissions and router-name globs (for example `lab-*`).
  You can grant only roles whose permissions you hold yourself.
- **API keys**: create keys for MCP clients (shown once) and revoke them. The "Last
  used" column shows the last MCP tool call with the key, recorded at most once a minute.
- **Audit log**: search, filter and export the hash-chained audit log (ViewAudit).
- **Server**: the running configuration summary and catalog versions.

Your own account page (`/ui/account`) changes your password and language. After
`kcc admin init`, or an administrative reset, the first sign-in must change the
password.

Changes made with the CLI (`kcc apikey revoke`, `kcc user disable`, `kcc user passwd`)
reach a running `kcc serve` within about 2 seconds: a revoked key is refused, and the
account's signed-in sessions end when it is disabled or its password is reset.

## Metrics

The Web UI doesn't chart Prometheus metrics. Enable `[metrics]` and use the Grafana
dashboard in `deploy/monitoring/`; see [MONITORING.md](MONITORING.md).

## Language and theme

The masthead's language menu offers English, Russian, Ukrainian, German, Belarusian and
Kazakh; the theme menu offers light, dark and system. Both are stored in cookies set by
the page's JavaScript, so without JavaScript they do nothing. When you're signed in, the
language menu also saves the language to your account, as the account page does, and
every next page uses it. The sign-in page follows the cookie and shows only these two
menus. See [I18N.md](I18N.md).
