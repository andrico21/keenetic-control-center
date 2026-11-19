# Privacy

kcc runs on your own host and sends nothing to its authors. This document lists what it
stores, for how long, what it never stores, and what can leave the host.

## What kcc stores

Everything lives in the state directory (`[state] dir`, default `~/.local/state/kcc` on
Linux, `%LOCALAPPDATA%\kcc` on Windows; `/var/lib/kcc` in the container), with
directories 0700 and files 0600 on Unix. "Encrypted" means sealed with the master key
(see [SECURITY.md](SECURITY.md)).

| Data | Location | Form | Kept |
|---|---|---|---|
| Router profiles added in the Web UI or CLI: name, URL, login, managed credential path, TLS mode, tags | `routers.json` | plain JSON, no password | until you remove the router |
| Router passwords typed into the Web UI, or given to `kcc router add/edit` (file, `KCC_PASSWORD` or prompt) | `router-credentials/<id>.sealed` | encrypted with the master key, `router:<id>` as associated data | until you remove the router |
| Router login tokens and read-only polling passwords given to `kcc router add/edit` | `router-credentials/<id>.token.sealed`, `router-credentials/<id>.read.sealed` | encrypted with the master key, `router:<id>:token` / `router:<id>:read` as associated data | until you remove the router or replace the credential |
| Router profiles in `kcc.toml` and their password files | where you put them | as you keep them | as you keep them |
| Web accounts: name, role, password hash, lockout state, language | `users.json` | hash encrypted, `account:<username>` as associated data | until deleted |
| API keys: name, role, Argon2id hash | `api_keys.json` | hash only | until revoked |
| Custom roles | `roles.json` | plain JSON | until deleted |
| Configuration backups: the router's full startup configuration, secrets included | `backups/<router>/` | encrypted | pruned after each new backup by `[backups] keep_last` (50) and `max_age` (180 days) |
| Presets: captured configuration lines, secrets included | `presets/<id>.json` | encrypted | until deleted |
| Migration and preset runs: step record (no secrets), redacted plan and report, sealed source and typed passwords | `migrations/<id>/` | record and reports plain, the rest encrypted | the sealed parts (source, copied settings, passwords) of every run are deleted when the run finishes, when the router's recovery window of an unfinished apply ends, when the source or target is chosen again (passwords only), and after 24 hours without a change of the run; unchanged runs are deleted whole after 30 days; records and reports stay until then |
| Background jobs: kind, router, state, progress | `jobs/` | plain JSON | finished records are pruned after 30 days; running records are kept for recovery |
| Telegram notification settings: on/off, language, client-detail switch, events, chats (id, label, topic, silent) | `notify.json` | plain JSON | until changed |
| Telegram delivery state: when the bot token was set or refused, chats Telegram refused, the newest firmware version notified per router | `notify_state.json` | plain JSON, no client data | until changed |
| Telegram bot token | `notify/telegram.token.sealed` | encrypted with the master key, `notify:telegram` as associated data | until replaced or removed |
| Audit log: time, actor, action, router, outcome, parameter names and non-secret values | `audit.jsonl` (rotated at 50 MiB) | plain, hash-chained | complete rotated files whose newest entry is older than `[audit] retention` (365 days) are pruned after rotation |

Audit pruning never splits a rotated file and removes only the oldest run of fully expired
files. The first retained entry keeps the original
`prev_hash` of the deleted prefix as an external chain anchor, and `kcc audit verify`
reports that anchor while checking every retained entry. A last audit line cut short by
a crash is moved, unchanged, to `audit.jsonl.torn-<unix-ts>` in the state directory (owner-only,
kept until you delete it), and the audit log records its name and size, never its content.
Deleting the oldest rotated files by hand is indistinguishable from retention
pruning: the chain proves the integrity of what is kept, not that nothing older ever existed.

In memory only, lost on restart: Web sessions (each holds a SHA-256 fingerprint of its
account's stored password hash, which lets kcc end it when the password changes), the live traffic history (30 minutes),
poller caches, Web UI preset drafts, MCP migration plans and transient MCP presets.

## What kcc never stores

- Plaintext web account passwords or API keys.
- Secrets in the audit log, in application logs, in error messages, or in redacted
  reports and downloads.
- Router data in any place other than the state directory, unless you configure log
  forwarding.

## What leaves the host

- **Router requests** go only to router addresses your outbound policy admits.
- **Log forwarding** (off by default) sends router log records to the sinks you
  configure. See below.
- **Prometheus metrics** (off by default) expose router metrics to whoever can reach the
  metrics listener. Per-client series are off by default; when on, clients are labelled
  by a pseudonym unless `per_client_label` says `name` or `mac`. The pseudonym is a keyed
  hash of the MAC and the router with a random per-process key: the same on every scrape
  while kcc runs, different on each router and after each restart.
- **MCP results** go to the assistant, and from there usually to a third-party model
  provider. See below.

## What MCP may send to a model

An MCP client sees whatever its tools return: router identity, interfaces, clients
(names, MAC and IP addresses), DHCP leases, routes, firewall rules, DNS settings, VPN
peers and log lines, depending on the role and toolsets. The assistant typically
forwards these results to its model provider, whose retention policy then applies.

- Values under secret-shaped keys are always replaced whole with `<redacted>`, whatever
  they hold. A key is secret-shaped when it contains password, passwd, passphrase,
  token, secret, API key, private key, ns3, PSK or preshared, ends in `-key`, or is
  `key`, `pin` or `community`; case is ignored and `-` counts as `_`. The Web UI masks
  raw answers by the same rule, with `********`.
- The raw tools (`kcc_rci_read`, `kcc_rci_batch`, `kcc_cli_parse`) also redact the
  secrets in every string of the router's answer, such as the lines of
  `show running-config`, unless the role holds RevealSecrets on that router. With
  RevealSecrets those strings arrive as the router sent them, stored secrets included,
  so give an assistant's key RevealSecrets only when its model may see them.
- `[privacy] redact_clients_in_mcp = true` replaces MAC addresses, client names (the
  `name`, `hostname`, `host`, `fqdn` and `alias` members of a client object) and values
  under keys that have `mac`, `hostname`, `host_name`, `ip` or `address` as a whole word
  (`ip_address` does, `description` does not), and the MAC, IPv4 and IPv6 addresses inside
  any other text, including the progress notifications of running tools. A host name
  written inside free text, such as a log line, can't be recognised and stays. The
  pseudonym is `client-` and 16 hex digits of a keyed hash whose random key lives only in
  the running process: it's stable until kcc restarts and different afterwards.
- Limit exposure with a narrow role and router scope for the API key, and fewer
  toolsets.

## Log forwarding

Router logs can contain client MAC addresses, host names, addresses, account names, and
other operational data supplied by the router or its clients. Forwarding sends this data
to the configured external sink, where that sink's access and retention policies apply.

Set `[logs] redact_macs = true` when stable hardware addresses are not needed in the
destination. This option redacts MAC addresses before records are broadcast to subscribers
or queued for sinks. It does not remove other identifiers from free-form router messages;
operators should restrict sink access and choose an appropriate retention period.

Passwords, bearer tokens, and API keys are loaded from configured files and are excluded
from kcc `Debug`, error, and tracing output. They are still transmitted to the selected
sink as HTTP authentication material, so use HTTPS outside loopback and protect the
credential files.

`KCC_MASTER_KEY_FILE` points to the key outside the state directory. A backup or copy of
state does not decrypt itself: restore the same key separately or the sealed router
credentials and other encrypted records are permanently unrecoverable. The
`password_file`, `read_password_file` and `token_file` paths of `kcc.toml` routers are
never imported by this store. The files given to `kcc router add/edit`
(`--password-file`, `--token-file`, `--read-password-file`) are read once and may be
deleted afterwards; kcc never deletes or rewrites them.

Records queued for a sink are kept in memory only (up to `[logs] queue_max` per sink)
and are lost at exit or on overflow.
