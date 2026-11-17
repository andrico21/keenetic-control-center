# Configuration reference

kcc reads one TOML file, `kcc.toml`: `--config <path>`, else `kcc.toml` in the platform
config directory (`~/.config/kcc` on Linux, `~/Library/Application Support/kcc` on
macOS, `%APPDATA%\kcc` on Windows). A missing file means every default. Unknown tables
and keys are rejected at startup. [kcc.example.toml](../kcc.example.toml) lists the
kcc sections with their defaults.

Durations use humantime syntax (`30s`, `15m`, `12h`, `180d`). Secrets never go in this
file: routers and log sinks name files that hold them. On Unix each such file, and
`[server] tls_key_path`, must be readable by its owner only (mode 0600 or 0400): kcc
refuses a file that group or others can access when it connects to the router, loads
the log sink or starts `kcc serve`. Windows has no such mode check.

**Environment overrides.** `KCC_<SECTION>_<KEY>` overrides a key of the kcc sections
`[web]`, `[mcp]`, `[outbound]`, `[state]`, `[backups]`, `[audit]`, `[cli]`, `[privacy]`,
`[metrics]` and `[logs]` (not `[logs] sinks`; only the keys listed in
`crates/kcc-app/src/settings/env_overrides.rs` have a variable), for example `KCC_WEB_ENABLED=false` or
`KCC_OUTBOUND_ALLOWED_NETWORKS=192.168.1.0/24,10.0.0.0/8`. Booleans are
`true`/`false`/`1`/`0`, lists are comma-separated. `[[routers]]` has no overrides.
`[server]` and `[observability]` use `RMCP_SERVER_KIT__SERVER__<KEY>` and
`RMCP_SERVER_KIT__OBSERVABILITY__<KEY>`. `KCC_MASTER_KEY_FILE` names the master key
file outside the state directory (default `<config dir>/kcc/master.key`). Back it up
separately: sealed router credentials and other encrypted state are unrecoverable without
the same 32-byte key.

**Reload.** On Unix, `SIGHUP` makes `kcc serve` re-read the file and apply API keys,
accounts (the Web sessions of a deleted or disabled account, or one with another role or
password, end), roles (to MCP and to signed-in Web UI sessions) and router profiles
(added routers are exported to `/metrics` at once, removed ones dropped); a rejected file
keeps the previous one, and keys and accounts still apply. `kcc serve` also applies API
key and account changes by itself within about 2 seconds, without `SIGHUP`. Other changes
need a restart.

## Top level

| Key | Type | Default | Meaning |
|---|---|---|---|
| `server` | table | see below | HTTP listener (rmcp-server-kit) |
| `observability` | table | see below | logging (rmcp-server-kit) |
| `web` | table | see below | Web UI |
| `mcp` | table | see below | MCP server |
| `outbound` | table | see below | which router addresses kcc may contact |
| `state` | table | see below | state directory |
| `backups` | table | see below | backup retention |
| `audit` | table | see below | audit retention |
| `cli` | table | see below | identity of CLI runs |
| `privacy` | table | see below | data minimization |
| `metrics` | table | see below | Prometheus exporter |
| `logs` | table | see below | router log collection and forwarding |
| `routers` | array of tables | none | read-only router profiles |

## `[web]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | serve the Web UI |
| `session_idle` | duration | `30m` | sign out after this much inactivity |
| `session_absolute` | duration | `12h` | sign out this long after login regardless of activity |
| `login_max_failures` | integer | `5` | failed logins before the account locks (at least 1) |
| `lockout` | duration | `15m` | how long a locked account stays locked |
| `default_locale` | string | `"en"` | language for users who haven't chosen one: `en`, `ru`, `uk`, `de`, `be`, `kk` |
| `public_url` | URL | unset | externally reachable base URL behind a reverse proxy; without listener TLS it needs `[server] trusted_proxies` |

An `https` `public_url` also makes the session cookie `Secure` with the `__Host-` prefix and
turns on the TLS content security policy, as listener TLS does.

A Web UI on a non-loopback listener needs TLS or an https `public_url` behind trusted
proxies; kcc refuses to start otherwise.

## `[mcp]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `http_enabled` | bool | `true` | serve MCP over Streamable HTTP on `/mcp` (API key required) |
| `stdio_enabled` | bool | `false` | allow `kcc mcp stdio`, which bypasses HTTP authentication |
| `stdio_role` | string | `"viewer"` | role of the stdio identity; must exist |
| `read_only` | bool | `false` | register only read tools |
| `allow_destructive` | bool | `false` | allow destructive tools and raw changes to management settings (each call still needs `confirm: true`) |
| `max_result_bytes` | integer | `32768` | cap on the JSON text of one tool result; larger results are truncated: error codes and status members are kept and the largest array is cut |
| `toolsets` | list of strings | `["core"]` | tool groups to register: `core`, `network-write`, `vpn`, `dns`, `system-admin`, `migration`, `presets`, `raw` ([MCP_TOOLS.md](MCP_TOOLS.md)) |

## `[outbound]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `allowed_networks` | list of CIDRs | `[]` | networks router addresses must fall into; empty admits none |
| `allowed_suffixes` | list of strings | `[]` | DNS suffixes whose resolved global addresses are admitted, e.g. `"keenetic.pro"`; values are case-insensitive, normalized with a leading dot, and match the bare name or subdomains only |
| `allow_loopback` | bool | `false` | admit literal and resolved loopback router addresses; required even when a loopback CIDR is in `allowed_networks` |
| `argon2_max_iterations` | integer | `16` | most Argon2 iterations a router may ask for at ndw4 sign-in, 1 to 64 (the protocol maximum); a router asking for more is refused ("router authentication cost exceeds local policy") before any key is derived, so a host posing as a router cannot make kcc spend 64 passes over 256 MiB per sign-in; raise it only for a router that needs more |

IPv4-mapped, NAT64 (`64:ff9b::/96`), SIIT IPv4-translated (`::ffff:0:0:0/96`),
IPv4-compatible (`::/96`) and 6to4 (`2002::/16`) addresses are checked against both
their outer IPv6 address and embedded IPv4 address. Unspecified, multicast, broadcast
and cloud metadata addresses (`169.254.169.0/24`, `169.254.170.0/24`, `fd00:ec2::/64`,
`100.100.100.200`), plus local-use NAT64 and Teredo forms, are never admitted by any
setting. The documentation prefix `3fff::/20` and SRv6 SIDs `5f00::/16` are
non-global and therefore cannot be admitted by a suffix. See [SECURITY.md](SECURITY.md).

The policy is deny-by-default: with both lists empty (the default), kcc contacts no
router outside loopback (and loopback only with `allow_loopback = true`). Adding or
testing a router outside the lists (`kcc router add`, `kcc router test`, the Web UI's
router form), or using a router from `[[routers]]` that lies outside them, is refused
with a message that names the relevant setting and the router's address. A suffix admits
only global addresses; private and link-local router names still need `allowed_networks`.
`kcc serve` logs one warning at startup when routers are configured but
`allowed_networks` and `allowed_suffixes` are both empty. The CLI reads `kcc.toml` on
every run; a running `kcc serve` applies a changed `[outbound]` section after a restart.
A router URL may name an IPv4 or bracketed IPv6 literal (`http://[fd00::1]`), which is
checked as an address. Router and log sink connections ignore the `HTTP_PROXY`,
`HTTPS_PROXY` and `ALL_PROXY` environment variables and always connect directly.

## `[state]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `dir` | path | platform state directory | where accounts, keys, backups, presets, jobs and the audit log live (`~/.local/state/kcc` on Linux, `%LOCALAPPDATA%\kcc` on Windows) |

## `[backups]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `keep_last` | integer | `50` | backups kept per router; `0` disables the count limit |
| `max_age` | duration | `180d` | backups older than this are pruned; `0s` disables the age limit |

Pruning runs after each new backup. A backup file that cannot be read is skipped, left in place and logged by name; it does not stop pruning of the readable ones.

## `[audit]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `retention` | duration | `365d` | maximum age of complete rotated audit files; `0s` disables age pruning |

Pruning runs after rotation. A rotated file is removed only when its newest entry is
older than the retention bound, so a file that overlaps the cutoff stays intact. Pruning
removes only the oldest run of fully expired files. The
first retained entry keeps its original `prev_hash` as the deleted prefix's chain anchor;
`kcc audit verify` reports that anchor while verifying the retained suffix.

Finished background-job records under `<state>/jobs/` are retained for 30 days. Startup
removes older completed, failed, cancelled and interrupted records; running records are
never age-pruned and remain subject to normal crash recovery.

## `[cli]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `role` | string | `"admin"` | role CLI runs act as |
| `router_scope` | list of globs | `[]` | router ids the CLI may touch on top of the role's scope; empty means all |

## `[privacy]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `redact_clients_in_mcp` | bool | `false` | pseudonymize client MACs, names, host names and addresses, also inside free text and progress messages, in MCP results; pseudonyms last for one process run ([PRIVACY.md](PRIVACY.md)) |

## `[metrics]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | serve the Prometheus `/metrics` endpoint |
| `bind` | socket address | `"127.0.0.1:9090"` | listener of the unauthenticated, plaintext endpoint; port at least 1024 |
| `allow_non_loopback` | bool | `false` | required for a non-loopback `bind` |
| `interval` | duration | `30s` | refresh of light items (at least `15s`) |
| `heavy_interval` | duration | `120s` | refresh of heavy items (at least `60s` and at least `interval`) |
| `per_client` | bool | `false` | export per-client series |
| `per_client_max` | integer | `256` | per-router cap on exported clients (at least 1); overflow is counted |
| `per_client_label` | string | `"pseudonym"` | client label: `name`, `pseudonym` (a per-router keyed hash, stable for one process run) or `mac` |

See [MONITORING.md](MONITORING.md) and [METRICS.md](METRICS.md).

## `[logs]`

Router log collection and sink forwarding run only in the long-lived `kcc serve` process;
short-lived commands such as `kcc mcp stdio` do not start collectors or sinks.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | collect router logs |
| `routers` | list of strings | `[]` | router ids to collect; empty selects every router |
| `mode` | string | `"stream"` | `stream` (falls back to polling after repeated failures) or `poll` |
| `stream_interval` | duration | `5s` | delay between reads of a background stream (at least `5s`) |
| `poll_interval` | duration | `30s` | delay between snapshot reads (at least `5s`) |
| `redact_macs` | bool | `false` | replace MAC addresses in messages before forwarding |
| `queue_max` | integer | `10000` | pending records kept per sink (at least 1); the oldest are dropped on overflow |
| `sinks` | array of tables | none | destinations, below |

### `[[logs.sinks]]` with `kind = "loki"`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `url` | URL | required | Loki base URL; kcc appends `/loki/api/v1/push`. https, or http on loopback |
| `tenant` | string | unset | sent as `X-Scope-OrgID` |
| `basic_auth_user` | string | unset | HTTP Basic user; needs `password_file` |
| `password_file` | path | unset | file with the Basic password |
| `bearer_token_file` | path | unset | file with a bearer token (instead of Basic) |
| `ca_file` | path | unset | PEM CA certificate to trust |
| `compress` | bool | `false` | gzip request bodies |

### `[[logs.sinks]]` with `kind = "elasticsearch"`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `url` | URL | required | base URL; kcc appends `/_bulk`. https, or http on loopback |
| `flavor` | string | `"elasticsearch"` | `elasticsearch` (data stream `logs-keenetic.syslog-default`) or `opensearch` (daily `keenetic-logs-YYYY.MM.DD`) |
| `target` | string | unset | override the data stream or index |
| `basic_auth_user` | string | unset | HTTP Basic user; needs `password_file` |
| `password_file` | path | unset | file with the Basic password |
| `api_key_file` | path | unset | file with an API key, sent as `Authorization: ApiKey` |
| `ca_file` | path | unset | PEM CA certificate to trust |
| `compress` | bool | `false` | gzip request bodies |

### `[[logs.sinks]]` with `kind = "stdout"`

No other keys: one JSON object per line on standard output.

## `[[routers]]`

Routers listed here are read-only in the Web UI and take precedence over routers added
with `kcc router add` or the Web UI, which live in the state directory.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `name` | string | required | profile id, 1 to 32 of `a-z 0-9 -` |
| `url` | URL | required | router base URL, `http` or `https` |
| `login` | string | unset | login name; required unless `auth = "token"` |
| `password_file` | path | unset | file holding the password |
| `read_login` | string | unset | separate login for the shared read-only poller |
| `read_password_file` | path | unset | its password file |
| `token_file` | path | unset | file holding an API token |
| `auth` | string | `"auto"` | `auto`, `ndw2`, `ndw4`, `token` or `digest` |
| `tls` | string or table | `"verify"` | `"verify"` against trusted roots, or `{ pin_sha256 = "<64 hex digits>" }`, the SHA-256 of the certificate's public key |
| `test_device` | bool | `false` | live test suites may change this router |
| `tags` | list of strings | `[]` | free-form labels |

`auth` selects the sign-in scheme of the router: `auto` takes ndw4 when the router
offers it and ndw2 otherwise, `ndw2` and `ndw4` force one scheme, `digest` signs every
request with HTTP Digest (KeenDNS HTTP proxy), and `token` sends the contents of
`token_file` in the `X-NDMA-TKN` header. A profile sets exactly one of `password_file`
and `token_file`; `token_file` needs `auth = "token"` (or `auto`, which then means
`token`). `auth` and `token_file` apply to `[[routers]]` entries only.

These profile credential paths are operator-managed and are read unchanged (a migration
that changes the router's management password writes the new one into `password_file`,
mode 0600). Routers added with the Web UI or `kcc router add` are different: every
credential they take (password, login token, read-only polling password) is sealed into
`<state>/router-credentials/<id>.sealed`, `<id>.token.sealed` or `<id>.read.sealed`,
and the input file given with `--password-file`, `--token-file` or
`--read-password-file` is never referenced again. `kcc router add/edit` take the same
`--auth` modes as `auth` here. A state router stored by an older kcc with an external
password file keeps working and is warned about once per CLI run and at `kcc serve`
startup, naming `kcc router edit <id> --new-password --password-file <file>`.

## `[server]` (rmcp-server-kit)

kcc passes this section to rmcp-server-kit 3.21, which runs the shared HTTP listener.
kcc replaces three of its settings: `auth` (kcc uses the API keys from `kcc apikey`,
30 requests per minute per key), `security_headers` (kcc sends its own Content Security
Policy) and `extra_route_rate_limit` (600 per minute for the Web UI).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `listen_addr` | IP literal | `"127.0.0.1"` | listen address; IPv6 in brackets |
| `listen_port` | integer | `8443` | listen port |
| `tls_cert_path` | path | unset | PEM certificate; with `tls_key_path` enables TLS |
| `tls_key_path` | path | unset | PEM private key |
| `tls_handshake_timeout` | duration | `"10s"` | per-handshake deadline |
| `max_concurrent_tls_handshakes` | integer | `256` | cap on in-flight TLS handshakes |
| `shutdown_timeout` | duration | `"30s"` | graceful shutdown timeout |
| `request_timeout` | duration | `"120s"` | per-request timeout |
| `max_request_body` | integer | `1048576` | maximum request body in bytes |
| `allowed_origins` | list of strings | `[]` | extra `Origin` values allowed on browser requests, in addition to the Web UI listener and `web.public_url` origins derived by kcc; use this for another trusted reverse-proxy origin |
| `stdio_enabled` | bool | `false` | the kit's stdio switch; kcc uses `[mcp] stdio_enabled` instead |
| `tool_rate_limit` | integer | unset | MCP tool calls per source IP per minute |
| `tool_rate_limit_burst` | integer | unset | burst for `tool_rate_limit` |
| `extra_route_rate_limit` | integer | unset | replaced by kcc (600) |
| `extra_route_rate_limit_burst` | integer | unset | burst for the Web UI rate limit |
| `extra_route_rate_limit_exempt_paths` | list of strings | `[]` | exact paths exempt from the Web UI rate limit |
| `request_log_exclude_paths` | list of strings | `["/healthz", "/readyz"]` | paths left out of request logs |
| `log_context` | table | see below | extra fields on request log lines |
| `key_eviction_policy` | string | `"evict_lru"` | full rate-limit table: `evict_lru` or `reject_new` |
| `trusted_proxies` | list of CIDRs | `[]` | reverse proxies whose forwarding header is trusted |
| `trusted_forwarder_max_entries` | integer | `16` | forwarding-chain entries scanned (1 to 64) |
| `forwarded_header` | string | `"x-forwarded-for"` | `x-forwarded-for` or `forwarded`; needs `trusted_proxies` |
| `session_idle_timeout` | duration | `"20m"` | MCP session idle timeout |
| `session_binding` | bool | `true` | bind MCP session ids to the authenticated identity |
| `session_binding_secret` | string | unset | shared HMAC secret for session binding across instances |
| `task_binding` | bool | `false` | bind MCP task ids to their creator |
| `sse_keep_alive` | duration | `"15s"` | SSE keep-alive interval |
| `sse_priming_enabled` | bool | `true` | send the SSE priming event |
| `sse_retry` | duration | `"3s"` | reconnect hint in the priming event |
| `public_url` | string | unset | the kit's advertised base URL; kcc's Web UI uses `[web] public_url` |
| `compression_enabled` | bool | `false` | gzip/br compression of MCP responses |
| `compression_min_size` | integer | `1024` | minimum response size to compress |
| `max_concurrent_requests` | integer | unset | global cap on in-flight requests (excess gets 503) |
| `admin_enabled` | bool | `false` | the kit's `/admin/*` diagnostic endpoints |
| `admin_role` | string | `"admin"` | role required for them |
| `auth` | table | unset | replaced by kcc |
| `tool_list_filtering` | bool | `true` | filter `tools/list` by RBAC |
| `expose_build_metadata` | bool | `false` | build metadata on `/version` |
| `security_headers` | table | kit defaults | replaced by kcc |

### `[server.log_context]`

All default to `false` except where noted.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `client_ip` | bool | `false` | log the resolved client IP |
| `peer_ip` | bool | `false` | log the direct peer IP |
| `request_id` | bool | `false` | log the request-id header (needs `trusted_proxies`) |
| `request_id_header` | string | `"x-request-id"` | header read for `request_id` |
| `request_line` | bool | `false` | log method and path on failed authentication |
| `user_agent` | bool | `false` | log the sanitized User-Agent on failed authentication |
| `auth_scheme` | bool | `false` | log the authentication scheme on failed authentication |
| `mcp_hints` | bool | `false` | log MCP session presence and protocol version |
| `session_id_header` | string | `"plain"` | how `Mcp-Session-Id` appears in header logs: `plain`, `mask` or `hide` |
| `credential_fingerprint` | bool | `false` | log a short HMAC fingerprint of bearer credentials |
| `credential_owner` | bool | `false` | log the identity of a verified but rejected credential |
| `request_completion` | bool | `false` | DEBUG line with status and latency |

### `[server.security_headers]`

kcc replaces this table with its own headers, so these keys have no effect; they are
accepted for compatibility with rmcp-server-kit.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `x_content_type_options` | string | kit default | replaced by kcc |
| `x_frame_options` | string | kit default | replaced by kcc |
| `cache_control` | string | kit default | replaced by kcc |
| `referrer_policy` | string | kit default | replaced by kcc |
| `cross_origin_opener_policy` | string | kit default | replaced by kcc |
| `cross_origin_resource_policy` | string | kit default | replaced by kcc |
| `cross_origin_embedder_policy` | string | kit default | replaced by kcc |
| `permissions_policy` | string | kit default | replaced by kcc |
| `x_permitted_cross_domain_policies` | string | kit default | replaced by kcc |
| `content_security_policy` | string | kit default | replaced by kcc |
| `x_dns_prefetch_control` | string | kit default | replaced by kcc |
| `strict_transport_security` | string | kit default | replaced by kcc |

### `[server.auth]`

kcc replaces this table with the API keys from `kcc apikey`, so these keys have no
effect.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | kit default | replaced by kcc |
| `api_keys` | array | kit default | replaced by kcc API keys |
| `mtls` | table | unset | replaced by kcc |
| `rate_limit` | table | unset | replaced by kcc |
| `max_concurrent_verifications` | integer | kit default | replaced by kcc |
| `verification_wait` | duration | kit default | replaced by kcc |
| `oauth` | table | unset | replaced by kcc |

## `[observability]` (rmcp-server-kit)

| Key | Type | Default | Meaning |
|---|---|---|---|
| `log_level` | string | `"info,rmcp=warn,rmcp_server_kit=info"` | `tracing` filter; keep the default in production because `rmcp` debug/trace logs tool arguments, including secret fields |
| `log_format` | string | `"pretty"` | `pretty`, `json` or `text` |
| `audit_log_path` | path | unset | the kit's own append-only request audit file (separate from kcc's audit log) |
| `log_request_headers` | bool | `false` | log request headers at DEBUG (sensitive ones redacted) |
| `metrics_enabled` | bool | `false` | must stay `false`: use `[metrics]` |
| `metrics_bind` | string | `"127.0.0.1:9090"` | unused by kcc; use `[metrics] bind` |
| `log_plaintext_oauth_tokens` | bool | `false` | debugging only |
| `log_oauth_claim_values` | bool | `false` | debugging only |
| `log_tool_call_arguments` | bool | `false` | log MCP tool arguments in plain text; debugging only |
| `log_upstream_error_bodies` | bool | `false` | debugging only |
