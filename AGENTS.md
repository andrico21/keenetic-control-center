# AGENTS.md

## Rust guidelines

Read, in this order, before writing or reviewing Rust code (see `RUST_GUIDELINES.md`):

1. `docs/rust-guidelines/RUST_GUIDELINES.md` (universal core)
2. `docs/rust-guidelines/overlays/domains/http-services.md`
3. `docs/rust-guidelines/overlays/domains/mcp-servers.md`
4. `docs/rust-guidelines/overlays/projects/keenetic-control-center.md` (always last)

Never edit the vendored files. Open deviations in the project overlay are tasks, not
permission.

## No `#[allow]`

No `#[allow(...)]` or `#![allow(...)]` anywhere. Use `#[expect(lint, reason = "...")]`
on the narrowest item. `cargo xtask allow-gate` enforces this.

## Commands

Gate G0 (every Rust change leaves it green, run from the repo root):

1. `cargo +nightly-2026-10-03 fmt --all -- --check`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
3. `cargo test --workspace --all-features`
4. `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`
5. `cargo xtask allow-gate` and `cargo xtask profile-eq`

Gate G1 (release): G0 plus `cargo deny check`, `cargo audit`, `cargo vet`,
`cargo machete`, `cargo xtask lint-completeness`, `cargo xtask i18n-check`,
`cargo xtask assets-check`, `cargo xtask cancel-safety`, `taplo fmt --check`, per-library default-feature
`cargo clippy -p <crate> --all-targets -- -D warnings` and `cargo test -p <crate>`, and
MSRV `cargo +1.100.0 build --workspace --all-features`.

Guidelines checksum: `(cd docs/rust-guidelines && sha256sum -c SHA256SUMS)`.

## Crate map

- `kcc-rci`: RCI HTTP client, auth, sessions, outbound policy
- `kcc-catalog`: command catalog per firmware version, request validation
- `kcc-config`: router config text parsing, `ns3` secrets, redaction
- `kcc-domain`: curated domains (system, interfaces, Wi-Fi, clients, routing, VPN, ...)
- `kcc-migrate`: config migration between routers
- `kcc-app`: config file, state store, permissions, audit, change sets
- `kcc-telemetry`: polling and live router metrics
- `kcc-i18n`: every user-visible string (en, ru, uk, de, be, kk)
- `kcc-web`: Web UI
- `kcc-mcp`: MCP server
- `kcc-ssh`: SSH transport to Entware: policy-admitted pinned TCP, pinned host key, closed typed command set
- `kcc-testkit`: fake router, fixtures, capture tool
- `kcc`: the binary
- `xtask/`: separate workspace for project gates and generators

## Test tiers

- Unit: inline `#[cfg(test)] mod tests`.
- Integration: each crate's `tests/*.rs`, against the fake router only.
- Live: `crates/kcc/tests/live_*.rs`, `#[ignore]`d, run only via
  `cargo test -p kcc --test <name> -- --ignored` when `KCC_LIVE_*` is set, and only
  against `test_device = true` profiles.

## Fake router

`kcc-testkit` provides `FakeRouter::spawn() -> (SocketAddr, Handle)` for tests and the
binary `cargo run -p kcc-testkit --bin kcc-fake-router -- --model KN-1811 --bind 127.0.0.1:18080 --password-file <file>`.
Models: `KN-1811`, `KN-1010`, `KN-3810`, `NC-3013`.

## Live env contract

- `KCC_LIVE_URL` (e.g. `http://192.168.1.1`), `KCC_LIVE_LOGIN`, `KCC_LIVE_PASSWORD_FILE`.
- `KCC_LIVE_ALLOW_WRITE=1` for write suites.
- `KCC_LIVE_SOURCE_FILE` (a saved startup-config, the default migration/preset source) or
  `KCC_LIVE_SOURCE_URL`/`_LOGIN`/`_PASSWORD_FILE`.
- `KCC_LIVE_TARGET_URL`/`_LOGIN`/`_PASSWORD_FILE` for the migration and preset rehearsal
  target.
- `KCC_LIVE_ALLOW_SERIAL`: comma-separated router serials. Every live test reads the
  serial via `show identification` of every router it contacts (the live migration source
  included) and refuses any router not listed.
- `KCC_LIVE_ALLOW_REBOOT=1`: only for probes that may reboot a test router.
- `KCC_LIVE_TARGET_CONFIG`: path of a `kcc.toml` whose `[[routers]]` entry for the suite's
  router (`KCC_LIVE_URL`, or `KCC_LIVE_TARGET_URL` for the migration and preset rehearsals)
  has `test_device = true`. Every live suite, read-only ones included, requires it and checks
  the profile before contacting the router; the serial check follows. kcc's own clients in
  the suites (the `kcc` child, the MCP registry, the migration probe) use this file's
  `[outbound]` table, so its `allowed_networks` must admit the router.
- `KCC_LIVE_COMMIT=1`: the live migration rehearsal commits instead of its default rollback.
- `KCC_LIVE_TELEGRAM_TOKEN_FILE`: path of a file holding a Telegram bot token (owner-readable).
- `KCC_LIVE_TELEGRAM_CHAT`: the chat id the Telegram live suite sends to. That suite
  (`crates/kcc/tests/live_telegram.rs`) contacts the real Bot API and no router, so it is
  exempt from `KCC_LIVE_TARGET_CONFIG` and `KCC_LIVE_ALLOW_SERIAL`; every other live suite
  keeps both.

A missing variable makes the live test log `live-skip:<reason>` through `tracing` and
return `Ok(())`. It never passes silently.

## Evidence

QA output goes to `.omo/evidence/task-<N>-keenetic-control-center.<ext>` (`.log`,
`.json`, `.png`), captured as `<cmd> 2>&1 | tee <evidence>`.
