# Project overlay: keenetic-control-center

**Load order:** core `RUST_GUIDELINES.md` -> `overlays/domains/http-services.md` ->
`overlays/domains/mcp-servers.md` -> this file.

## The project (verified 2026-11-05)

- **What:** `kcc`, a local control center for Keenetic and Netcraze routers. It talks to
  routers over the RCI HTTP API and exposes a Web UI, an MCP server (built on
  `rmcp-server-kit`) and a CLI. It is **not published**: every crate sets
  `publish = false`.
- **Workspace:** root `Cargo.toml` with `members = ["crates/*"]` and `exclude = ["xtask"]`.
  Library crates `kcc-rci`, `kcc-catalog`, `kcc-config`, `kcc-domain`, `kcc-migrate`,
  `kcc-app`, `kcc-telemetry`, `kcc-i18n`, `kcc-web`, `kcc-mcp`, `kcc-testkit`; binary crate
  `kcc`. `xtask/` is a separate workspace with lint tables equal to the root profile.
- **Toolchain:** edition 2024, `rust-version = "1.99.1"`, `unsafe_code = "forbid"`.
  No `rust-toolchain.toml`. Formatting uses the dated nightly `nightly-2026-10-03`
  (`rustfmt.toml` sets `imports_granularity`/`group_imports`); MSRV is checked with
  `cargo +1.99.1 build --workspace --all-features`.
- **CI:** `.github/workflows/ci.yml` (jobs fmt, clippy, test, rustdoc, deny, audit, vet,
  machete, msrv, gates, xtask, taplo, guidelines) and `.github/dependabot.yml`.
- **Notable dependencies:** `rmcp-server-kit`, `axum`, `askama`, `reqwest`/`rustls`,
  `secrecy`, `zeroize`, `chacha20poly1305`, `serde`, `tokio`, `tracing`, `proptest`
  (dev), `rcgen` (dev).
- **Vendored rules:** `docs/rust-guidelines/` holds the core, `http-services.md` and
  `mcp-servers.md` byte-for-byte at the commit in `PIN`, with `SHA256SUMS` checked by the
  CI `guidelines` job. This file is the project's own overlay and is not covered by the
  sums. The root `RUST_GUIDELINES.md` is the pointer file.

## Project-specific rules

- **(a) Outbound requests go only to registered router profiles that pass the router
  outbound policy.** Scheme `http` or `https` only; no redirects followed; the resolved
  address must fall inside `[outbound] allowed_networks`; cloud-metadata addresses
  (`169.254.169.254` and equivalents) are always refused; TLS is verify-or-pin, never
  skipped. This is the LAN-management adaptation of the http-services SSRF rule (see
  deviation 1).
- **(b) Raw RCI input is validated before sending.** Every raw RCI request or CLI line that
  comes from a tool argument, a form field or a CLI argument is validated against
  `kcc-catalog` and the identifier validators before it reaches a router.
- **(c) Every curated write is read back and compared.** A write that the router accepts
  but does not apply fails with a verification error naming the field.
- **(d) Secrets live in `secrecy`/`zeroize` types.** They never reach logs, the audit
  log, tool results, error text or `Debug` output.
- **(e) Web UI hardening.** No inline script or style; CSP `default-src 'none'` plus
  explicit `'self'` sources; CSRF protection on every state-changing request; askama
  auto-escaping only, no bypass.
- **(f) Localization.** Every user-visible string comes from `kcc-i18n`, and
  `cargo xtask i18n-check` passes for en, ru, uk, de, be and kk.
- **(g) Live tests only against test devices.** Live suites run only against router
  profiles marked `test_device = true`.
- **(h) Not a published library.** All crates are `publish = false`, so
  `cargo semver-checks` does not apply. This is a statement of scope, not a deviation.
- **(i) Privacy.** No stored client telemetry history; retention limits apply to the
  audit log and backups; MCP honours `redact_clients`.

## Deviations to resolve (status 2026-11-05)

1. **Router targets in private address space** (opened 2026-11-05, open). The
   http-services SSRF rule ("DO: Prevent SSRF") rejects private and loopback targets, but
   a LAN router manager has to reach them. kcc follows rmcp-server-kit's
   operator-configured `OAuthSsrfAllowlist` precedent: router profiles are admin-only,
   the operator sets `allowed_networks`, metadata addresses are always refused, and each
   target is resolved once and pinned. **Task:** propose an http-services clarification
   for operator-configured management targets upstream (tracked in `UPSTREAM.md`). Until
   it lands, rule (a) is the only accepted shape; it is not a licence to widen outbound
   access.

## Common alignment steps

- **Lint tables.** The root `[workspace.lints]` is the core Section 9 profile verbatim;
  every member sets `[lints] workspace = true`; `xtask/` carries equal tables, checked by
  `cargo xtask profile-eq`.
- **No `#[allow]`.** Exceptions are `#[expect(lint, reason = "...")]` on the narrowest
  item; `cargo xtask allow-gate` enforces it.
- **`.cargo/config.toml`.** Commits `[build] warnings = "deny"`.
- **Old guideline file.** The root `RUST_GUIDELINES.md` is a pointer; the rules are
  vendored under `docs/rust-guidelines/` at a recorded pin with checksum CI, as in
  rmcp-server-kit.
