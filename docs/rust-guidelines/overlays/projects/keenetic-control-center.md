# Project overlay: keenetic-control-center

**Load order:** core `RUST_GUIDELINES.md` -> `overlays/domains/http-services.md` ->
`overlays/domains/mcp-servers.md` -> this file.

## The project (verified 2026-11-14)

- **What:** `kcc`, a local control center for Keenetic and Netcraze routers. It talks to
  routers over the RCI HTTP API and exposes a Web UI, an MCP server (built on
  `rmcp-server-kit`) and a CLI. It is **not published**: every crate sets
  `publish = false`.
- **Workspace:** root `Cargo.toml` with `members = ["crates/*"]` and `exclude = ["xtask"]`.
  Library crates `kcc-rci`, `kcc-catalog`, `kcc-config`, `kcc-domain`, `kcc-migrate`,
  `kcc-app`, `kcc-telemetry`, `kcc-i18n`, `kcc-web`, `kcc-mcp`, `kcc-testkit`; binary crate
  `kcc`. `xtask/` is a separate workspace with lint tables equal to the root profile.
- **Toolchain:** edition 2024, `rust-version = "1.100.0"` (root and `xtask/`),
  `unsafe_code = "forbid"`. No `rust-toolchain.toml`; CI pins `1.100.0`. Formatting uses
  the dated nightly `nightly-2026-10-03` (`rustfmt.toml` sets
  `imports_granularity`/`group_imports`); MSRV is checked with
  `cargo +1.100.0 build --workspace --all-features`.
- **CI:** `.github/workflows/ci.yml` (jobs fmt, clippy, test, rustdoc, deny, audit, vet,
  machete, msrv, gates, xtask, taplo, guidelines) and `.github/dependabot.yml`. Gate tools
  are installed at pinned versions: cargo-deny 0.20.2, cargo-audit 0.23.0, cargo-vet
  0.10.3, cargo-machete 0.9.2, taplo 0.10.0 (see deviation 2); `release.yml` installs
  cargo-zigbuild 0.24.1. Dependabot carries a 3-day
  `cooldown` for both cargo ecosystems (`/`, `/xtask`).
- **Notable dependencies:** `rmcp-server-kit`, `axum`, `askama`, `reqwest`/`rustls`,
  `secrecy`, `zeroize`, `chacha20poly1305`, `serde`, `tokio`, `tracing`, `proptest`
  (dev), `rcgen` (dev).
- **Vendored rules:** `docs/rust-guidelines/` holds the core, `http-services.md` and
  `mcp-servers.md` byte-for-byte at the commit in `PIN` (upstream `andrico21/rust-guidelines`
  `49898c91ea69ca5b9d9510ad2db9e750f3c64847`, stable through Rust 1.100), with `SHA256SUMS` checked by the
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

## Deviations to resolve (status 2026-11-14)

1. **Router targets in private address space** (opened 2026-11-05, open). The
   http-services SSRF rule ("DO: Prevent SSRF") rejects private and loopback targets, but
   a LAN router manager has to reach them. kcc follows rmcp-server-kit's
   operator-configured `OAuthSsrfAllowlist` precedent: router profiles are admin-only,
   the operator sets `allowed_networks`, metadata addresses are always refused, and each
   target is resolved once and pinned. **Task:** propose an http-services clarification
   for operator-configured management targets upstream (tracked in [`docs/rust-guidelines/UPSTREAM.md`](../../UPSTREAM.md)). Until
   it lands, rule (a) is the only accepted shape; it is not a licence to widen outbound
   access.
2. **cargo-machete and taplo are pinned too** (opened 2026-11-14, accepted). Core
   Section 12 pins cargo-deny, cargo-audit and cargo-vet and says "the other tools stay
   unpinned". Here cargo-machete and taplo also run as merge-blocking CI jobs, so the
   core's reason (an unpinned install decides a merge and bypasses the cooldown) applies
   to them as well. Bump all five pins deliberately, together with this overlay, each to
   the newest non-yanked release at least three days old by its crates.io `created_at`
   (`cargo install` ignores the cooldown); last bumped 2026-11-18.
3. **Dependency versions not re-checked against "latest past the cooldown"** (opened
   2026-11-14, resolved 2026-11-18). Core Section 11 (Supply Chain) asks that every
   dependency be the version `cargo update` selects. Both workspaces (`/` and `xtask/`)
   now resolve with a plain `cargo update` under the cooldown, every crates.io
   requirement is written as its locked version, and a `cargo update --dry-run --verbose`
   changes nothing. Held back on 2026-11-18 (re-checked 17:45 UTC), all inside the
   cooldown unless named: brotli 9.1.3, bytes 1.12.2, clap/clap_derive 4.6.8,
   clap_complete 4.6.12, clap_lex 1.1.2, jiff/jiff-static 0.2.46 and jiff-core 0.1.8
   (xtask), regex-automata 0.4.19, regex-syntax 0.8.12, rmcp/rmcp-macros 3.11.0,
   smallvec 1.16.6, uuid 1.29.3, zeroize 1.9.2; matchit 0.8.6 is held by axum 0.8.9's
   `matchit = "=0.8.4"`. Repeat the check at least monthly (core Section 12).
4. **Rust versions in workflow files are unquoted** (opened 2026-11-14, resolved
   2026-11-18). Core Section 11 (Tooling) asks to quote every Rust version in YAML.
   `ci.yml`, `container.yml` and `release.yml` now quote every toolchain
   (`toolchain: "1.100.0"`, `toolchain: "nightly-2026-10-03"`); keep any new pin quoted.
5. **No `Cache-Control` on the kit's own routes** (opened 2026-11-16, open). The
   http-services rule on response headers wants `Cache-Control: no-store` on every
   authenticated response. kcc turns the kit's `Cache-Control` off in
   `crates/kcc-web/src/csp.rs`, because the kit sets it on every response and would
   replace the long-lived `immutable` policy of hash-addressed Web UI assets. The Web
   router sets `no-store` on all its other responses, so only the kit's routes (`/mcp`,
   health, version) go without the header. The kit has no setting to add it only when
   absent. **Task:** ask upstream for an if-not-present mode (listed in
   `docs/BACKLOG.md` under "Upstream"); once it lands, set `no-store` there and
   close this deviation.

## Common alignment steps

- **Lint tables.** The root `[workspace.lints]` is the core Section 9 profile verbatim,
  all four tables (`rust`, `rustdoc`, `clippy`, `cargo`); every member sets
  `[lints] workspace = true`; `xtask/` carries equal tables. `cargo xtask profile-eq`
  checks both: the tables are equal, and every member manifest has `workspace = true`
  under `[lints]` (an empty `[lints]` satisfies `cargo::missing_lints_inheritance`).
  `cargo xtask lint-completeness` runs the rustc, Clippy and Cargo legs of the core's
  completeness check; the Cargo leg reads `lints.html` from the `rust-docs` component and
  fails when it cannot.
- **No `#[allow]`.** Exceptions are `#[expect(lint, reason = "...")]` on the narrowest
  item; `cargo xtask allow-gate` enforces it.
- **`.cargo/config.toml`.** Commits `[build] warnings = "deny"` (which also gates Cargo's
  own lints on 1.100) and the core Section 10 dependency cooldown:
  `[registry] global-min-publish-age = "3 days"` and
  `[resolver] incompatible-publish-age = "deny"`. `CONTRIBUTING.md` points to the core's
  RUSTSEC emergency path.
- **Old guideline file.** The root `RUST_GUIDELINES.md` is a pointer; the rules are
  vendored under `docs/rust-guidelines/` at a recorded pin with checksum CI, as in
  rmcp-server-kit.
