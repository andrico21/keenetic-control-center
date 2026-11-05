# Issues - keenetic-control-center

Problems and gotchas encountered during work on this plan.

_Auto-scaffolded by /ulw-execute. Append new entries below - never overwrite._

---

## [2026-11-05] Task: todo-16 catalog validation follow-up
- `kcc-catalog` still has no stable runtime command-query API usable by `kcc-testkit`; fake-router CLI parse currently uses the plan-permitted minimal allowlist for interface description/address plus simulator control commands. Replace it with profile-aware generated catalog lookup when that API lands.
- Full workspace G0 is currently blocked by concurrent unrelated work: nightly fmt reports `crates/kcc-catalog/src/generated.rs` and `crates/kcc-rci/src/auth.rs`, and workspace tests reject unused `kcc_catalog::generated::FILES` in the catalog lib-test harness. Testkit-scoped fmt/clippy/tests/rustdoc and workspace rustdoc/gates are clean.

## Todo 5 (CI) - blockers found while running scripts/ci-local.sh (2026-11-05)
- macOS and Windows legs of the `test` job are CI-only; not verifiable on this Linux host.
- `cargo clippy --manifest-path xtask/Cargo.toml --all-targets --all-features -- -D warnings` FAILS AT HEAD (verified in a clean `git archive HEAD` copy): `xtask/src/main.rs:7` `#![expect(clippy::multiple_crate_versions)]` is unfulfilled, most likely because root clippy.toml `allowed-duplicate-crates` (extended in todo 18 with getrandom etc.) is picked up from the parent dir and silences the lint. Needs an xtask/main.rs (or xtask clippy.toml) fix by an owner of xtask; todo 5 was told not to touch it.
- `taplo fmt --check` FAILS AT HEAD for Cargo.toml (root, byte-for-byte R-GUIDE template), clippy.toml, deny.toml, xtask/Cargo.toml, crates/kcc-{app,rci,testkit}/Cargo.toml, catalog/*.toml: no .taplo.toml existed and the files use 4-space indent + aligned comments. Added `.taplo.toml` (excludes target, spikes, supply-chain, catalog/.cache, stray literal `~/` dir created by cargo-audit's db-path); remaining failures need either a decision on taplo formatting options vs the vendored template or reformatting those files.
- `cargo machete crates xtask` fails in the working tree only because another agent has uncommitted kcc-rci/Cargo.toml dependency edits (todo 7); passes on `git archive HEAD`. The same in-progress kcc-rci edits (and xtask/src/catalog_build.rs) break workspace clippy/msrv in the working tree.
- A stray directory literally named `~` exists in the repo root (`~/.cargo/audit-advisory-db` from `.cargo/audit.toml` db-path with no tilde expansion); also deny.toml `db-path = "~/.cargo/advisory-db"`. Consider fixing.

## [2026-11-05] Todo 20 verification constraints
- LSP diagnostics timed out twice. The scoped compiler, focused no-deps Clippy, and integration tests are clean.
- Dependency-inclusive `cargo clippy -p kcc-app --all-targets --all-features -- -D warnings` reaches concurrent out-of-scope kcc-testkit additions and fails there (anonymize.rs/capture.rs strict-lint diagnostics). Full-workspace nightly fmt also reports those sibling files. Todo 20 did not modify kcc-testkit.

## [2026-11-05] Todo 33 follow-ups
- Todo 48 must use `kcc_web::csp::security_headers(tls)`; with the kit default the CSP would block every Web UI script/style and `Cache-Control: no-store` would defeat the hashed-asset cache. With it, `/mcp`, `/healthz`, `/readyz`, `/version` carry no Cache-Control (accepted: authenticated POST/SSE and small status documents without validators); revisit if the kit gains a per-route Cache-Control opt-out.
- Theme and language menus write their cookies client-side in `assets/js/app.js` (no state-changing endpoint before CSRF exists); without JavaScript they do nothing. Recorded as accepted debt in `crates/kcc-web/DESIGN.md` section 8; todo 34 may add a POST fallback behind CSRF.
