#!/usr/bin/env bash
# Runs every `run:` command of .github/workflows/ci.yml, in job order, on this
# host (Linux). The macOS and Windows legs of the `test` job are CI-only.
# Keep this file in step with ci.yml.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

export CARGO_BUILD_WARNINGS=deny
export CARGO_TERM_COLOR=always

step() { printf '\n=== %s ===\n' "$*"; }

step fmt
cargo +nightly-2026-11-21 fmt --all -- --check

step clippy-workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings

LIBRARIES=(kcc-app kcc-catalog kcc-config kcc-domain kcc-i18n kcc-mcp kcc-migrate kcc-rci kcc-telemetry kcc-testkit kcc-web)
for crate in "${LIBRARIES[@]}"; do
  step "clippy+test ${crate} (default features)"
  cargo clippy -p "${crate}" --all-targets -- -D warnings
  cargo test -p "${crate}"
done

step test
cargo test --workspace --all-features
cargo test --doc --workspace

step rustdoc
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features

step deny
cargo deny check

step audit
# Own database directory: an older cargo-deny may have left a non-git clone at
# cargo-audit's default $CARGO_HOME/advisory-db. CI runners start empty.
cargo audit --db "${CARGO_HOME:-$HOME/.cargo}/audit-advisory-db"

step vet
cargo vet --locked

step machete
cargo machete crates xtask

step msrv
cargo +1.100.0 build --workspace --all-features

step gates
cargo xtask allow-gate
cargo xtask profile-eq
cargo xtask i18n-check
cargo xtask assets-check
cargo xtask cancel-safety
shellcheck deploy/podman/*.sh scripts/*.sh scripts/live/*.sh
actionlint .github/workflows/*.yml
cargo xtask lint-completeness

step xtask
cargo clippy --manifest-path xtask/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path xtask/Cargo.toml --all-features
cargo deny --manifest-path xtask/Cargo.toml check

step taplo
taplo fmt --check

step guidelines
(cd docs/rust-guidelines && sha256sum -c SHA256SUMS)

step "all green"
