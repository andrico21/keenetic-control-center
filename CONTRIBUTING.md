# Contributing

Thanks for helping. Fork the repository, branch from `master`, and open a pull request
with focused commits. Read `AGENTS.md` and the Rust guidelines it lists before writing
Rust code; the project overlay `docs/rust-guidelines/overlays/projects/keenetic-control-center.md`
is binding. Don't edit the vendored guideline files.

## Gate G0: every change

Run from the repository root; every Rust change leaves all of these green:

```text
cargo +nightly-2026-11-22 fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
cargo xtask allow-gate
cargo xtask profile-eq
```

## Gate G1: releases

G0 plus `cargo deny check`, `cargo audit`, `cargo vet`, `cargo machete`,
`cargo xtask lint-completeness`, `cargo xtask i18n-check`, `cargo xtask assets-check`,
`cargo xtask cancel-safety`, `taplo fmt --check`, per-library default-feature
`cargo clippy -p <crate> --all-targets -- -D warnings` and `cargo test -p <crate>`, and
the MSRV build `cargo +1.100.0 build --workspace --all-features`. A new dependency needs
`cargo vet` and `cargo deny` to pass.

CI (`.github/workflows/ci.yml`) runs these gates on every push to `master` and every pull
request against it. The release and container workflows call the same `ci.yml` first,
so a tag is built and published only after every gate passes.
`scripts/ci-local.sh` runs the same commands on a Linux host.

## Dependency cooldown

`.cargo/config.toml` sets a 3-day publish-age cooldown: `cargo add` and `cargo update`
skip versions published less than 3 days ago, and Dependabot waits the same 3 days.
Versions already in `Cargo.lock` are not re-checked, so review lockfile diffs like code.
A RUSTSEC fix younger than the cooldown takes the emergency path in the vendored core,
`docs/rust-guidelines/RUST_GUIDELINES.md` Section 10 ("Hold new dependency versions back
with a publish-age cooldown"), in one commit.

## Dependency bumps

`cargo vet` checks the root workspace (`supply-chain/`) and the xtask workspace
(`xtask/supply-chain/`) against audits imported from public sets (bytecode-alliance,
embark-studios, google, isrg, mozilla, zcash). In the commit that changes a lockfile:

1. Run `cargo vet` (and `cargo vet --manifest-path xtask/Cargo.toml` for xtask). It
   fetches the imported sets and updates `imports.lock`.
2. For each crate it reports that no imported set covers, add a targeted
   `cargo vet add-exemption <crate> <version> --criteria safe-to-deploy`, and name every
   added exemption in the commit body. Never re-create exemptions in bulk, and never
   `cargo vet certify` a crate you have not actually reviewed.
3. Run `cargo vet prune` to drop exemptions the imports now cover.

CI runs `cargo vet --locked` for both workspaces.

## Lint rules

- The workspace lint profile is strict (Clippy pedantic, nursery and most of
  restriction). `cargo xtask lint-completeness` keeps it complete.
- No `#[allow(...)]` or `#![allow(...)]` anywhere; `cargo xtask allow-gate` fails on
  one. Silence a lint with `#[expect(lint, reason = "...")]` on the narrowest item.
- No `unwrap`, `expect`, `panic!`, `println!` or `dbg!` outside tests, and no `unsafe`.
- Product code never starts subprocesses (`crates/kcc/tests/source_guards.rs`).
- Keep files under about 250 non-blank, non-comment lines; split by responsibility.
- Tests never contain real secrets or router identifiers: build dummy keys at run time
  and use documentation address ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
  and `02:` MAC addresses. A scanner test enforces this.

## Tests

- Unit tests live inline; integration tests in each crate's `tests/`, always against
  the fake router (`kcc_testkit::FakeRouter::spawn()`), never a real one.
- Live tests (`crates/kcc/tests/live_*.rs`) are ignored by default and run only with the
  `KCC_LIVE_*` variables from `AGENTS.md`, against routers marked `test_device = true`.
- Tests must not depend on timing: wait for an event or state change with a bounded
  timeout instead of sleeping.
- A test under a paused tokio clock (`start_paused = true`) serves the fake router with
  `FakeRouter::serve_local` and registers the socket with `RouterRegistry::with_local_socket`
  (or `OutboundPolicy::with_local_socket`) on Unix: loopback TCP delivers asynchronously on
  macOS and the paused clock jumps ahead of written replies. See `crates/kcc-web/tests/support/build.rs`; Windows keeps TCP.

## CI runners

kcc refuses to run with an elevated Windows token (the privilege floor in
`docs/SECURITY.md`), and GitHub's `windows-latest` runner runs every job elevated. So
the Windows leg of `ci.yml` starts `cargo test` through `.github/scripts/deelevate.ps1`,
which launches it with a non-elevated token and fails the step at once if the child is
still elevated. Never weaken the check to make a runner pass.

To iterate on one runner without the whole matrix, dispatch the `Probe` workflow with a
filtered `cargo test` (the Windows probe uses the same launcher):

```text
gh workflow run probe.yml -f os=macos-latest -f command='-p kcc-app --test platform_timing_probe -- --ignored' -f repeat=3
```

`-f token_probe=true` adds a job that prints, for each way of starting a de-elevated
child on `windows-latest`, whether its token is elevated, its integrity level, and the
groups and privileges that keep it elevated.

## Documentation checks

`cargo test -p kcc --test docs` checks the documentation:

- **Examples.** Fenced blocks tagged `bash kcc-doc-test` in `README.md` and `docs/*.md`
  run against a fake router, in document order, one fresh environment per file. Each
  block runs under `bash -euo pipefail` in a temporary directory with the built `kcc`
  first on `PATH`, a private `HOME`, XDG directories and master key, a `kcc.toml` that
  admits the fake router's loopback address, `$ROUTER_URL` set to the fake router and
  `router.pw` holding its password. A non-zero exit fails the test. Tag only commands
  that exist and work without a terminal; use `text` blocks for everything else.
- **Configuration reference.** `docs/CONFIG.md` must list exactly the keys `kcc.toml`
  accepts. The test asks the real `Config` deserializer for each table's field list, so
  a new setting without a row (or a row for a removed one) fails.
- **Links.** Every relative link and anchor in `README.md` and `docs/*.md` must
  resolve. If `lychee` is installed, `lychee --offline` runs too.
- **Firmware table.** The `hardware-verified` lines in `docs/FIRMWARE.md` must equal
  `HARDWARE_VERIFIED`.

Generated documents (`docs/MCP_TOOLS.md`, `docs/METRICS.md`) are rebuilt with
`cargo xtask gen-tool-docs` and `cargo xtask gen-metric-docs`.

## Fixtures

The fake router serves fixtures from `crates/kcc-testkit/fixtures/`. To capture a new
one from a router you own:

```text
cargo run -p kcc-testkit --bin kcc-capture -- --url http://192.168.1.1 \
  --password-file router.pw --allow-serial <serial>
```

It refuses a router whose serial isn't listed, only reads, and anonymizes identifiers
before writing `<hw_id>-<firmware>/`. Review the output before committing it. Document
simulator behaviour you rely on in `crates/kcc-testkit/BEHAVIOUR.md`, marked `assumed`
until a live run confirms it.

## Translations

Every user-visible string lives in `crates/kcc-i18n/locales/<locale>/*.ftl` (en, ru, uk,
de, be, kk). Add the English message, run `cargo xtask i18n-gen`, add the message to
every other locale with the same variables, then run `cargo xtask i18n-check`. Details
in [docs/I18N.md](docs/I18N.md).

## Commits

Use Conventional Commits (`feat(web): ...`, `fix(rci): ...`, `docs: ...`) and update
[CHANGELOG.md](CHANGELOG.md) for user-visible changes. Report security problems
privately as described in [docs/SECURITY.md](docs/SECURITY.md).
