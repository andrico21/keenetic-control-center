## X-review: build, CI and supply chain (read-only, HEAD 349b7fb)

### X-01 CI and container workflows trigger on `main`, but the repository's branch is `master`
- severity: high
- kind: bug
- rule: RUST_GUIDELINES.md §12 "Required CI Tools" ("MUST run in CI on every PR. Failure blocks merge."), AGENTS.md G0/G1
- evidence: `.github/workflows/ci.yml:3-8`
  ```yaml
  on:
    push:
      branches: [main]
    pull_request:
      branches: [main]
  ```
  `.github/workflows/container.yml:3-8` has the same filter. `CONTRIBUTING.md:3` says "Fork the repository, branch from `master`, and open a pull request". `git branch -a` lists only `master`.
- impact: Pushes to `master` and pull requests against it, including Dependabot's, start neither CI nor the container e2e. No G0 or G1 gate (fmt, clippy, test, deny, audit, vet, machete, xtask gates, shellcheck, actionlint) blocks a merge. This also explains how X-02 could go unnoticed.
- fix: Use `branches: [master]` in `ci.yml` and `container.yml`, or rename the default branch and update CONTRIBUTING.md. Then make the CI jobs required status checks.
- confidence: medium (INFERRED: no remote is configured locally, so I could not see GitHub's default branch. Every local signal says `master`; only the workflows and the Quadlet `Documentation=` URL, `deploy/podman/kcc.container:12`, say `main`.)

### X-02 The `gates` job cannot run `lint-completeness` as configured, and when it fails the other gates in that job are skipped
- severity: medium
- kind: bug
- rule: RUST_GUIDELINES.md §9 "Keeping the profile complete"; overlay "Common alignment steps" ("the Cargo leg reads `lints.html` from the `rust-docs` component and fails when it cannot")
- evidence: `xtask/src/cargo_lints.rs:41-47` reads `<sysroot>/share/doc/rust/html/cargo/reference/lints.html` and returns `GateError::Read` when it is missing. `xtask/src/lint_completeness.rs:56`:
  ```rust
  let clippy_help = stdout_of("rustup", &["run", "stable", "clippy-driver", "-W", "help"])?;
  ```
  `ci.yml:182-191`:
  ```yaml
  - uses: dtolnay/rust-toolchain@... # master
    with:
      toolchain: 1.100.0
  - uses: Swatinem/rust-cache@...
  - run: cargo xtask lint-completeness
  - run: cargo xtask allow-gate
  ...
  - run: cargo xtask cancel-safety
  ```
- impact: The job installs 1.100.0 without `rust-docs` or `clippy`, so the Cargo leg exits 2. Because the job's steps run in sequence, `allow-gate`, `profile-eq`, `i18n-check`, `assets-check`, `cancel-safety`, shellcheck and actionlint never run. The Clippy leg also reads whatever `stable` the runner ships, not the pinned 1.100.0 used by the rustc leg. When stable becomes 1.101, the gate fails, or the wrong list passes, with no code change.
- fix: Add `components: clippy, rust-docs` to the gates job, and replace `"stable"` with the active toolchain (for example `rustup run 1.100.0 clippy-driver`, or run `clippy-driver` from `rustc --print sysroot`). Move `lint-completeness` to the end of the job, or split it into its own job.
- confidence: medium (INFERRED: that dtolnay/rust-toolchain installs with `--profile minimal`, and which `stable` the runner image provides)

### X-03 e2e step functions ignore `set -e`, so failures in the middle of a step pass
- severity: medium
- kind: test-quality
- rule: project rule (g) (live suites must prove the behaviour); RUST_GUIDELINES.md §13 (tests that cannot fail)
- evidence: `deploy/podman/e2e.sh:74-77`
  ```bash
  step() {
    local name="$1"
    shift
    if "$@" >"${WORK}/step-${name}.log" 2>&1; then
  ```
  `e2e.sh:327-332`
  ```bash
  domain_write_save() {
    kcc --router fake-a --yes system set-description kcc-e2e-description
    kcc --router fake-a --yes dns static-host nas.kcc-e2e.test 192.0.2.40
    kcc --router fake-a --yes config save
    kcc --router fake-a --json config state
  ```
  `e2e.sh:414-421` (`sighup_reload`: only `healthz` decides the result). `live-e2e.sh:72-75` and `216-225`: `reversible_write` passes when `clients register` fails, because the final check only proves the MAC is *not* registered.
- impact: Bash ignores errexit inside a function called as an `if` condition. I confirmed this with a scratch run: `f(){ false; echo after; true; }; if f; then echo PASS; fi` prints PASS. The container e2e is the only proof that the seccomp profile allows the write and save path. If the profile misses a syscall that only `config save` uses, the step still passes. The `no-denials` grep does not catch it either, because kcc reports such failures as "RCI transport failed" (deploy/podman/README.md says so). A broken profile would then ship. The live "one reversible write" proves nothing.
- fix: In both `step()` helpers, run `set +e; ( set -e; "$@" ) >"$log" 2>&1; rc=$?; set -e`, then test `rc`. I verified this form returns 1 on a failure in the middle of the function.
- confidence: high

### X-04 Releases and published images skip every G1 gate
- severity: medium
- kind: security
- rule: AGENTS.md "Gate G1 (release)"; RUST_GUIDELINES.md §12 "Required CI Tools"
- evidence: `.github/workflows/release.yml:59-61` (`build: needs: meta`), then `106` `cargo zigbuild --release --locked ...`, then `156-161` (`release: needs: [meta, checksums]`, `contents: write`). `container.yml:105-108` (`push: needs: image`). Neither workflow runs or waits for test, clippy, deny, audit or vet.
- impact: Pushing a `v*` tag on any commit, including one that never went through CI (see X-01), publishes a GitHub release and `ghcr.io/...:<tag>` plus `:latest` with no advisory, license or test check. A RUSTSEC advisory published after the last merge is not caught at release time.
- fix: Expose `ci.yml` through `workflow_call` and add a `gates` job to `release.yml` and `container.yml` that the build and push jobs `need`. At minimum, run `cargo deny check` and `cargo audit` there.
- confidence: high

### X-05 No gate checks lint *levels* against the vendored profile
- severity: low
- kind: guideline
- rule: RUST_GUIDELINES.md §9 Policy, "Every crate uses the profile below, unchanged" and "No group-level `allow` in any manifest" (line ~1632-1645)
- evidence: `xtask/src/lint_completeness.rs:97-101` collects only key names:
  ```rust
  let configured: BTreeSet<String> = lints
      .values()
      .filter_map(toml::Value::as_table)
      .flat_map(|table| table.keys().cloned())
      .collect();
  ```
  `xtask/src/profile_eq.rs:34-36` compares xtask with root only.
- impact: Setting `unwrap_used = "allow"`, or `pedantic = "allow"`, in both `Cargo.toml` and `xtask/Cargo.toml` passes `lint-completeness`, `profile-eq` and clippy. The overlay's claim that the profile is "verbatim" is not enforced. Today the tables are identical to §9; I diffed them.
- fix: In `lint-completeness`, require every entry to be `deny` or `forbid`, except `redundant_pub_crate = "allow"`. Alternatively, extract the TOML block from the checksummed `RUST_GUIDELINES.md` and run `profile_eq::compare` against root.
- confidence: high

### X-06 The cargo-vet gate is nominal, and the documented bump procedure keeps it that way
- severity: low
- kind: security
- rule: RUST_GUIDELINES.md §10 "DO: Use `cargo vet` for supply chain trust" (line ~3033)
- evidence: `supply-chain/audits.toml:1-4` holds an empty `[audits]` table, against 307 `[[exemptions.*]]` entries, including `rmcp` and `rmcp-server-kit` (`supply-chain/config.toml:703-713`), `chacha20poly1305` (`:159`), `argon2` (`:51`), `rustls` (`:735`) and `reqwest` (`:695`). `ci.yml:147-150`:
  ```yaml
  # ... Bump dependencies and run `cargo vet regenerate
  # exemptions` in the same commit.
  - run: cargo vet --locked
  ```
- impact: Regenerating exemptions on every bump exempts the new version automatically. A compromised patch release of `rmcp-server-kit` that clears the 3-day cooldown would pass `cargo vet` once the bump commit follows the documented procedure.
- fix: On bumps, require `cargo vet` to pass through imports or `cargo vet certify`/`diff`, and stop regenerating exemptions in bump commits. Audit the direct security-critical crates first.
- confidence: high

### X-07 The xtask workspace's dependencies are never advisory- or vet-checked
- severity: low
- kind: security
- rule: RUST_GUIDELINES.md §12 "Required CI Tools" (`cargo audit` on every PR)
- evidence: `xtask/Cargo.toml:13-22` includes `ureq = "3.5.1"` (an HTTP/TLS client) and `lopdf` (parses downloaded PDFs); `xtask/Cargo.lock` lists 128 packages. `ci.yml:134` (`run: cargo audit`) and `ci.yml:150` (`cargo vet --locked`) cover only the root lockfile.
- impact: Code from 128 crates runs in the CI gates job and on developer machines, and a RUSTSEC advisory in any of them goes unreported. The missing deny config for xtask is already in BACKLOG; audit and vet are not.
- fix: Add `cargo audit -f xtask/Cargo.lock` to the `xtask` job.
- confidence: high

### X-08 `ci.yml` checkouts keep the token in `.git/config`
- severity: low
- kind: security
- rule: overlay http-services / workflow least privilege (inconsistent with this repository's own `container.yml` and `release.yml`)
- evidence: `ci.yml:34`, `64`, `88` and every other checkout is `- uses: actions/checkout@3d3c42e... # v7.0.1` with no `persist-credentials: false`. Compare `container.yml:38-40` and `release.yml:43`, which set it.
- impact: Jobs that compile third-party `build.rs` and proc-macros (clippy, test, rustdoc, msrv, gates) leave `GITHUB_TOKEN` readable in `.git/config`. The scope is `contents: read`, so impact is limited.
- fix: Add `with: { persist-credentials: false }` to every checkout in `ci.yml`.
- confidence: high

### X-09 Image publishing: prerelease tags overwrite `:latest`, and the version label is always 0.1.0
- severity: low
- kind: bug
- rule: none (release correctness)
- evidence: `container.yml:131-132`
  ```bash
  podman manifest push --all "${IMAGE}:${TAG}" "docker://${IMAGE}:${TAG}"
  podman manifest push --all "${IMAGE}:${TAG}" "docker://${IMAGE}:latest"
  ```
  `release.yml:173-176` treats `*-*` versions as prereleases. `kcc.container:18` and `run.sh:15` default to `:latest`. `Containerfile:61` has `ARG VERSION="0.1.0"`, and `container.yml:66-69` never passes `--build-arg VERSION`.
- impact: Tagging `v0.2.0-rc.1` moves every Quadlet or `run.sh` deployment on `:latest` to the release candidate on its next pull. Every image claims `org.opencontainers.image.version=0.1.0`.
- fix: Push `:latest` only when `TAG` has no `-`, and pass `--build-arg VERSION="${GITHUB_REF_NAME#v}"`.
- confidence: high

### X-10 `web-smoke.sh` puts the admin Web password on a command line
- severity: low
- kind: security
- rule: project rule (d) (secrets never exposed); local-user trust boundary
- evidence: `scripts/live/web-smoke.sh:157-161`
  ```bash
  podman run --rm --network host --ipc host \
    ...
    -e "WEB_USER=smoke" -e "WEB_PASSWORD=$(cat "${WORK}/web.password")" \
  ```
- impact: While the live run is in progress, another local user can read the password from `/proc/<pid>/cmdline` or `podman inspect`. They can then log in as `admin` to the kcc on 127.0.0.1, which holds the live router's credentials and has write permission.
- fix: Export `WEB_PASSWORD` in the environment and pass `-e WEB_PASSWORD` without a value, or use `--env-file` on a 0600 file.
- confidence: high

### X-11 kcc-rci depends directly on the outdated getrandom 0.2, and the duplicate-skip reason does not mention it
- severity: low
- kind: guideline
- rule: RUST_GUIDELINES.md §10 "Configure `cargo deny`" (each `skip` names the chain that forces it); §11 Supply Chain (latest versions)
- evidence: `crates/kcc-rci/Cargo.toml:12` has `getrandom = "0.2.17"`. `Cargo.lock` shows `kcc-rci -> getrandom 0.2.17` next to `rand`/`tempfile`/`crypto-common -> getrandom 0.4.3`. `deny.toml:40` gives the reason `"ring 0.17.14 -> rustls 0.23 -> reqwest 0.13.5 -> rmcp-server-kit"`, and `clippy.toml:18` is the same.
- impact: If `ring` leaves the tree, the 0.2 duplicate stays, and the skip still claims ring forces it. First-party code stays on an unmaintained API (`getrandom::getrandom`, `crates/kcc-rci/src/auth_ndw4.rs:88`).
- fix: Use the workspace `rand` 0.10, or getrandom 0.4 (`getrandom::fill`), in kcc-rci, and keep the skip reason accurate.
- confidence: high

### X-12 `ci-local.sh` has drifted from `ci.yml`
- severity: low
- kind: docs
- rule: none (the script says "Keep this file in step with ci.yml")
- evidence: `scripts/ci-local.sh:51-58` runs `lint-completeness`, `allow-gate`, `profile-eq`, `i18n-check`, `assets-check`, shellcheck and actionlint, but no `cargo xtask cancel-safety`. `ci.yml:191` runs it.
- impact: A contributor gets "all green" locally while CI's cancel-safety gate fails.
- fix: Add `cargo xtask cancel-safety` after `assets-check`.
- confidence: high

### X-13 Seccomp drift never blocks, and the profile admits 32-bit ABIs the image never uses
- severity: info
- kind: security
- rule: none
- evidence: `container.yml:86-91` (`continue-on-error: true` on `seccomp gen --check`). `deploy/podman/seccomp-kcc.json:6-10` lists `SCMP_ARCH_X86`, `SCMP_ARCH_X32` and `SCMP_ARCH_ARM`; only amd64 and arm64 images are built.
- impact: The profile can grow beyond what the binary needs without anyone being told. A post-compromise attacker can use the compat-ABI syscall entry points. The default Docker profile does the same.
- fix: Optionally make the drift check blocking on amd64, and keep only `X86_64` and `AARCH64`.
- confidence: high

## Coverage
- Read in full: `Cargo.toml`, all 12 `crates/*/Cargo.toml`, `clippy.toml`, `rustfmt.toml`, `deny.toml`, `.cargo/config.toml`, `.cargo/audit.toml`, `supply-chain/audits.toml`, `.taplo.toml`, `.containerignore`, `.github/workflows/{ci,container,release}.yml`, `.github/dependabot.yml`, `Containerfile`, `deploy/podman/{kcc.container,run.sh,e2e.sh,live-e2e.sh}`, `scripts/{ci-local.sh,package-release.sh}`, `scripts/live/{web-smoke.sh,rci.py}`, `CONTRIBUTING.md`, `AGENTS.md`, `docs/BACKLOG.md`, the overlay `keenetic-control-center.md`, RUST_GUIDELINES §9 (profile, clippy.toml, exclusions, completeness), §10 (deny, vet, audit, cooldown), §12. In xtask: `allow_gate.rs`, `cancel_safety.rs`, `cancel_safety/scan.rs`, `profile_eq.rs`, `lint_inheritance.rs`, `manifest.rs`, `lint_completeness.rs`, `cargo_lints.rs`, `tool_output.rs`, `main.rs`.
- Skimmed: `supply-chain/config.toml` and `imports.lock` (through grep), `seccomp-kcc.json` (parsed), `xtask/Cargo.toml` (deps, plus a diff of its lint tables against root), `xtask/src/assets.rs:15-94,240-459`, `xtask/src/seccomp_gen.rs:160-229`, `deploy/podman/README.md`.
- Not read: `xtask/src/{i18n.rs,i18n/unused.rs,catalog*.rs,seccomp.rs,seccomp_groups.rs,metric_docs.rs,tool_docs.rs,failure.rs,assets/notice_contrast.rs}`, `scripts/live/web-smoke.mjs`, `deploy/podman/kcc.toml.example`.

## Clean
- The `[workspace.lints]` tables match RUST_GUIDELINES §9 "The profile" exactly, including the Cargo table and the `redundant_pub_crate` override. The xtask tables differ only in comment spacing.
- `clippy.toml` matches the §9 values. `allowed-duplicate-crates` mirrors `deny.toml` `[bans] skip` one-to-one, with reasons.
- `.cargo/config.toml` has `build.warnings = "deny"` and the §10 cooldown (`3 days`, `incompatible-publish-age = "deny"`). Dependabot uses a 3-day cooldown for both cargo directories.
- `deny.toml` is the §10 template plus `CDLA-Permissive-2.0`, documented with its dependency chain. No advisory is ignored in either deny or audit, so the two lists are consistent.
- MSRV and rust-version are 1.100.0 everywhere: root, xtask, every member through the workspace, CI, the Containerfile builder, the overlay, AGENTS.md and CONTRIBUTING.md. The fmt nightly is pinned to the same date everywhere.
- CI covers every §12 tool, with deny, audit, vet, machete, taplo, shellcheck and actionlint pinned, plus the AGENTS.md G0/G1 list (the BACKLOG item about xtask fmt aside).
- Workflow hygiene: every action is pinned by SHA, the default permissions are `contents: read` with narrow per-job write grants, there is no `pull_request_target`, and untrusted contexts reach shell through `env`.
- `allow-gate`: I found no bypass. It handles inner, outer, spaced, multi-line, nested `cfg_attr` and CRLF forms, and blanks comments and strings correctly, including raw strings and lifetimes.
- `profile-eq` member inheritance rejects an empty `[lints]` table and `workspace = false`.
- Container hardening: digest-pinned bases, a static musl binary, uid 65532, read-only root, `cap-drop=ALL`, `no-new-privileges`, a seccomp allowlist (`clone` with a namespace-flag mask, `clone3` returning ENOSYS), memory and pids limits, and publishing on loopback only.
- `package-release.sh` validates version and target, and `--verify` is used before release.
- The live scripts check the `test_device = true` profile and the serial allowlist before touching a router.