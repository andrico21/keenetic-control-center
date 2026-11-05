# Learnings - keenetic-control-center

Conventions, patterns, and successful approaches discovered during work on this plan.

_Auto-scaffolded by /ulw-execute. Append new entries below - never overwrite._

---

- Task 3: vendored andrico21/rust-guidelines at PIN 80b5b6b149c0baea52d6d21e529918807c0bb9a8 (core, http-services, mcp-servers) under docs/rust-guidelines/ with SHA256SUMS.

- Task 4 (xtask): `xtask/` is its own workspace (empty `[workspace]`), deps pinned clap 4.6.7 (default-features off; std, derive, help, usage, error-context), toml 1.2.0 (`text.parse::<toml::Table>()`), dev-dep tempfile 3.27.0. Lint tables generated from the guide fence with `sed 's/^\[workspace\.lints\./[lints./'`, so they are textually equal to root `[workspace.lints]`.
- `clippy-driver -W help` prints the group table as one line per group: `   clippy::restriction  clippy::a, clippy::b, ...`. Parser: `trim_start().strip_prefix("clippy::restriction")`, require whitespace next, split on `,`, trim, strip `clippy::`, `-`->`_`. rustc side: `split_whitespace`, field 2 == `allow`. Manifest side: keys of every `[workspace.lints.*]` table. Missing set on 1.99.1 = exactly the 25 exclusions. Empty parse result is an error (exit 2), not a pass.
- allow-gate blanks comments, strings (incl. raw `r#".."#`, b/c prefixes) and char literals (lifetimes kept) before matching, then parses whole `#[..]`/`#![..]` attributes whitespace-free: hit when body starts `allow(` or is `cfg_attr(..)` containing `allow(` after `,`/`(`. Skips `target/` dirs; scans only `crates/` and `xtask/src`.
- Profile-satisfying patterns hit in xtask: `where W: io::Write` (inline_trait_bounds), `Display::fmt(&self, f: ..)` (renamed_function_params beats min_ident_chars, which did not fire on `f` there), explicit `field: _` instead of `..` (rest_pattern_accessible_field), `drop(map.insert(..))` for owned Option (let_underscore_drop), `.collect::<Vec<_>>().concat()` instead of collecting `format!` into String (format_collect), tests use `use core::error::Error; Result<(), Box<dyn Error>>` (absolute_paths). Exit codes: 0 pass, 1 gate failed, 2 could not run.

## [todo 53] Shell probe patterns
- shellcheck SC2016 fires on single-quoted jq filters passed through a wrapper function (it only knows literal `jq`); use double quotes with `\$var` escapes instead of disabling.
- Byte-level codecs in bash: `od -An -v -tu1` to read bytes, `printf '%b' '\0NNN...' | openssl base64 -A` to write them (handles NUL). Bash ns3 port matches zyxel_scramble.py.
- `.omo/evidence/` is gitignored; evidence files stay local.

## [2026-11-05] Task: todo-1
- Cargo.toml: header + R-GUIDE lines 1591-1802 byte-for-byte (profile block fence is 1590-1803). clippy.toml = lines 1830-1846 with the sample's `doc-valid-idents = [".."]` line replaced by the full list (a duplicate key is invalid TOML).
- Completeness check run as documented (R-GUIDE 1907-1916) against root Cargo.toml: prints exactly the 25 exclusions.
- Bin crate needed a non-trivial main: `fn main() {}` trips clippy missing_const_for_fn; `std::process::exit(0)` trips absolute_paths. Used `use std::process::exit; fn main() { exit(0) }`.
- Tools: cargo-vet/machete/nextest/mutants/zigbuild/taplo installed from source. `lychee-bin` does not exist; crate is `lychee`. shellcheck, actionlint, zig 0.17.1 prebuilt into ~/.cargo/bin and ~/.local/bin (zig needs PATH).
- Toolchain 1.99.1 installed via rustup (stable already 1.99.1).

## Todo 2
- cargo-audit parse needs `fetch`+`stale` alongside `[database] path`; default db dir collides with cargo-deny's, hence a separate path in .cargo/audit.toml.
- `cargo machete` at root also scans spikes/lint-macros (reports unused deps); use `cargo machete crates xtask`.

## Todo 7
- `kcc-rci` dependency resolution selected serde 1.0.229, serde_json 1.0.154, serde_urlencoded 0.7.1, thiserror 2.0.21, url 2.5.8, and proptest 1.12.0 (manifest lower bounds remain compatible); proptest defaults were pinned explicitly to 256 cases in the property-test configuration.
- Treating `RciPath::from_str` as one segment is essential: multi-segment paths use `RciPath::from_segments`, so an object name such as `WifiMaster0/AccessPoint0` cannot silently become a path. Iterative status traversal stores `(JsonPointer, &Value)` on a `Vec` stack and skips descending into the consumed `status` member.
- The strict lint profile requires `#[inline]` on public trait methods, `# Errors` docs even for private fallible helpers, and narrow `#[expect]` annotations on assertion-based tests. A manual `Debug` implementation for `RciError` prevents retained router messages from leaking.

## Todo 12: catalog fetch/extract (xtask)
- `pdftotext` is NOT installed on this host, so `extract` used the podman fallback (debian:12-slim, one container run over `/w/*/*.pdf`); poppler-utils 22.12.0-2+deb12u3 recorded in `[extraction]` of `catalog/sources.lock`. `extract` auto-picks native when `pdftotext -v` works.
- URL pattern held as specified. Per version: 31 manuals answer 200, 20 answer 404 (recorded `absent`); all five NC ids 404 on 4.3/5.0/5.1 (no Netcraze CLI manuals published). KN-1811 is 200 on 4.3, 5.0 and 5.1. GCS answers a clean 404 for missing objects; any other non-200 status fails the run.
- `catalog/.cache` is ~800 MB for three versions (PDFs + txt + outline.json); `kn-1811.txt` (5.1) is 54697 lines. lopdf `get_toc` gives ~900-1150 bookmarks per manual.
- xtask new deps: ureq 3 (rustls/ring), sha2, lopdf (default features off), serde, serde_json, jiff (UTC date only). ring (getrandom 0.2) and lopdf (getrandom 0.4) trip `clippy::cargo` multiple_crate_versions, so main.rs carries a crate-level `#![expect(clippy::multiple_crate_versions, reason=...)]`.
- Lints: `field_scoped_visibility_modifiers` denies `pub(crate)` fields, so lock structs use plain `pub` fields inside `pub(crate)` types. `Task` lost `Copy` (Catalog carries a String).
- The `catalog fetch --version 9.9` QA run leaves a 9.9 `absent` entry in `sources.lock`.
