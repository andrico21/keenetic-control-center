# Third-party notices

kcc is licensed under Apache-2.0 or MIT. It ships, or is built from, the third-party
material below.

## Web UI assets

Vendored under `crates/kcc-web/assets/vendor/` and served by kcc itself; nothing is
loaded from a CDN. Each file was extracted unchanged from its npm package and is pinned
in `crates/kcc-web/assets/ASSETS.lock`; `cargo xtask assets-check` verifies the hashes.

| Asset | Version | File | SHA-256 | License |
|---|---|---|---|---|
| htmx | 2.0.11 | `htmx.min.js` | `d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717` | 0BSD |
| htmx-ext-sse | 2.2.4 | `htmx-ext-sse.min.js` | `98a46496de0c3605fbffdce9167ba427bdd9553184f83f149c261891a92c0136` | 0BSD |
| uPlot | 1.6.32 | `uPlot.iife.min.js` | `19c8d4c6ad88929a79f4ae49d6f7161566dfd0ba3d15cc495e974f787eb78f1f` | MIT |
| uPlot (CSS) | 1.6.32 | `uPlot.min.css` | `df630c6a8d6f8eeaff264b50f73ce5b114f646ffd9a0bb74f049b0a00135fa04` | MIT |

License texts: [htmx](crates/kcc-web/assets/LICENSES/htmx-0BSD.txt),
[htmx-ext-sse](crates/kcc-web/assets/LICENSES/htmx-ext-sse-0BSD.txt),
[uPlot](crates/kcc-web/assets/LICENSES/uPlot-MIT.txt).

## Command catalog

`catalog/` contains structural command facts (command paths, syntax structure, argument
types, page numbers, model applicability, version history) generated from Keenetic
Limited's official English command reference guides for KeeneticOS 4.3, 5.0 and 5.1.
The manuals are copyright (c) Keenetic Limited and aren't redistributed: the generated
files contain no manual descriptions or examples. Every source URL and SHA-256 is
recorded in [catalog/sources.lock](catalog/sources.lock); see
[catalog/README.md](catalog/README.md).

Keenetic and Netcraze are trademarks of their owners. kcc is unofficial and is not
affiliated with Keenetic Limited or Netcraze.

## Rust crates

The binary links the Rust crates listed in `Cargo.lock`. Their licenses are restricted
by `deny.toml` (checked with `cargo deny check`); each crate's license text ships with
its source on crates.io.

## Container image

The OCI image is built on `gcr.io/distroless/static-debian13` (pinned by digest in the
Containerfile), whose packages carry their own Debian licenses.
