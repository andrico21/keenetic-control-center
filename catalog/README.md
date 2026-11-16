# KeeneticOS command catalog

This directory contains structural command facts generated from Keenetic Limited's
official English Command Reference Guide PDFs. The source URLs and SHA-256 hashes are
recorded in `sources.lock` and each generated `index.json`.

The generated files intentionally contain no manual descriptions or examples. They keep
only command paths, syntax structure, argument types, boolean command properties, page
numbers, official PDF URLs, model applicability, and version history facts. The manuals
remain copyright (c) Keenetic Limited and are not redistributed by this repository.

`synopsis-errata.json` holds the few corrections the generator applies to the manuals'
syntax, each with its reason: a synopsis that contradicts the manual's own examples, and
`interface vlan-id`, which kcc's segments send but no manual documents.

Regenerate a firmware catalog with:

```text
cargo xtask catalog build --version 5.1
```

## Tests

`cargo test --manifest-path xtask/Cargo.toml` needs no network or cache: hermetic guards
check the committed `<version>/*.json` shards (documented keyword literals, semantic
argument types, structural spot facts, the 98% synopsis gate and the 12-word string cap),
and the parser is tested on small inline facts-only fixtures.

The parser tests over the extracted KN-1811 5.1 manual (including the 13-consecutive-word
copyright check against the source text) are `#[ignore]`d because `catalog/.cache` is
gitignored and fetched from the network. Maintainers with the cache run them with:

```text
cargo xtask catalog fetch --version 5.1
cargo xtask catalog extract
cargo test --manifest-path xtask/Cargo.toml -- --ignored
```

Official PDFs follow this model-specific URL shape:
`https://storage.googleapis.com/docs.help.keenetic.com/cli/<version>/en/cli_manual_<model>.pdf`.
The exact URL for every available model is in `sources.lock`.
