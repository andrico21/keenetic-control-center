# KeeneticOS command catalog

This directory contains structural command facts generated from Keenetic Limited's
official English Command Reference Guide PDFs. The source URLs and SHA-256 hashes are
recorded in `sources.lock` and each generated `index.json`.

The generated files intentionally contain no manual descriptions or examples. They keep
only command paths, syntax structure, argument types, boolean command properties, page
numbers, official PDF URLs, model applicability, and version history facts. The manuals
remain copyright (c) Keenetic Limited and are not redistributed by this repository.

Regenerate a firmware catalog with:

```text
cargo xtask catalog build --version 5.1
```

Official PDFs follow this model-specific URL shape:
`https://storage.googleapis.com/docs.help.keenetic.com/cli/<version>/en/cli_manual_<model>.pdf`.
The exact URL for every available model is in `sources.lock`.
