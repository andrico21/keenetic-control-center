The ndw4 vector uses public dummy credentials and fixed nonces/salt. Regenerate
from the repository root with:

```
node crates/kcc-rci/scripts/vectors/ndw4-vector.mjs /tmp/opencode/research/rci-tools
```

The generator checks the reference commit and imports its SHA3/HMAC utilities
and protocol constants. Install `hash-wasm@4.12.0` in that disposable reference
checkout before running it. The generator lives inside kcc-rci with the client it
checks.
