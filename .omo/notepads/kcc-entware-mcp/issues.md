
## [2026-11-20] Todo 6 (e6) findings for later todos
- russh-cryptovec 0.62.0 calls `mlock`/`munlock` on every CryptoVec buffer (via nix on unix, VirtualLock on Windows) and ignores failures. Once kcc-ssh runs inside `kcc serve` (container), the traced seccomp profile (todo 18) must include `mlock`/`munlock` or the calls fail with EPERM (silently ignored by russh, but a kill-on-violation profile would kill the process). Check the profile's default action when tracing the SSH leg.
- russh logs through the `log` crate (debug/trace), not `tracing`: todo 7's no-secret-in-logs byte test must capture `log` records too (LogTracer via tracing-subscriber's `tracing-log`).
- `cargo deny --manifest-path xtask/Cargo.toml check` warns `unmatched-skip` for thiserror@1.0.69/thiserror-impl@1.0.69 (root deny.toml read for the xtask workspace); pre-existing, exit 0.

## [2026-11-21] Todo 24 (e24): out-of-scope findings
- `crates/kcc-web/src/admin_shared.rs` `Timestamp::at` calls `humantime::format_rfc3339_seconds(time).to_string()`. humantime's Display returns `fmt::Error` for year >= 10000, so `to_string()` panics. A hand-edited `api_keys.json` with `created_at`/`last_used_at`/`expires_at` >= 253402300800 would panic the keys page handler. This predates todo 24, which only adds `expires_at` to the same path. `kcc_app::api_keys` formats with `write!` instead and fails closed.
- `crates/kcc-web/src/admin_keys.rs` was already 325 pure LOC (over 250) before todo 24 and is now 346. A split (handlers vs. region/dialog builders) is a follow-up.
