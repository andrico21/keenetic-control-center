//! Executable checks of the README and `docs/`: examples, configuration keys, links and
//! the firmware table.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests assert inside fallible test functions"
)]

extern crate alloc;

#[path = "docs/config_keys.rs"]
mod config_keys;
#[cfg(unix)]
#[path = "docs/examples.rs"]
mod examples;
#[path = "docs/firmware.rs"]
mod firmware;
#[path = "docs/links.rs"]
mod links;
#[path = "docs/markdown.rs"]
mod markdown;
#[path = "support/spawning.rs"]
mod spawning;
