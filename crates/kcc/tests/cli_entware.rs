//! Process-level acceptance tests of `kcc entware` and `kcc storage initialize`.
//!
//! Every test runs the built binary with a hermetic `HOME`, XDG directories, master key
//! and `USER=tester` against a fake router served from the test process.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process and own temporary OS resources"
)]

#[path = "cli_entware/gates.rs"]
mod gates;
#[path = "cli_entware/lab.rs"]
mod lab;
#[path = "support/master_key.rs"]
mod master_key;
#[path = "cli_entware/settings.rs"]
mod settings;
#[path = "cli_entware/setup.rs"]
mod setup;
#[path = "cli_entware/setup_exits.rs"]
mod setup_exits;
#[path = "cli_entware/setup_refusals.rs"]
mod setup_refusals;
#[path = "support/spawning.rs"]
mod spawning;
#[path = "cli_entware/status.rs"]
mod status;
#[path = "cli_entware/storage.rs"]
mod storage;
#[path = "cli/support.rs"]
mod support;
