//! The secret-hygiene byte test, alone in its own process.
//!
//! It installs a process-wide subscriber before any SSH work. No other test shares the
//! process, so no other thread registers the same callsites first and every
//! `kcc_ssh` DEBUG/TRACE event reaches the capture.
#![expect(
    clippy::tests_outside_test_module,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration-test crate: assertions define the contract"
)]

extern crate alloc;

#[path = "ssh_logs/logs.rs"]
mod logs;
#[expect(
    dead_code,
    reason = "shared with the ssh target; this target uses a part of it"
)]
#[path = "ssh/support.rs"]
mod support;
