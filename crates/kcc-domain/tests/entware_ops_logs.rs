//! The operations' output-hygiene byte test, alone in its own process.
//!
//! It installs a process-wide subscriber before any work. No other test shares the
//! process, so every DEBUG/TRACE event of kcc and russh's `log` records reach the capture.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

extern crate alloc;

#[expect(
    dead_code,
    reason = "shared with the entware_enrol target; this target uses a part of it"
)]
#[path = "entware_enrol/harness.rs"]
mod harness;
#[path = "entware_ops_logs/output.rs"]
mod output;
mod support;
