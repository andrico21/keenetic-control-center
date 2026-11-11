//! Process-level recovery receipts for closing migration and preset runs.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process and own temporary resources"
)]

#[path = "cli/closing.rs"]
mod closing;
#[path = "cli/closing_saved.rs"]
mod closing_saved;
#[path = "cli/support.rs"]
mod support;
