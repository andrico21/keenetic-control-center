//! The Entware service log: the router's own log records of one service, masked.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

#[path = "entware_service_log/records.rs"]
mod records;
mod support;
