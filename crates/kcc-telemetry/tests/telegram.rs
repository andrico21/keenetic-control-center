//! The Telegram Bot API client and the delivery outbox against the fake Telegram.
//!
//! Real time with short injected timings; every wait is an awaited event bounded by a
//! timeout.
#![expect(
    clippy::std_instead_of_alloc,
    clippy::tests_outside_test_module,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration-test crate: assertions define the contract"
)]

#[path = "telegram/client.rs"]
mod client;
#[path = "telegram/hygiene.rs"]
mod hygiene;
#[path = "telegram/outbox.rs"]
mod outbox;
#[path = "telegram/support.rs"]
mod support;
