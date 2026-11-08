//! The services `kcc serve` wires around the Web UI, against the fake router: the
//! firmware-update check behind the dashboard badge, the signed-in session count, and the
//! log page following the router's log collector.

#[path = "integrations/support.rs"]
mod support;
#[path = "integrations/wiring.rs"]
mod wiring;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "integrations/update_check.rs"]
mod update_check;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "integrations/sessions.rs"]
mod sessions;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "integrations/log_collector.rs"]
mod log_collector;
