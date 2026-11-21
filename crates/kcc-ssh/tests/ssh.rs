//! Tests of the SSH transport, the command set and the limits against `FakeEntwareSsh`.
//!
//! Real time over loopback sockets with short injected timeouts; every wait is bounded.
#![expect(
    clippy::tests_outside_test_module,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration-test crate: assertions define the contract"
)]

#[path = "ssh/commands.rs"]
mod commands;
#[path = "ssh/limits.rs"]
mod limits;
#[path = "ssh/support.rs"]
mod support;
#[path = "ssh/transport.rs"]
mod transport;
