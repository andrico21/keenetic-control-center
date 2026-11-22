//! Entware SSH enrolment (probe, bootstrap, re-pin, revoke, disable) against the fake
//! router and the fake Entware SSH server.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

extern crate alloc;

#[path = "entware_enrol/bootstrap.rs"]
mod bootstrap;
#[path = "entware_enrol/guards.rs"]
mod guards;
#[path = "entware_enrol/harness.rs"]
mod harness;
#[path = "entware_enrol/local.rs"]
mod local;
#[path = "entware_enrol/mismatch.rs"]
mod mismatch;
#[path = "entware_enrol/steps.rs"]
mod steps;
mod support;
#[path = "entware_enrol/tickets.rs"]
mod tickets;
