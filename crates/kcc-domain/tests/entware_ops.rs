//! Entware package and service operations over SSH against the fake router and the fake
//! Entware SSH server.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

extern crate alloc;

#[path = "entware_ops/audit.rs"]
mod audit;
#[path = "entware_ops/guards.rs"]
mod guards;
#[expect(
    dead_code,
    reason = "shared with the entware_enrol target; this target uses a part of it"
)]
#[path = "entware_enrol/harness.rs"]
mod harness;
#[path = "entware_ops/jobs.rs"]
mod jobs;
#[path = "entware_ops/leases.rs"]
mod leases;
#[path = "entware_ops/packages.rs"]
mod packages;
#[path = "entware_ops/rig.rs"]
mod rig;
#[path = "entware_ops/services.rs"]
mod services;
mod support;
