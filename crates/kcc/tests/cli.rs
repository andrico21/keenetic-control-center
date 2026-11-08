//! Process-level acceptance tests of the `kcc` command-line interface.
//!
//! Every test runs the built binary with a hermetic `HOME`, XDG directories, master key
//! and `USER=tester` against fake routers served from the test process.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process and own temporary OS resources"
)]

#[path = "cli/admin.rs"]
mod admin;
#[path = "cli/basics.rs"]
mod basics;
#[path = "cli/health.rs"]
mod health;
#[path = "cli/migrate.rs"]
mod migrate;
#[path = "cli/policy.rs"]
mod policy;
#[path = "cli/router_credentials.rs"]
mod router_credentials;
#[path = "cli/support.rs"]
mod support;
