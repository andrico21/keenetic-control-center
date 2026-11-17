//! Process-level acceptance tests of the domain write commands of the `kcc` CLI.
//!
//! Every test runs the built binary with a hermetic `HOME`, XDG directories, master key
//! and `USER=tester` against a fake router served from the test process, and reads the
//! change back with a fresh read.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process and own temporary OS resources"
)]

#[path = "cli_domain_writes/admin.rs"]
mod admin;
#[path = "cli_domain_writes/coverage.rs"]
mod coverage;
#[path = "cli_domain_writes/exposed.rs"]
mod exposed;
#[path = "cli_domain_writes/gate.rs"]
mod gate;
#[path = "cli_domain_writes/jobs.rs"]
mod jobs;
#[path = "cli_domain_writes/lab.rs"]
mod lab;
#[path = "cli_domain_writes/lan.rs"]
mod lan;
#[path = "cli_domain_writes/link.rs"]
mod link;
#[path = "cli_domain_writes/own_accounts.rs"]
mod own_accounts;
#[path = "cli_domain_writes/secrets.rs"]
mod secrets;
#[path = "cli/support.rs"]
mod support;
#[path = "cli_domain_writes/system.rs"]
mod system;
