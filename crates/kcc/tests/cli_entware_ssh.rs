//! Process-level acceptance tests of `kcc entware ssh|packages|services` and the notice
//! of `kcc router remove`.
//!
//! Every test runs the built binary with a hermetic `HOME`, XDG directories, master key
//! and `USER=tester` against a fake router and a fake Entware SSH server served from the
//! test process. Every run of a flow is checked for the Entware password, kcc's key and
//! raw SSH output on stdout and stderr.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process and own temporary OS resources"
)]

#[path = "cli_entware/lab.rs"]
#[expect(
    dead_code,
    reason = "the Entware lab is shared with cli_entware; these tests use a part of it"
)]
mod base;
#[path = "cli_entware_ssh/domain_exits.rs"]
mod domain_exits;
#[path = "cli_entware_ssh/enrol.rs"]
mod enrol;
#[path = "cli_entware_ssh/hostile_text.rs"]
mod hostile_text;
#[path = "cli_entware_ssh/lab.rs"]
mod lab;
#[path = "support/master_key.rs"]
mod master_key;
#[path = "cli_entware_ssh/packages.rs"]
mod packages;
#[path = "cli_entware_ssh/refusals.rs"]
mod refusals;
#[path = "cli_entware_ssh/removal.rs"]
mod removal;
#[path = "cli_entware_ssh/repin.rs"]
mod repin;
#[path = "cli_entware_ssh/services.rs"]
mod services;
#[path = "support/spawning.rs"]
mod spawning;
#[path = "cli_entware_ssh/ssh_failures.rs"]
mod ssh_failures;
#[cfg(target_os = "linux")]
#[path = "cli_entware_ssh/stack.rs"]
mod stack;
#[path = "cli/support.rs"]
mod support;
#[path = "cli_entware_ssh/ticket_refusals.rs"]
mod ticket_refusals;
