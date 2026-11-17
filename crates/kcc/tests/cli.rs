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
#[path = "cli/apply_permissions.rs"]
mod apply_permissions;
#[path = "cli/audit_pending.rs"]
mod audit_pending;
#[path = "cli/backup_diff.rs"]
mod backup_diff;
#[path = "cli/basics.rs"]
mod basics;
#[path = "cli/batch_outcomes.rs"]
mod batch_outcomes;
#[path = "cli/bracket.rs"]
mod bracket;
#[path = "cli/bracket_failures.rs"]
mod bracket_failures;
#[path = "cli/busy.rs"]
mod busy;
#[path = "cli/cli_contract.rs"]
mod cli_contract;
#[path = "cli/dns.rs"]
mod dns;
#[path = "cli/failsafe.rs"]
mod failsafe;
#[path = "cli/failures.rs"]
mod failures;
#[path = "cli/finish_failures.rs"]
mod finish_failures;
#[path = "cli/firewall_binding.rs"]
mod firewall_binding;
#[path = "cli/firewall_permissions.rs"]
mod firewall_permissions;
#[path = "cli/health.rs"]
mod health;
#[path = "cli/interface_refusals.rs"]
mod interface_refusals;
#[path = "cli/migrate.rs"]
mod migrate;
#[path = "cli/migrate_finish.rs"]
mod migrate_finish;
#[path = "cli/nested_risk.rs"]
mod nested_risk;
#[path = "cli/outbound.rs"]
mod outbound;
#[path = "cli/permission_gates.rs"]
mod permission_gates;
#[path = "cli/persists.rs"]
mod persists;
#[path = "cli/pipes.rs"]
mod pipes;
#[path = "cli/policy.rs"]
mod policy;
#[path = "cli/preset_finish.rs"]
mod preset_finish;
#[cfg(unix)]
#[path = "cli/private_output.rs"]
mod private_output;
#[path = "cli/rci_transport.rs"]
mod rci_transport;
#[path = "cli/reveal.rs"]
mod reveal;
#[path = "cli/role_dominance.rs"]
mod role_dominance;
#[path = "cli/router_credentials.rs"]
mod router_credentials;
#[path = "cli/router_edits.rs"]
mod router_edits;
#[path = "cli/router_rollback.rs"]
mod router_rollback;
#[path = "cli/router_sealing.rs"]
mod router_sealing;
#[path = "cli/runtime_management.rs"]
mod runtime_management;
#[cfg(unix)]
#[path = "cli/secret_files.rs"]
mod secret_files;
#[path = "cli/support.rs"]
mod support;
#[path = "cli/unsaved.rs"]
mod unsaved;
