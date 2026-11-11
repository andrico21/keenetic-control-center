//! Process-level acceptance tests of `kcc preset` and `kcc copy`.
//!
//! Every test runs the built binary with a hermetic `HOME`, XDG directories, master key
//! and `USER=tester` against fake routers `fake-a` (source) and `fake-b` (target).
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process and own temporary OS resources"
)]

#[path = "cli_presets/apply_permissions.rs"]
mod apply_permissions;
#[path = "cli_presets/copy.rs"]
mod copy;
#[path = "cli_presets/fixture.rs"]
mod fixture;
#[path = "cli_presets/presets.rs"]
mod presets;
#[path = "cli/support.rs"]
mod support;
