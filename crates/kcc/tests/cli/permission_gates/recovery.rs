//! Management and fail-safe recovery operations require recovery authority.

use kcc_app::{audit::read_entries, permissions::Permission};
use kcc_testkit::Handle;

use super::{TestResult, add_role, env_config, lab, mutation_count};

/// Counts parser commands after `before`; root planning reads have no command.
fn command_count(handle: &Handle, before: usize) -> usize {
    handle
        .request_log()
        .into_iter()
        .skip(before)
        .filter(|request| request.command().is_some())
        .count()
}

/// Management-interface writes require recovery permission for custom and built-in roles.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn management_interface_down_requires_destructive_before_router_mutation() -> TestResult {
    let (env, handle, address) = lab("router", "writer").await?;
    add_role(&env, "writer", &[Permission::Read, Permission::Write])?;
    for role in ["writer", "operator"] {
        env.write_config(&env_config(&env, role, address))?;
        let before = handle.request_log().len();
        let run = env.kcc(&[
            "--yes",
            "--confirm-destructive",
            "lab-1",
            "interfaces",
            "down",
            "Bridge0",
        ])?;
        assert_eq!(run.code, 10_i32, "role {role}: {run:?}");
        assert_eq!(command_count(&handle, before), 0, "role {role}");
    }
    let entries = read_entries(&env.state_dir())?;
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.action == "cli.refused" && entry.outcome == "forbidden")
            .count(),
        2,
        "both management refusals are audited: {entries:?}"
    );
    env.write_config(&env_config(&env, "admin", address))?;
    let before = handle.request_log().len();
    let allowed = env.kcc(&[
        "--yes",
        "--confirm-destructive",
        "lab-1",
        "interfaces",
        "down",
        "Bridge0",
    ])?;
    assert_eq!(allowed.code, 0_i32, "admin: {allowed:?}");
    assert_ne!(
        command_count(&handle, before),
        0,
        "admin reaches the router"
    );
    handle.shutdown().await?;
    Ok(())
}

/// Scheduled commit needs recovery permission, while native commit only needs `Save`.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failsafe_commit_requires_recovery_permission_only_for_scheduled_mode() -> TestResult {
    let (scheduled_env, scheduled, scheduled_address) = lab("extender", "operator").await?;
    let refused_before = scheduled.request_log().len();
    let refused = scheduled_env.kcc(&["config", "failsafe", "commit"])?;
    assert_eq!(refused.code, 10_i32, "scheduled operator: {refused:?}");
    assert_eq!(
        mutation_count(&scheduled, refused_before),
        0,
        "scheduled operator"
    );
    scheduled_env.write_config(&env_config(&scheduled_env, "admin", scheduled_address))?;
    let allowed_before = scheduled.request_log().len();
    let allowed = scheduled_env.kcc(&["config", "failsafe", "commit"])?;
    assert_eq!(allowed.code, 0_i32, "scheduled admin: {allowed:?}");
    assert_ne!(
        mutation_count(&scheduled, allowed_before),
        0,
        "scheduled admin"
    );
    scheduled.shutdown().await?;

    let (native_env, native, _native_address) = lab("router", "operator").await?;
    let native_before = native.request_log().len();
    let native_commit = native_env.kcc(&["config", "failsafe", "commit"])?;
    assert_eq!(
        native_commit.code, 0_i32,
        "native operator: {native_commit:?}"
    );
    assert_ne!(mutation_count(&native, native_before), 0, "native operator");
    native.shutdown().await?;
    Ok(())
}
