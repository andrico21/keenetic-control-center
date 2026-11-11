//! Raw destructive requests require the dedicated permission.

use kcc_app::{audit::read_entries, permissions::Permission};

use super::{TestResult, add_role, lab, mutation_count};

/// Raw removal, delete and nested destructive bodies require `Destructive` permission.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_destructive_shapes_are_refused_and_audited_without_router_mutation() -> TestResult {
    let (env, handle, _address) = lab("router", "raw").await?;
    add_role(&env, "raw", &[Permission::Read, Permission::RawRci])?;
    let before = handle.request_log().len();
    for args in [
        vec![
            "--yes",
            "--confirm-destructive",
            "lab-1",
            "rci",
            "post",
            "system",
            "description",
            "--data",
            r#"{"no":true}"#,
        ],
        vec![
            "--yes",
            "--confirm-destructive",
            "lab-1",
            "rci",
            "delete",
            "system",
            "description",
        ],
        vec![
            "--yes",
            "--confirm-destructive",
            "lab-1",
            "rci",
            "post",
            "system",
            "--data",
            r#"{"reboot":{}}"#,
        ],
    ] {
        let run = env.kcc(&args)?;
        assert_eq!(run.code, 10_i32, "kcc {args:?}: {run:?}");
    }
    assert_eq!(
        mutation_count(&handle, before),
        0,
        "no raw mutation may pass"
    );
    let entries = read_entries(&env.state_dir())?;
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.action == "cli.refused" && entry.outcome == "forbidden")
            .count(),
        3,
        "every raw refusal is audited: {entries:?}"
    );
    handle.shutdown().await?;
    Ok(())
}

/// A role with the missing permission added reaches the router for every raw shape.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_destructive_shapes_reach_the_router_with_destructive_permission() -> TestResult {
    let (env, handle, _address) = lab("router", "rawdes").await?;
    add_role(
        &env,
        "rawdes",
        &[
            Permission::Read,
            Permission::RawRci,
            Permission::Destructive,
        ],
    )?;
    for args in [
        vec![
            "--yes",
            "--confirm-destructive",
            "lab-1",
            "rci",
            "post",
            "system",
            "description",
            "--data",
            r#"{"no":true}"#,
        ],
        vec![
            "--yes",
            "--confirm-destructive",
            "lab-1",
            "rci",
            "delete",
            "system",
            "description",
        ],
        vec![
            "--yes",
            "--confirm-destructive",
            "lab-1",
            "rci",
            "post",
            "system",
            "--data",
            r#"{"reboot":{}}"#,
        ],
    ] {
        let before = handle.request_log().len();
        let run = env.kcc(&args)?;
        assert_ne!(mutation_count(&handle, before), 0, "kcc {args:?}: {run:?}");
        assert_ne!(
            run.code, 10_i32,
            "permission gate must allow kcc {args:?}: {run:?}"
        );
    }
    handle.shutdown().await?;
    Ok(())
}
