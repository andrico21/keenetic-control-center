//! Refused local-state commands (backups and router profiles) are audited like refused
//! router commands.

use kcc_app::{audit::read_entries, permissions::Permission};

use super::{TestResult, add_role_with_scope, env_config, lab};
use crate::support::Env;

/// The `cli.refused` entries recorded as `forbidden` so far.
fn refusals(env: &Env) -> TestResult<usize> {
    Ok(read_entries(&env.state_dir())?
        .iter()
        .filter(|entry| entry.action == "cli.refused" && entry.outcome == "forbidden")
        .count())
}

/// F-13: every backup and router-profile command refused for a missing permission or a
/// router outside the scope leaves one `cli.refused` entry (exit 10).
// NOT cancel-safe: the fixture owns router tasks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_local_state_commands_are_audited() -> TestResult {
    let (env, handle, address) = lab("router", "viewer").await?;
    add_role_with_scope(
        &env,
        "elsewhere",
        &[Permission::Read],
        vec!["other".to_owned()],
    )?;
    let full = env.path("full-backup.txt");
    let output = full.to_str().ok_or("output path")?;
    let cases: [(&str, &[&str]); 9] = [
        ("viewer", &["backup", "get", "any", "--output", output]),
        ("viewer", &["backup", "delete", "any"]),
        ("viewer", &["router", "remove", "lab-1"]),
        (
            "viewer",
            &["router", "add", "new-1", "--url", "http://192.0.2.1"],
        ),
        ("viewer", &["router", "edit", "lab-1", "--login", "other"]),
        ("elsewhere", &["backup", "list"]),
        ("elsewhere", &["backup", "diff", "older", "newer"]),
        ("elsewhere", &["backup", "get", "any"]),
        ("elsewhere", &["router", "test"]),
    ];
    let mut unaudited = Vec::new();
    for (role, args) in cases {
        env.write_config(&env_config(&env, role, address))?;
        let before = refusals(&env)?;

        let run = env.kcc(args)?;

        assert_eq!(run.code, 10_i32, "{role} {args:?}: {run:?}");
        if refusals(&env)? != before.saturating_add(1) {
            unaudited.push(args.join(" "));
        }
    }
    assert!(unaudited.is_empty(), "not audited: {unaudited:?}");
    handle.shutdown().await?;
    Ok(())
}
