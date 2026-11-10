//! CLI confirmation and recovery cover nested raw commands.
use kcc_testkit::FakeRouter;

use super::support::{Env, TestResult, router};

/// A nested destructive command needs the same typed confirmation as its direct form.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_destructive_requires_confirmation_without_mutations() -> TestResult {
    let (address, handle) = FakeRouter::spawn().await?;
    let env = Env::new("")?;
    let password = env.write(
        "router.password",
        &['a', 'd', 'm', 'i', 'n'].iter().collect::<String>(),
    )?;
    env.write_config(&router("lab-1", address, &password))?;
    for args in [
        vec![
            "--yes",
            "rci",
            "delete",
            "user",
            "--data",
            r#"{"name":"victim"}"#,
        ],
        vec![
            "--yes",
            "rci",
            "batch",
            "--data",
            r#"[{"system reboot":{}}]"#,
        ],
        vec![
            "--yes",
            "rci",
            "post",
            "user",
            "--data",
            r#"{"name":"victim","no":true}"#,
        ],
        vec!["--yes", "rci", "post", "system", "reboot", "--data", "{}"],
        vec![
            "--yes",
            "rci",
            "post",
            "system",
            "--data",
            r#"{"reboot":{}}"#,
        ],
        vec![
            "--yes",
            "rci",
            "batch",
            "--data",
            r#"[{"system":{"configuration":{"factory-reset":{}}}}]"#,
        ],
    ] {
        let run = env.kcc(&args)?;
        assert_eq!(run.code, 10_i32, "{run:?}");
    }
    assert_eq!(
        handle
            .request_log()
            .iter()
            .filter(
                |record| matches!(record.method().as_str(), "POST" | "DELETE")
                    && record.path().starts_with("/rci")
            )
            .count(),
        0,
        "discovery may read; no mutation reaches the router"
    );
    handle.shutdown().await?;
    Ok(())
}

/// Direct and nested management writes both arm and disarm the router timer.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_management_arms_the_same_fail_safe_as_direct() -> TestResult {
    for args in [
        vec![
            "--yes",
            "--confirm-destructive",
            "lab-1",
            "rci",
            "batch",
            "--data",
            r#"[{"ip":{"http":{"port":{"port":8082}}}},{"mws":{"member":{"reboot":{}}}}]"#,
        ],
        vec![
            "--yes",
            "rci",
            "post",
            "ip",
            "http",
            "port",
            "--data",
            r#"{"port":8082}"#,
        ],
        vec![
            "--yes",
            "rci",
            "post",
            "--data",
            r#"{"ip":{"http":{"port":{"port":8082}}}}"#,
        ],
    ] {
        let (address, handle) = FakeRouter::spawn().await?;
        let env = Env::new("")?;
        let password = env.write(
            "router.password",
            &['a', 'd', 'm', 'i', 'n'].iter().collect::<String>(),
        )?;
        env.write_config(&router("lab-1", address, &password))?;
        let run = env.kcc(&args)?;
        assert_eq!(run.code, 0_i32, "{run:?}");
        let commands = handle
            .request_log()
            .iter()
            .filter_map(|record| {
                record
                    .command()
                    .filter(|line| {
                        let command = line.strip_prefix("no ").unwrap_or(line);
                        command.starts_with("system configuration fail-safe timer")
                            || command.starts_with("system reboot")
                    })
                    .map(str::to_owned)
            })
            .collect::<Vec<_>>();
        assert_eq!(commands.len(), 2, "armed and disarmed: {commands:?}");
        handle.shutdown().await?;
    }
    Ok(())
}
