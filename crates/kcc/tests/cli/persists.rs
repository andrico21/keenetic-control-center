//! Commands the router persists immediately are labelled before they run, in human
//! output and in the `--json` document; other commands are not.

use fluent_bundle::FluentArgs;
use kcc_app::audit::read_entries;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter};
use serde_json::Value;

use super::support::{Env, TestResult, router};

fn mixed_note(key: MessageKey) -> String {
    let mut args = FluentArgs::new();
    args.set("paths", "system country");
    tr(Locale::En, key, Some(&args))
}

/// Path POST and deep root batches retain the same mixed result and note.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_path_and_deep_prefix_post_report_saved_paths() -> TestResult {
    let (address, handle) = FakeRouter::spawn().await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", address, &password))?;
    for args in [
        vec![
            "rci",
            "post",
            "system",
            "--data",
            r#"{"country":{"country":"DE"},"description":{"description":"mixed"}}"#,
        ],
        vec![
            "rci",
            "post",
            "system",
            "--data",
            r#"{"country":{"country":"DE"},"ndss":{"dump-report":{"disable":{}}}}"#,
        ],
        vec![
            "rci",
            "batch",
            "--data",
            r#"[{"system":{"country":{"country":"DE"},"ndss":{"dump-report":{"disable":{}}}}}]"#,
        ],
    ] {
        let mut command = vec!["--yes"];
        command.extend_from_slice(&args);
        let human = env.kcc(&command)?;
        assert_eq!(human.code, 0_i32, "{human:?}");
        assert!(human.stderr.contains("system country"), "{human:?}");
        command.insert(0, "--json");
        let run = env.kcc(&command)?;
        assert_eq!(run.code, 0_i32, "{run:?}");
        let value: Value = serde_json::from_str(&run.stdout)?;
        assert_eq!(value.get("persists_immediately"), Some(&Value::Bool(false)));
        assert_eq!(
            value.get("persisted_paths"),
            Some(&serde_json::json!(["system country"]))
        );
    }
    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rci_post_labels_system_country_and_nothing_else() -> TestResult {
    let (address, handle) = FakeRouter::spawn().await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", address, &password))?;
    let label = tr(Locale::En, keys::CLI_PERSISTS_IMMEDIATELY, None);
    let country = ["system", "country", "--data", r#"{"country":"DE"}"#];
    let host = [
        "ip",
        "host",
        "--data",
        r#"{"domain":"cli.example","address":"192.0.2.12"}"#,
    ];
    for (path, persists) in [(&country, true), (&host, false)] {
        let mut human = vec!["--yes", "rci", "post"];
        human.extend_from_slice(path);
        let human_run = env.kcc(&human)?;
        assert_eq!(human_run.code, 0_i32, "{human_run:?}");
        assert_eq!(human_run.stderr.contains(&label), persists, "{human_run:?}");
        assert!(
            !human_run.stderr.contains("system country"),
            "pure requests have no mixed-path note: {human_run:?}"
        );
        let mut json = vec!["--json"];
        json.extend_from_slice(&human);
        let json_run = env.kcc(&json)?;
        assert_eq!(json_run.code, 0_i32, "{json_run:?}");
        let document: Value = serde_json::from_str(&json_run.stdout)?;
        assert_eq!(
            document.get("persists_immediately"),
            Some(&Value::Bool(persists)),
            "{document}"
        );
    }
    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rci_mixed_root_batch_requires_save_and_reports_persisted_paths() -> TestResult {
    let (address, handle) = FakeRouter::spawn().await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", address, &password))?;
    let data = r#"[{"system":{"country":{"country":"DE"},"description":{"description":"mixed"}}}]"#;

    let human = env.kcc(&["--yes", "rci", "batch", "--data", data])?;
    assert_eq!(human.code, 0_i32, "{human:?}");
    assert!(human.stderr.contains("system country"), "{human:?}");
    assert!(
        !human
            .stderr
            .contains(&tr(Locale::En, keys::CLI_PERSISTS_IMMEDIATELY, None)),
        "{human:?}"
    );

    let json_run = env.kcc(&["--json", "--yes", "rci", "batch", "--data", data])?;
    assert_eq!(json_run.code, 0_i32, "{json_run:?}");
    let document: Value = serde_json::from_str(&json_run.stdout)?;
    assert_eq!(
        document.get("persists_immediately"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        document.get("persisted_paths"),
        Some(&serde_json::json!(["system country"]))
    );
    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_mixed_changes_use_future_tense_and_send_nothing() -> TestResult {
    let (address, handle) = FakeRouter::spawn().await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", address, &password))?;
    let before = mixed_note(keys::CLI_MIXED_PERSISTENCE_BEFORE);
    let applied = mixed_note(keys::CLI_MIXED_PERSISTENCE);

    for args in [
        vec![
            "rci",
            "post",
            "system",
            "--data",
            r#"{"country":{"country":"DE"},"description":{"description":"mixed"}}"#,
        ],
        vec![
            "rci",
            "batch",
            "--data",
            r#"[{"system":{"country":{"country":"DE"}}},{"system":{"description":{"description":"mixed"}}}]"#,
        ],
    ] {
        let run = env.kcc(&args)?;
        assert_ne!(run.code, 0_i32, "{run:?}");
        assert!(run.stderr.contains(&before), "{run:?}");
        assert!(!run.stderr.contains(&applied), "{run:?}");
    }
    let entries = read_entries(&env.state_dir())?;
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert!(
        entries
            .iter()
            .all(|entry| entry.action == "cli.refused" && entry.outcome == "refused"),
        "only the two missing confirmations are audited: {entries:?}"
    );
    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successful_mixed_change_reports_saved_paths_only_after_the_future_note() -> TestResult {
    let (address, handle) = FakeRouter::spawn().await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", address, &password))?;
    let run = env.kcc(&[
        "--yes",
        "rci",
        "post",
        "system",
        "--data",
        r#"{"country":{"country":"DE"},"description":{"description":"mixed"}}"#,
    ])?;
    assert_eq!(run.code, 0_i32, "{run:?}");
    let before = mixed_note(keys::CLI_MIXED_PERSISTENCE_BEFORE);
    let applied = mixed_note(keys::CLI_MIXED_PERSISTENCE);
    let before_at = run
        .stderr
        .find(&before)
        .ok_or_else(|| format!("future note missing: {run:?}"))?;
    let applied_at = run
        .stderr
        .find(&applied)
        .ok_or_else(|| format!("applied note missing: {run:?}"))?;
    assert!(before_at < applied_at, "{run:?}");
    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successful_text_changes_state_whether_the_result_is_saved() -> TestResult {
    let (address, handle) = FakeRouter::spawn().await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", address, &password))?;

    for (args, key) in [
        (
            vec![
                "--yes",
                "rci",
                "post",
                "system",
                "description",
                "--data",
                r#"{"description":"ordinary"}"#,
            ],
            keys::CLI_APPLIED,
        ),
        (
            vec![
                "--yes",
                "rci",
                "batch",
                "--data",
                r#"[{"system":{"description":{"description":"batch"}}}]"#,
            ],
            keys::CLI_APPLIED,
        ),
        (
            vec![
                "--yes",
                "rci",
                "post",
                "system",
                "country",
                "--data",
                r#"{"country":"DE"}"#,
            ],
            keys::CLI_APPLIED_PERSISTED,
        ),
        (
            vec![
                "--yes",
                "--confirm-destructive",
                "lab-1",
                "rci",
                "delete",
                "system",
                "description",
            ],
            keys::CLI_DONE,
        ),
    ] {
        let run = env.kcc(&args)?;
        assert_eq!(run.code, 0_i32, "{run:?}");
        assert!(run.stderr.contains(&tr(Locale::En, key, None)), "{run:?}");
    }

    let json = env.kcc(&[
        "--json",
        "--yes",
        "rci",
        "post",
        "system",
        "description",
        "--data",
        r#"{"description":"json"}"#,
    ])?;
    assert_eq!(json.code, 0_i32, "{json:?}");
    assert!(json.stderr.is_empty(), "{json:?}");
    let document: Value = serde_json::from_str(&json.stdout)?;
    assert_eq!(
        document.get("persists_immediately"),
        Some(&Value::Bool(false))
    );
    handle.shutdown().await?;
    Ok(())
}
