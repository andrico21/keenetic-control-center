//! Namespace batches require confirmation and report unsaved completion at the CLI.
use kcc_app::audit::read_entries;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{FakeRouter, model::Profile};
use serde_json::{Value, json};

use crate::support::{Env, TestResult, router};

/// A Show sibling cannot bypass confirmation or suppress the namespace change receipt.
// NOT cancel-safe: the fixture owns router tasks and writes until shutdown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn namespace_batches_require_confirmation_and_report_unsaved() -> TestResult {
    for items in [
        json!([{"ip":{"http":{}}}]),
        json!([{"show":{"version":{}}},{"ip":{"http":{}}}]),
        json!([{"show":{"version":{}},"ip":{"http":{}}}]),
    ] {
        let fake = FakeRouter::builder(Profile::default()).build()?;
        let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
        let env = Env::new("")?;
        let password = env.write(
            "router.password",
            &['a', 'd', 'm', 'i', 'n'].iter().collect::<String>(),
        )?;
        env.write_config(&router("lab-1", address, &password))?;
        let data = serde_json::to_string(&items)?;

        let refused = env.kcc(&["rci", "batch", "--data", &data])?;
        assert_eq!(refused.code, 10_i32, "{items}: {refused:?}");
        assert_eq!(
            handle
                .request_log()
                .iter()
                .filter(|record| record.method() == "POST" && record.path() == "/rci/")
                .count(),
            0
        );
        assert!(
            read_entries(&env.state_dir())?
                .iter()
                .all(|entry| entry.action != "router.change_batch"),
            "unconfirmed batch was not applied"
        );

        let run = env.kcc(&["--yes", "rci", "batch", "--data", &data])?;
        assert_eq!(run.code, 0_i32, "{items}: {run:?}");
        let document: Value = serde_json::from_str(&run.stdout)?;
        assert_eq!(document.get("unsaved"), Some(&json!(true)), "{items}");
        assert_eq!(document.get("persists_immediately"), Some(&json!(false)));
        assert!(
            run.stderr
                .contains(&tr(Locale::En, keys::CLI_APPLIED, None)),
            "{run:?}"
        );
        assert!(
            !run.stderr
                .contains(&tr(Locale::En, keys::CLI_APPLIED_PERSISTED, None)),
            "{run:?}"
        );
        let responses = document
            .get("items")
            .and_then(Value::as_array)
            .ok_or("response items")?;
        assert_eq!(
            responses.len(),
            items.as_array().ok_or("input items")?.len()
        );
        assert!(
            responses
                .iter()
                .all(|response| response.get("ok") == Some(&json!(true))),
            "accepted items"
        );
        let entries = read_entries(&env.state_dir())?;
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.action == "router.change_batch")
                .map(|entry| entry.outcome.as_str())
                .collect::<Vec<_>>(),
            ["applied_unsaved"]
        );
        assert_eq!(
            handle
                .request_log()
                .iter()
                .filter(|record| record.method() == "POST" && record.path() == "/rci/")
                .count(),
            1
        );
        handle.shutdown().await?;
    }
    Ok(())
}
