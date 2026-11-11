//! Management-item fate and armed recovery survive partial batch reporting.

use kcc_app::audit::read_entries;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};
use serde_json::{Value, json};

use crate::support::{Env, TestResult, router};

/// A successful ordinary sibling does not make a refused management item applied.
// NOT cancel-safe: the fixture owns router tasks until shutdown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_management_item_reports_unknown_armed() -> TestResult {
    for mode in ["router", "extender"] {
        for (json_output, ordinary_sibling) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let mut scenario = migration::Fixture::default();
            scenario.mode = Some(mode.to_owned());
            let faults = FaultInjection::default()
                .refuse_batch_pointer("/ip/http/port".to_owned())
                .fail_parse_matching("no system", 1);
            let fake = FakeRouter::builder(Profile::default())
                .faults(faults)
                .build()?
                .with_migration(scenario);
            let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
            let env = Env::new("")?;
            let password = env.write(
                "router.password",
                &['a', 'd', 'm', 'i', 'n'].iter().collect::<String>(),
            )?;
            env.write_config(&router("lab-1", address, &password))?;
            let mut values = vec![json!({"ip":{"http":{"port":{"port":8431_u16}}}})];
            if ordinary_sibling {
                values.push(json!({"system":{"description":{"description":"ordinary"}}}));
            }
            let data = serde_json::to_string(&values)?;
            let args = if json_output {
                vec!["--json", "--yes", "rci", "batch", "--data", &data]
            } else {
                vec!["--yes", "rci", "batch", "--data", &data]
            };

            let run = env.kcc(&args)?;

            assert_eq!(run.code, 7_i32, "{mode}: {run:?}");
            let items: Value = serde_json::from_str(&run.stdout)?;
            assert_eq!(items.pointer("/items/0/ok"), Some(&json!(false)));
            assert_eq!(
                items.pointer("/items/1/ok"),
                ordinary_sibling.then_some(&json!(true))
            );
            let expected = tr(Locale::En, keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED, None);
            if json_output {
                let error: Value = serde_json::from_str(&run.stderr)?;
                assert_eq!(error.pointer("/error/fail_safe_armed"), Some(&json!(true)));
                assert_eq!(error.pointer("/error/message"), Some(&json!(expected)));
            } else {
                assert!(run.stderr.contains(&expected), "{mode}: {run:?}");
            }
            assert!(handle.recovery_armed(), "{mode}: timer remains armed");
            let entries = read_entries(&env.state_dir())?;
            let failed = entries
                .iter()
                .find(|entry| entry.action == "cli.change")
                .ok_or("CLI audit")?;
            assert_eq!(
                failed.params_redacted.get("fail_safe_armed"),
                Some(&json!(true))
            );
            handle.shutdown().await?;
        }
    }
    Ok(())
}
