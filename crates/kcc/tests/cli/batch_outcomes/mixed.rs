//! Mixed read/write receipts at the CLI boundary.
use fluent_bundle::FluentArgs;
use kcc_app::audit::read_entries;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{FakeRouter, FaultInjection, model::Profile};
use serde_json::{Value, json};

use crate::support::{Env, TestResult, router};

/// A read contributes no applied count, persistence or save advice beside a write.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_read_batches_count_only_changes() -> TestResult {
    for (rejected, ordinary, outcome, persisted, code) in [
        ("/system/country", false, "failed", false, 7_i32),
        ("/absent", false, "applied_persisted", true, 0_i32),
        ("/absent", true, "applied_unsaved", false, 0_i32),
        (
            "/system/country",
            true,
            "partially_applied_unsaved",
            false,
            7_i32,
        ),
    ] {
        let fake = FakeRouter::builder(Profile::default())
            .faults(FaultInjection::default().refuse_batch_pointer(rejected.to_owned()))
            .build()?;
        let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
        let env = Env::new("")?;
        let password = env.write(
            "router.password",
            &['a', 'd', 'm', 'i', 'n'].iter().collect::<String>(),
        )?;
        env.write_config(&router("lab-1", address, &password))?;
        let mut items = vec![json!({"show":{"version":{}}})];
        if ordinary {
            items.push(json!({"system":{"description":{"description":"lab"}}}));
        }
        if !ordinary || rejected == "/system/country" {
            items.push(json!({"system":{"country":{"country":"DE"}}}));
        }
        let run = env.kcc(&[
            "--yes",
            "rci",
            "batch",
            "--data",
            &serde_json::to_string(&items)?,
        ])?;
        assert_eq!(run.code, code, "{run:?}");
        let mut args = FluentArgs::new();
        args.set("succeeded", if ordinary { "1" } else { "0" });
        args.set("failed", "1");
        let key = if code != 0_i32 {
            keys::CLI_BATCH_REFUSED
        } else if persisted {
            keys::CLI_APPLIED_PERSISTED
        } else {
            keys::CLI_APPLIED
        };
        assert!(
            run.stderr.contains(&tr(Locale::En, key, Some(&args))),
            "{run:?}"
        );
        args.set("paths", "system country");
        assert!(
            !run.stderr
                .contains(&tr(Locale::En, keys::CLI_MIXED_PERSISTENCE, Some(&args))),
            "{run:?}"
        );
        assert_eq!(
            run.stderr.contains(&tr(
                Locale::En,
                keys::CLI_MIXED_PERSISTENCE_BEFORE,
                Some(&args)
            )),
            ordinary && rejected == "/system/country",
            "{run:?}"
        );
        let document: Value = serde_json::from_str(&run.stdout)?;
        assert_eq!(document.get("unsaved"), Some(&json!(ordinary)));
        assert_eq!(
            document.get("persists_immediately"),
            Some(&json!(persisted))
        );
        assert_eq!(document.get("persisted_paths"), None);
        let entries = read_entries(&env.state_dir())?;
        let entry = entries
            .iter()
            .find(|entry| entry.action == "router.change_batch")
            .ok_or("batch audit")?;
        assert_eq!(entry.outcome, outcome);
        handle.shutdown().await?;
    }
    Ok(())
}

/// A nested Show batch needs no confirmation and creates no change audit entry.
// NOT cancel-safe: the fixture owns router tasks until shutdown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn namespace_reads_bypass_change_workflow() -> TestResult {
    for rejected in ["/absent", "/show/clock/date"] {
        let fake = FakeRouter::builder(Profile::default())
            .faults(FaultInjection::default().refuse_batch_pointer(rejected.to_owned()))
            .build()?;
        let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
        let env = Env::new("")?;
        let password = env.write(
            "router.password",
            &['a', 'd', 'm', 'i', 'n'].iter().collect::<String>(),
        )?;
        env.write_config(&router("lab-1", address, &password))?;
        let run = env.kcc(&[
            "rci",
            "batch",
            "--data",
            r#"[{"show":{"clock":{"date":{}}}}]"#,
        ])?;
        assert_eq!(
            run.code,
            if rejected == "/absent" { 0_i32 } else { 7_i32 },
            "{run:?}"
        );
        let document: Value = serde_json::from_str(&run.stdout)?;
        assert_eq!(document.get("persists_immediately"), Some(&json!(false)));
        assert_eq!(document.get("unsaved"), Some(&json!(false)));
        assert!(
            !run.stderr
                .contains(&tr(Locale::En, keys::CLI_APPLIED, None)),
            "{run:?}"
        );
        assert!(
            read_entries(&env.state_dir())?
                .iter()
                .all(|entry| entry.action != "router.change_batch"),
            "reads leave no change audit"
        );
        handle.shutdown().await?;
    }
    Ok(())
}
