//! Router-refused batch items cannot produce a CLI success note.
use fluent_bundle::FluentArgs;
use kcc_app::audit::read_entries;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{FakeRouter, FaultInjection, model::Profile};
use serde_json::{Value, json};

use super::support::{Env, TestResult, router};

/// Refused persisting items retain exit 7 and never print a completed-change message.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batch_refusals_never_print_success_or_claim_failed_persistence() -> TestResult {
    for (rejected, mixed, persists, outcome) in [
        ("/system/country", false, false, "failed"),
        (
            "/system/description",
            true,
            true,
            "partially_applied_persisted",
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
        let data = if mixed {
            r#"[{"system":{"country":{"country":"DE"}}},{"system":{"description":{"description":"lab"}}}]"#
        } else {
            r#"[{"system":{"country":{"country":"DE"}}}]"#
        };
        let run = env.kcc(&["--yes", "rci", "batch", "--data", data])?;
        assert_eq!(run.code, 7_i32, "{run:?}");
        let mut arguments = FluentArgs::new();
        arguments.set("succeeded", if mixed { "1" } else { "0" });
        arguments.set("failed", "1");
        assert!(
            run.stderr
                .contains(&tr(Locale::En, keys::CLI_BATCH_REFUSED, Some(&arguments))),
            "{run:?}"
        );
        assert!(
            !run.stderr
                .contains(&tr(Locale::En, keys::CLI_APPLIED_PERSISTED, None)),
            "{run:?}"
        );
        assert!(
            !run.stderr
                .contains(&tr(Locale::En, keys::CLI_APPLIED, None)),
            "{run:?}"
        );
        let document: Value = serde_json::from_str(&run.stdout)?;
        assert_eq!(document.get("persists_immediately"), Some(&json!(persists)));
        if mixed {
            assert_eq!(
                document.get("persisted_paths"),
                Some(&json!(["system country"]))
            );
        }
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
