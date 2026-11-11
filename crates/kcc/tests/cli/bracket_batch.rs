//! Batch application facts survive failed recovery cleanup.

use std::io::{self, Write as _};

use fluent_bundle::FluentArgs;
use kcc_app::audit::read_entries;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{FakeRouter, FaultInjection, migration, model::Profile};
use serde_json::{Value, json};

use crate::support::{Env, TestResult, router};

/// Refused, applied and partial batches retain their items and recovery facts in both modes.
// NOT cancel-safe: the fixture owns router tasks until shutdown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batch_completion_controls_recovery_message() -> TestResult {
    for mode in ["router", "extender"] {
        for (refused, partial, armed) in [
            (true, false, true),
            (false, false, true),
            (true, true, true),
            (true, false, false),
        ] {
            let mut scenario = migration::Fixture::default();
            scenario.mode = Some(mode.to_owned());
            let mut faults = FaultInjection::default();
            if refused {
                faults = faults.refuse_batch_pointer("/ip/http/port".to_owned());
            }
            if armed {
                faults = faults.fail_parse_matching("no system", 1);
            }
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
            let mut items = vec![json!({"ip":{"http":{"port":{"port":8430_u16}}}})];
            if partial {
                items.push(json!({"system":{"description":{"description":"lab"}}}));
            }
            let data = serde_json::to_string(&items)?;
            let run = env.kcc(&["--yes", "rci", "batch", "--data", &data])?;
            let applied = !refused;
            let key = if applied {
                keys::MANAGEMENT_DISARM_FAILED
            } else {
                keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED
            };
            assert_eq!(
                run.code,
                if refused { 7_i32 } else { 6_i32 },
                "{mode}: {run:?}"
            );
            assert_eq!(
                run.stderr.contains(&tr(Locale::En, key, None)),
                armed,
                "{mode}: {run:?}"
            );
            if refused {
                let mut args = FluentArgs::new();
                args.set("succeeded", if partial { "1" } else { "0" });
                args.set("failed", "1");
                assert!(
                    run.stderr
                        .contains(&tr(Locale::En, keys::CLI_BATCH_REFUSED, Some(&args))),
                    "{run:?}"
                );
                let value: Value = serde_json::from_str(&run.stdout)?;
                assert_eq!(value.pointer("/items/0/ok"), Some(&json!(false)));
                assert!(run.stdout.contains("injected batch refusal."), "{run:?}");
            }
            assert_eq!(handle.recovery_armed(), armed);
            let entries = read_entries(&env.state_dir())?;
            let batch = entries
                .iter()
                .find(|entry| entry.action == "router.change_batch")
                .ok_or("batch audit")?;
            let outcome = if partial {
                "partially_applied_unsaved"
            } else if refused {
                "failed"
            } else {
                "applied_unsaved"
            };
            assert_eq!(batch.outcome, outcome);
            if armed {
                let entry = entries
                    .iter()
                    .find(|entry| entry.action == "cli.change")
                    .ok_or("CLI audit")?;
                assert_eq!(
                    entry.params_redacted.get("fail_safe_armed"),
                    Some(&json!(true))
                );
            }
            writeln!(
                io::stderr(),
                "T112 CLI mode={mode} refused={refused} partial={partial} key={} exit={} audit={outcome} armed={armed} fake={armed}",
                if armed { key.id() } else { "none" },
                run.code
            )?;
            handle.shutdown().await?;
        }
    }
    Ok(())
}
