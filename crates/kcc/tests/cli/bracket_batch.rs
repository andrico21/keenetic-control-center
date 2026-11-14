//! Batch items keep their own outcomes when the recovery cleanup fails.

use fluent_bundle::FluentArgs;
use kcc_app::audit::read_entries;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::FaultInjection;
use serde_json::{Value, json};

use crate::{
    bracket::{lab, reporting},
    support::TestResult,
};

/// Refused, applied and partial batches keep their items, exit code and recovery message;
/// an accepted ordinary sibling never makes a refused management item applied.
// NOT cancel-safe: the fixture owns router tasks until shutdown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batch_completion_controls_recovery_message() -> TestResult {
    for (refused, partial, armed, json_output) in [
        (true, false, true, false),
        (false, false, true, false),
        (true, true, true, false),
        (true, true, true, true),
        (true, false, false, false),
    ] {
        let mut faults = FaultInjection::default();
        if refused {
            faults = faults.refuse_batch_pointer("/ip/http/port".to_owned());
        }
        if armed {
            faults = faults.fail_parse_matching("no system", 1);
        }
        let (env, handle) = lab(reporting("router"), faults, "admin").await?;
        let mut items = vec![json!({"ip":{"http":{"port":{"port":8430_u16}}}})];
        if partial {
            items.push(json!({"system":{"description":{"description":"lab"}}}));
        }
        let data = serde_json::to_string(&items)?;
        let args = ["--json", "--yes", "rci", "batch", "--data", &data];

        let run = env.kcc(if json_output { &args } else { &args[1..] })?;

        let label = format!("refused={refused} partial={partial} json={json_output}: {run:?}");
        let key = if refused {
            keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED
        } else {
            keys::MANAGEMENT_DISARM_FAILED
        };
        let message = tr(Locale::En, key, None);
        assert_eq!(run.code, if refused { 7_i32 } else { 6_i32 }, "{label}");
        if json_output {
            let error: Value = serde_json::from_str(&run.stderr)?;
            assert_eq!(error.pointer("/error/fail_safe_armed"), Some(&json!(true)));
            assert_eq!(error.pointer("/error/message"), Some(&json!(message)));
        } else {
            assert_eq!(run.stderr.contains(&message), armed, "{label}");
        }
        if refused {
            let value: Value = serde_json::from_str(&run.stdout)?;
            assert_eq!(value.pointer("/items/0/ok"), Some(&json!(false)), "{label}");
            assert_eq!(
                value.pointer("/items/1/ok"),
                partial.then_some(&json!(true)),
                "{label}"
            );
            assert!(run.stdout.contains("injected batch refusal."), "{label}");
        }
        if refused && !json_output {
            let mut counts = FluentArgs::new();
            counts.set("succeeded", if partial { "1" } else { "0" });
            counts.set("failed", "1");
            let note = tr(Locale::En, keys::CLI_BATCH_REFUSED, Some(&counts));
            assert!(run.stderr.contains(&note), "{label}");
        }
        assert_eq!(handle.recovery_armed(), armed, "{label}");
        let entries = read_entries(&env.state_dir())?;
        let batch = entries
            .iter()
            .find(|entry| entry.action == "router.change_batch")
            .ok_or("batch audit")?;
        let outcome = match (partial, refused) {
            (true, _) => "partially_applied_unsaved",
            (false, true) => "failed",
            (false, false) => "applied_unsaved",
        };
        assert_eq!(batch.outcome, outcome, "{label}");
        let change = entries.iter().find(|entry| entry.action == "cli.change");
        assert_eq!(
            change.and_then(|entry| entry.params_redacted.get("fail_safe_armed")),
            armed.then_some(&json!(true)),
            "{label}"
        );
        handle.shutdown().await?;
    }
    Ok(())
}
