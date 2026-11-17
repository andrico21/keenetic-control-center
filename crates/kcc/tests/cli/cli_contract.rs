//! The CLI's stable output contract: the `--json` envelope for argument errors, the saved
//! state a rollback reports, and the router a missing confirmation names.

use kcc_testkit::model::Firmware;
use serde_json::Value;

use super::{
    migrate::target,
    support::{Env, TestResult},
};

/// F-27: with `--json`, an argument error is the failure envelope on stderr and exits 2.
#[test]
fn json_argument_errors_use_the_failure_envelope() -> TestResult {
    let env = Env::new("")?;

    let run = env.kcc_bare(&["--json", "--no-such-flag"])?;

    assert_eq!(run.code, 2_i32, "{run:?}");
    assert!(run.stdout.is_empty(), "{run:?}");
    let error: Value = serde_json::from_str(&run.stderr)?;
    assert_eq!(
        error.pointer("/error/kind"),
        Some(&"usage".into()),
        "{error}"
    );
    assert_eq!(
        error.pointer("/error/exit_code"),
        Some(&2_u8.into()),
        "{error}"
    );
    Ok(())
}

/// F-15: a rollback restored the saved configuration, so nothing is left unsaved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rollback_results_report_nothing_unsaved() -> TestResult {
    for finish in [
        &["config", "failsafe", "rollback"][..],
        &["migrate", "finish", "rollback"][..],
    ] {
        let (env, handle) = target(Firmware::V5_1).await?;
        let confirm = ["--confirm-destructive", "target"];
        let arm = env.kcc(&[&confirm[..], &["config", "failsafe", "arm"]].concat())?;
        assert_eq!(arm.code, 0_i32, "{arm:?}");
        let changed = env.kcc(&["system", "set-description", "to-be-rolled-back"])?;
        assert_eq!(changed.code, 0_i32, "{changed:?}");

        let run = env.kcc(&[&["--json"][..], &confirm, finish].concat())?;

        assert_eq!(run.code, 0_i32, "{finish:?}: {run:?}");
        let document: Value = serde_json::from_str(&run.stdout)?;
        assert_eq!(
            document.get("unsaved"),
            Some(&Value::Bool(false)),
            "{finish:?}: {document}"
        );
        handle.shutdown().await?;
    }
    Ok(())
}

/// F-28: a refused confirmation without a terminal names the router, not `-`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_confirmation_names_the_router() -> TestResult {
    let (env, handle) = target(Firmware::V5_1).await?;

    let run = env.kcc(&["--json", "backup", "delete", "absent"])?;

    assert_eq!(run.code, 10_i32, "{run:?}");
    let error: Value = serde_json::from_str(&run.stderr)?;
    let detail = error
        .pointer("/error/details/0")
        .and_then(Value::as_str)
        .ok_or("no detail")?;
    assert!(detail.contains("target"), "{detail}");
    handle.shutdown().await?;
    Ok(())
}
