//! `kcc copy`: the finish rule and the three ways a verified copy ends.

use kcc_app::audit::{ActorKind, read_entries};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::model::Profile;
use serde_json::{Value, json};

use super::{
    fixture::{Pair, UPSTREAM, stdout_json},
    support::{TestResult, USER},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn copy_without_finish_exits_2_before_any_request() -> TestResult {
    let pair = Pair::start(Profile::default()).await?;
    let before = pair.requests();
    let run = pair.copy(&[])?;
    assert_eq!(run.code, 2_i32, "{run:?}");
    assert!(
        run.stderr
            .contains(&tr(Locale::En, keys::CLI_PRESET_FINISH_REQUIRED, None)),
        "{}",
        run.stderr
    );
    assert_eq!(pair.requests(), before);
    pair.stop().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keep_unsaved_leaves_startup_unchanged_and_the_timer_disarmed() -> TestResult {
    let pair = Pair::start(Profile::default()).await?;
    let startup = pair.target.startup_config_text();
    let run = pair.copy(&["--finish", "keep-unsaved"])?;
    assert_eq!(run.code, 0_i32, "{run:?}");
    let result = stdout_json(&run)?;
    assert_eq!(
        result.get("finish"),
        Some(&json!("keep-unsaved")),
        "{result}"
    );
    assert_eq!(result.get("verified"), Some(&json!(true)), "{result}");
    assert!(pair.target.running_config_text().contains(UPSTREAM));
    assert_eq!(pair.target.startup_config_text(), startup);
    let reply = pair
        .env
        .kcc(&["--router", "fake-b", "--json", "config", "state"])?;
    assert_eq!(reply.code, 0_i32, "{reply:?}");
    let state = stdout_json(&reply)?;
    assert_eq!(
        state.pointer("/fail-safe/active"),
        Some(&json!(false)),
        "{state}"
    );
    assert_eq!(state.get("unsaved"), Some(&json!(true)), "{state}");
    pair.stop().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn save_writes_the_lines_to_startup_and_is_audited_as_the_cli_user() -> TestResult {
    let pair = Pair::start(Profile::default()).await?;
    let run = pair.copy(&["--finish", "save"])?;
    assert_eq!(run.code, 0_i32, "{run:?}");
    assert_eq!(stdout_json(&run)?.get("finish"), Some(&json!("save")));
    assert!(pair.target.startup_config_text().contains(UPSTREAM));
    let audited = read_entries(&pair.env.state_dir())?
        .into_iter()
        .any(|entry| {
            entry.actor.kind == ActorKind::Cli
                && entry.actor.id == format!("cli:{USER}")
                && entry.router.as_deref() == Some("fake-b")
        });
    assert!(audited, "the copy is not audited as the CLI user");
    pair.stop().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rollback_restores_the_running_config_from_before_the_copy() -> TestResult {
    let pair = Pair::start(Profile::default()).await?;
    let running = pair.target.running_config_text();
    let run = pair.copy(&["--finish", "rollback"])?;
    assert_eq!(run.code, 0_i32, "{run:?}");
    let result: Value = stdout_json(&run)?;
    assert_eq!(result.get("applied"), Some(&json!(1_u64)), "{result}");
    assert_eq!(result.get("finish"), Some(&json!("rollback")), "{result}");
    assert_eq!(pair.target.running_config_text(), running);
    pair.stop().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn target_outside_the_cli_scope_exits_10_before_any_request() -> TestResult {
    let pair = Pair::start(Profile::default()).await?;
    pair.with_cli("role = \"operator\"\nrouter_scope = [\"fake-a\"]")?;
    let before = pair.requests();
    let run = pair.copy(&["--finish", "save"])?;
    assert_eq!(run.code, 10_i32, "{run:?}");
    assert_eq!(pair.requests(), before);
    pair.stop().await
}

/// A copy that finishes with a save prints its finish outcome and never the headline of
/// an unsaved change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn copy_finishing_with_save_never_says_unsaved() -> TestResult {
    let pair = Pair::start(Profile::default()).await?;
    let run = pair.copy(&["--finish", "save"])?;
    assert_eq!(run.code, 0_i32, "{run:?}");
    let not_saved = tr(Locale::En, keys::CLI_APPLIED, None);
    assert!(
        !run.stdout.contains(&not_saved) && !run.stderr.contains(&not_saved),
        "{run:?}"
    );
    pair.stop().await
}
