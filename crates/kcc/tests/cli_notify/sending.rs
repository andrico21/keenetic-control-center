//! `kcc notify test` against a fake Bot API.

use core::time::Duration;

use kcc_testkit::fake_telegram::{FakeTelegram, Fault};
use serde_json::{Value, json};
use tokio::time::timeout;

use crate::{
    CHAT, assert_hidden, audited, env_for, ok, set_token, show, support::TestResult, token,
};

/// Todo 12: `notify test` sends one message to the chat's thread, silently when the
/// chat is silent, with the sealed token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_test_message_is_delivered_once() -> TestResult {
    let fake = FakeTelegram::spawn().await?;
    let token = token();
    fake.expect_token(&token);
    let env = env_for(Some(&fake.url()))?;
    let set = set_token(&env, &token)?;
    drop(ok(
        &env,
        &[
            "notify", "chat", "add", CHAT, "--label", "Family", "--thread", "7", "--silent",
        ],
    )?);
    let delivered = ok(&env, &["notify", "test", "--chat", CHAT])?;
    timeout(Duration::from_secs(10), fake.wait_for_requests(1)).await?;
    let requests = fake.requests();
    assert_eq!(requests.len(), 1);
    let body = requests
        .first()
        .map(|request| request.body().clone())
        .ok_or("no request")?;
    assert_eq!(body.get("chat_id"), Some(&json!(-1_001_234_567_i64)));
    assert_eq!(body.get("message_thread_id"), Some(&json!(7_i64)));
    assert_eq!(body.get("disable_notification"), Some(&json!(true)));
    let entries = audited(&env, "cli.notify_test")?;
    assert_eq!(
        entries
            .first()
            .and_then(|entry| entry.get("params_redacted")),
        Some(&json!({ "label": "Family" }))
    );
    assert_hidden(&env, &token, &[&set, &delivered])?;
    fake.shutdown().await?;
    Ok(())
}

/// Todo 12: a token Telegram answers 401 to fails the test with the router exit code
/// and the class `token_rejected`, and `show` reports the rejection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_token_fails_the_test() -> TestResult {
    let fake = FakeTelegram::spawn().await?;
    fake.push_fault(Fault::Unauthorized);
    let token = token();
    let env = env_for(Some(&fake.url()))?;
    let set = set_token(&env, &token)?;
    drop(ok(
        &env,
        &["notify", "chat", "add", CHAT, "--label", "Family"],
    )?);
    let failed = env.kcc(&["--json", "notify", "test"])?;
    assert_eq!(failed.code, 6_i32, "{failed:?}");
    let error: Value = serde_json::from_str(failed.stderr.trim())?;
    let details = error
        .pointer("/error/details")
        .and_then(Value::as_array)
        .ok_or("no details")?;
    assert!(
        details
            .iter()
            .filter_map(Value::as_str)
            .any(|line| line.contains("token_rejected")),
        "{error}"
    );
    assert!(
        show(&env)?
            .pointer("/token/rejected_at")
            .is_some_and(Value::is_u64)
    );
    let entries = audited(&env, "cli.notify_test")?;
    let entry = entries.first().ok_or("no test audit")?;
    assert_eq!(entry.get("outcome"), Some(&json!("failed")));
    assert_eq!(
        entry.get("params_redacted"),
        Some(&json!({ "label": "Family", "failure": "token_rejected" }))
    );
    assert_hidden(&env, &token, &[&set, &failed])?;
    fake.shutdown().await?;
    Ok(())
}
