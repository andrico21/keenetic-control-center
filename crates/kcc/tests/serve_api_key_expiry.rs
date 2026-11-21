//! A running `kcc serve` refuses an API key once its expiry has passed, with HTTP 401 on
//! `/mcp`, while a key without an expiry keeps working. The expiry is checked on every
//! request against the real clock, and an expiry written to `api_keys.json` while the
//! server runs is applied by the state watcher.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process"
)]

#[path = "support/master_key.rs"]
mod master_key;
#[path = "support/serve_port.rs"]
mod serve_port;
#[path = "support/spawning.rs"]
mod spawning;
#[expect(
    dead_code,
    reason = "the shared serve fixture; this suite needs its process and clients only"
)]
#[path = "serve_state_watch/support.rs"]
mod support;

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use kcc_app::{
    api_keys::{ApiKeysDocument, create_api_key, expose_created_key},
    permissions::{Permission, Role},
};
use reqwest::{StatusCode, header};
use serde_json::json;
use tokio::time::{Instant, MissedTickBehavior, interval, timeout_at};

use crate::support::{Fixture, KEY_NAME, TestResult};

/// How often a test asks again while it waits for an expiry to take effect.
const RETRY: Duration = Duration::from_millis(250);

/// Upper bound for an expiry to take effect after it passed or was written.
const SETTLE: Duration = Duration::from_secs(30);

/// The current Unix second.
fn now() -> TestResult<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

/// The status of an MCP `initialize` made with `key`.
async fn mcp_status(fixture: &Fixture, key: &str) -> TestResult<StatusCode> {
    Ok(fixture
        .http()
        .post(format!("{}/mcp", fixture.base()))
        .bearer_auth(key)
        .header(header::ACCEPT, "application/json, text/event-stream")
        .json(&json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"expiry","version":"1"}}}))
        .send()
        .await?
        .status())
}

/// Asks with `ask` every [`RETRY`] until the server answers 401, for at most
/// [`SETTLE`]; every answer before that must be 200.
async fn refused_within_settle<F, A>(mut ask: F) -> TestResult
where
    F: FnMut() -> A,
    A: Future<Output = TestResult<StatusCode>>,
{
    let deadline = Instant::now()
        .checked_add(SETTLE)
        .ok_or("deadline overflow")?;
    let mut ticks = interval(RETRY);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let waited = timeout_at(deadline, async {
        loop {
            let _tick = ticks.tick().await;
            match ask().await? {
                StatusCode::UNAUTHORIZED => return TestResult::Ok(()),
                StatusCode::OK => {}
                other => return Err(format!("unexpected status {other}").into()),
            }
        }
    })
    .await;
    waited.map_err(|_elapsed| "the key was still accepted after its expiry")?
}

/// Todo 24: a key that expires a few seconds after the server started is refused with
/// 401 once that time has passed; the key without an expiry still gets 200.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_is_refused_once_its_expiry_has_passed() -> TestResult {
    let fixture = Fixture::new()?;
    let created_at = now()?;
    let brief = create_api_key(
        &fixture.state()?,
        &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
        "brief".to_owned(),
        "viewer".to_owned(),
        created_at,
        Some(created_at.saturating_add(3)),
    )?;
    let _server = fixture.serve()?;

    let key = expose_created_key(&brief);
    refused_within_settle(|| mcp_status(&fixture, key)).await?;

    assert!(
        now()? >= created_at.saturating_add(3),
        "refused before its expiry"
    );
    assert_eq!(
        fixture.mcp_status().await?,
        StatusCode::OK,
        "the key without an expiry"
    );
    Ok(())
}

/// Todo 24: an expiry in the past written to `api_keys.json` while the server runs
/// reaches the transport, and the key is refused with 401.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expiry_written_while_serving_takes_effect() -> TestResult {
    let fixture = Fixture::new()?;
    let _server = fixture.serve()?;
    assert_eq!(fixture.mcp_status().await?, StatusCode::OK, "the key works");

    let past = now()?.saturating_sub(60);
    fixture.state()?.update(|document: &mut ApiKeysDocument| {
        for key in document.keys.iter_mut().filter(|key| key.name == KEY_NAME) {
            key.expires_at = Some(past);
        }
    })?;

    refused_within_settle(|| fixture.mcp_status()).await
}
