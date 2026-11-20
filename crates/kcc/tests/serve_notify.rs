//! `kcc serve` delivers Telegram notifications: with notifications switched on in the state
//! and the bot token set on the Web page while it runs, the firmware update a router offers
//! and an account lockout reach the chat, and the token is nowhere in the state directory,
//! the audit log or the server's TRACE log. Counts and deduplication are proven by the
//! notifier's own tests; this one proves delivery through the real process.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process"
)]

#[path = "support/master_key.rs"]
mod master_key;
#[path = "serve_notify/process.rs"]
mod process;
#[path = "support/serve_port.rs"]
mod serve_port;
#[path = "support/spawning.rs"]
mod spawning;
#[path = "serve_notify/support.rs"]
mod support;
#[expect(dead_code, reason = "this suite only signs in and posts a form")]
#[path = "serve_refresh/web.rs"]
mod web;

use kcc_app::notify_store::NotifyRuntime;

use crate::{
    process::files,
    support::{FIRMWARE, Fixture, ROUTER, TestResult},
    web::Browser,
};

/// Todo 10: the firmware a router offers and a Web account lockout reach the chat.
///
/// The token is set on the Web page after the start; `notify_state.json` records the
/// announced version; the token's bytes are in no state file, audit entry or stderr line
/// (TRACE).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn firmware_and_lockout_reach_telegram_and_the_token_stays_secret() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let server = fixture.serve()?;
    let alice = Browser::sign_in(fixture.http(), fixture.base(), "alice").await?;
    let token = fixture.token().to_owned();

    let stored = alice
        .post(
            fixture.http(),
            fixture.base(),
            (
                "/ui/admin/notifications/token",
                &[("token", token.as_str())],
            ),
        )
        .await?;
    assert!(
        stored.status().is_success(),
        "token form: {}",
        stored.status()
    );
    for _attempt in 0..5_u8 {
        fixture.wrong_sign_in("bob").await?;
    }
    let firmware = fixture.message(FIRMWARE).await?;
    let lockout = fixture.message("bob").await?;
    let runtime = fixture
        .state()?
        .read::<NotifyRuntime>()?
        .ok_or("notify_state.json is missing")?;
    let stderr = server.finish();

    assert!(firmware.starts_with("[kcc]"), "{firmware}");
    assert!(lockout.contains("locked"), "{lockout}");
    assert_eq!(
        runtime.firmware_notified.get(ROUTER).map(String::as_str),
        Some(FIRMWARE),
        "the announced version is recorded"
    );
    let (_bot, secret) = token.split_once(':').ok_or("token shape")?;
    let state_files = files(fixture.state()?.dir())?;
    assert!(
        state_files.iter().any(|(path, _bytes)| path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("audit"))),
        "the audit log is among the scanned files"
    );
    for (path, bytes) in &state_files {
        assert!(
            !bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()),
            "the token is in {}",
            path.display()
        );
    }
    assert!(stderr.contains("TRACE"), "the server logged at TRACE");
    assert!(
        !stderr.contains(secret),
        "the token is in the server's stderr"
    );
    Ok(())
}
