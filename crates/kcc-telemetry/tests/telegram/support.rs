//! Shared setup of the Telegram tests: run-time tokens, chats, clients, outboxes and
//! bounded waits.

use core::{error::Error, time::Duration};

use kcc_app::{
    notify_store::recipients::{Chat, ChatId, ChatLabel},
    persist::StateStore,
};
use kcc_telemetry::notify::{
    bot::TelegramClient,
    delivery::{Outbox, OutboxConfig, OutboxHandle, OutboxStatus, Timings},
};
use kcc_testkit::fake_telegram::FakeTelegram;
use reqwest::Url;
use secrecy::SecretString;
use tempfile::TempDir;
use tokio::time::timeout;

/// Result of a test that propagates setup errors.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// Upper bound of every wait: generous, since the timings are real time.
pub(crate) const WAIT: Duration = Duration::from_secs(20);

/// A bot token in the Bot API shape, built at run time.
pub(crate) fn token_text() -> String {
    format!("{}:ABC-test_token_{}", 123_456_u32, "x".repeat(20))
}

/// [`token_text`] as a secret.
pub(crate) fn token() -> SecretString {
    SecretString::from(token_text())
}

/// A chat with a numeric id.
pub(crate) fn chat(id: i64) -> TestResult<Chat> {
    Ok(Chat::new(
        ChatId::parse(&id.to_string())?,
        ChatLabel::parse("ops")?,
    ))
}

/// The summary line the tests configure.
pub(crate) fn summary(count: u64) -> String {
    format!("dropped {count}")
}

/// Short timings: merge window 300 ms, spacing 50 ms, backoff 200 ms doubling to 800 ms.
pub(crate) fn timings() -> Timings {
    let mut timings = Timings::default();
    timings.merge_window = Duration::from_millis(300);
    timings.rate_spacing = Duration::from_millis(50);
    timings.backoff_base = Duration::from_millis(200);
    timings.backoff_cap = Duration::from_millis(800);
    timings
}

/// A client for the fake.
pub(crate) async fn client(fake: &FakeTelegram) -> TestResult<TelegramClient> {
    Ok(TelegramClient::new(&Url::parse(&fake.url())?, None).await?)
}

/// An outbox for the fake with a fresh state directory, configured with `chats`.
pub(crate) async fn outbox(
    fake: &FakeTelegram,
    chats: Vec<Chat>,
) -> TestResult<(OutboxHandle, StateStore, TempDir)> {
    let dir = tempfile::tempdir()?;
    let store = StateStore::open(dir.path())?;
    let handle = Outbox::spawn(
        client(fake).await?,
        OutboxConfig::new(summary),
        store.clone(),
        None,
        timings(),
    );
    handle.configure(Some(token()), chats, true);
    Ok((handle, store, dir))
}

/// Waits, bounded by [`WAIT`], until `fake` captured `count` requests.
pub(crate) async fn requests(fake: &FakeTelegram, count: usize) -> TestResult {
    timeout(WAIT, fake.wait_for_requests(count)).await?;
    Ok(())
}

/// Waits, bounded by [`WAIT`], until the outbox status satisfies `wanted`.
pub(crate) async fn status<F>(handle: &OutboxHandle, wanted: F) -> TestResult<OutboxStatus>
where
    F: Fn(&OutboxStatus) -> bool + Send,
{
    let mut watcher = handle.watch_status();
    let seen = timeout(WAIT, watcher.wait_for(wanted)).await??;
    Ok(seen.clone())
}

/// Runs `step` bounded by [`WAIT`].
pub(crate) async fn bounded<T, F>(step: F) -> TestResult<T>
where
    F: Future<Output = T>,
{
    Ok(timeout(WAIT, step).await?)
}
