//! Todo 8: the bot token never appears in logs (the `log` records of reqwest included),
//! error texts or `Debug` output.

use std::{
    io,
    net::TcpListener,
    sync::{Arc, Mutex, PoisonError},
};

use kcc_telemetry::notify::{
    bot::{Outgoing, TelegramClient},
    failure::SendError,
};
use kcc_testkit::fake_telegram::{FakeTelegram, Fault};
use reqwest::Url;
use tracing::Level;
use tracing_subscriber::util::SubscriberInitExt as _;

use crate::support::{TestResult, bounded, chat, client, outbox, token, token_text};

/// Every formatted event, shared with the subscriber's writer.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Capture {
    /// What was captured.
    fn text(&self) -> String {
        let bytes = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

/// Todo 8: a TRACE capture with the `log` bridge, every error text and the client's
/// `Debug` hold no part of the token.
#[tokio::test]
async fn token_never_leaks() -> TestResult {
    let capture = Capture::default();
    let writer = capture.clone();
    let _guard = tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish()
        .set_default();
    let fake = FakeTelegram::spawn().await?;
    let elsewhere = FakeTelegram::spawn().await?;
    let bot = client(&fake).await?;
    let message = Outgoing::new(&chat(42)?, "router home is down");
    let mut texts = vec![format!("{bot:?}"), format!("{message:?}")];
    let mut outcomes = vec![bounded(bot.send(&token(), &message)).await?.err()];
    for fault in [
        Fault::Unauthorized,
        Fault::Forbidden,
        Fault::TooManyRequests { retry_after: 1 },
        Fault::InternalServerError,
        Fault::Redirect(format!(
            "{}/bot{}/sendMessage",
            elsewhere.url(),
            token_text()
        )),
    ] {
        fake.push_fault(fault);
        outcomes.push(bounded(bot.send(&token(), &message)).await?.err());
    }
    let closed = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let unreachable = TelegramClient::new(&Url::parse(&format!("http://{closed}"))?, None).await?;
    outcomes.push(bounded(unreachable.send(&token(), &message)).await?.err());
    let (handle, _store, _dir) = outbox(&fake, vec![chat(42)?]).await?;
    texts.push(format!("{handle:?}"));
    handle.shutdown().await;
    for error in outcomes.iter().flatten() {
        texts.push(format!("{error} {error:?}"));
    }
    assert!(
        outcomes
            .iter()
            .flatten()
            .any(|error| matches!(error, SendError::Transient { status: None })),
        "a connect failure was mapped"
    );
    let logged = capture.text();
    assert!(
        logged.contains("starting new connection"),
        "reqwest's log records reach the capture"
    );
    let secret = token_text();
    let (_, key) = secret.split_once(':').ok_or("token shape")?;
    for text in texts.iter().chain([&logged]) {
        assert!(
            !text.contains(&secret) && !text.contains(key),
            "token leaked into: {text}"
        );
    }
    fake.shutdown().await?;
    elsewhere.shutdown().await?;
    Ok(())
}
