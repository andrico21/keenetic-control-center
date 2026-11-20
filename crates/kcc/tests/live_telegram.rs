//! Live Telegram delivery check, plus its hermetic skip proof.
//!
//! `#[ignore]`d; run with `cargo test -p kcc --test live_telegram -- --ignored`. Needs
//! `KCC_LIVE_TELEGRAM_TOKEN_FILE` (the bot token file) and `KCC_LIVE_TELEGRAM_CHAT` (the
//! chat id); when one is missing the test logs `live-skip:<reason>` and returns `Ok(())`.
//! No router is contacted, so the router gates (`KCC_LIVE_TARGET_CONFIG`,
//! `KCC_LIVE_ALLOW_SERIAL`) do not apply. The first message goes through the built
//! `kcc notify test` to the real Bot API (default `api_url`, public-CA TLS); the second is
//! a 4096 UTF-16 unit text of mixed BMP and astral characters sent with the Bot API client.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process and own temporary resources"
)]

extern crate alloc;

#[path = "support/master_key.rs"]
mod master_key;
#[path = "support/spawning.rs"]
mod spawning;
#[path = "cli/support.rs"]
#[expect(dead_code, reason = "the Telegram suite uses no fake router")]
mod support;

use alloc::sync::Arc;
use core::iter;
use std::{env, fs, io, path::PathBuf, sync::Mutex};

use kcc_app::{
    notify_store::recipients::{Chat, ChatId, ChatLabel},
    settings::notifications::DEFAULT_TELEGRAM_API_URL,
};
use kcc_telemetry::notify::{
    bot::{Outgoing, Sent, TelegramClient},
    text::MAX_MESSAGE,
};
use secrecy::SecretString;
use tracing::subscriber::set_default;
use tracing_subscriber::fmt::MakeWriter;
use url::Url;
use zeroize::Zeroizing;

use self::support::{Env, TestResult};

/// Blocks of four UTF-16 units that make up [`MAX_MESSAGE`].
const BLOCKS: usize = 1024;
/// Chat label the suite registers.
const LABEL: &str = "live";

/// The live environment contract.
struct LiveEnv {
    /// Bot token file path.
    token_file: PathBuf,
    /// Target chat id.
    chat: String,
}

/// Reads the variables through `read`, or names the first missing one.
fn live_env(read: &impl Fn(&str) -> Option<String>) -> Result<LiveEnv, &'static str> {
    let get = |name: &str, reason: &'static str| {
        read(name)
            .filter(|value| !value.trim().is_empty())
            .ok_or(reason)
    };
    Ok(LiveEnv {
        token_file: PathBuf::from(get(
            "KCC_LIVE_TELEGRAM_TOKEN_FILE",
            "kcc_live_telegram_token_file-unset",
        )?),
        chat: get("KCC_LIVE_TELEGRAM_CHAT", "kcc_live_telegram_chat-unset")?,
    })
}

/// A text of exactly [`MAX_MESSAGE`] UTF-16 units and fewer characters, mixing ASCII, a
/// two-byte BMP character and an astral one.
fn long_text() -> String {
    iter::repeat_n("A\u{e9}\u{1F600}", BLOCKS).collect()
}

/// Sends the first message through `kcc notify test`, with the owner's token copied into
/// a hermetic state; the copy is removed as soon as it is sealed.
fn cli_leg(live: &LiveEnv) -> TestResult {
    let token = Zeroizing::new(fs::read_to_string(&live.token_file)?);
    let env = Env::new("")?;
    let copy = env.write("bot.token", &token)?;
    let copy_arg = copy.to_str().ok_or("non-UTF-8 path")?;
    let sealed = env.kcc(&["notify", "token", "--file", copy_arg]);
    fs::remove_file(&copy)?;
    assert_eq!(sealed?.code, 0_i32, "notify token failed");
    for args in [
        &["notify", "chat", "add", &live.chat, "--label", LABEL][..],
        &["notify", "test", "--chat", &live.chat][..],
    ] {
        let run = env.kcc(args)?;
        assert_eq!(
            run.code,
            0_i32,
            "{:?} failed: {}",
            args.get(..2),
            run.stderr
        );
    }
    Ok(())
}

/// Sends the 4096 UTF-16 unit text with the Bot API client; the real API must accept it.
// NOT cancel-safe: dropped after the request went out, the message may be delivered
// without the caller learning it.
async fn limit_leg(live: &LiveEnv) -> TestResult {
    let token = SecretString::from(
        fs::read_to_string(&live.token_file)?
            .trim_end_matches(['\r', '\n'])
            .to_owned(),
    );
    let chat = Chat::new(ChatId::parse(&live.chat)?, ChatLabel::parse(LABEL)?);
    let text = long_text();
    assert_eq!(
        text.encode_utf16().count(),
        MAX_MESSAGE,
        "the text must be exactly the UTF-16 limit"
    );
    assert!(
        text.chars().count() < MAX_MESSAGE,
        "the character count must stay below the UTF-16 count"
    );
    let message = Outgoing::new(&chat, &text);
    assert_eq!(message.text(), text, "the text must be sent uncut");
    let client = TelegramClient::new(&Url::parse(DEFAULT_TELEGRAM_API_URL)?, None).await?;
    let _sent: Sent = client.send(&token, &message).await?;
    Ok(())
}

/// The live flow, reading its variables through `read`.
// NOT cancel-safe: sends real messages.
async fn run(read: impl Fn(&str) -> Option<String>) -> TestResult {
    let live = match live_env(&read) {
        Ok(live) => live,
        Err(reason) => {
            tracing::warn!("live-skip:{reason}");
            return Ok(());
        }
    };
    cli_leg(&live)?;
    limit_leg(&live).await
}

#[tokio::test]
#[ignore = "live Telegram: needs KCC_LIVE_TELEGRAM_TOKEN_FILE and KCC_LIVE_TELEGRAM_CHAT"]
async fn live_telegram_delivery() -> TestResult {
    drop(tracing_subscriber::fmt().with_writer(io::stderr).try_init());
    run(|name| env::var(name).ok()).await
}

/// Collects the log lines of the test thread.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_poison| io::Error::other("log buffer poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl MakeWriter<'_> for Captured {
    type Writer = Self;

    fn make_writer(&self) -> Self {
        self.clone()
    }
}

/// Todo 18: without the variables the live flow returns `Ok(())` and logs `live-skip:`.
#[tokio::test]
async fn skips_without_the_variables() -> TestResult {
    let log = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(log.clone())
        .with_ansi(false)
        .finish();
    let guard = set_default(subscriber);
    run(|_name| None).await?;
    drop(guard);
    let text = String::from_utf8(
        log.0
            .lock()
            .map_err(|_poison| "log buffer poisoned")?
            .clone(),
    )?;
    assert!(
        text.contains("live-skip:kcc_live_telegram_token_file-unset"),
        "{text}"
    );
    Ok(())
}
