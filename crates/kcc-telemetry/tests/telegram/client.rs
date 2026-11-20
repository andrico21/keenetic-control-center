//! The client: request body, reply mapping, length limits, redirects and the resolver.

use core::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use std::{
    io::{self, Write as _},
    sync::{Arc, Mutex, PoisonError},
};

use kcc_app::notify_store::DisabledReason;
use kcc_telemetry::notify::{
    bot::{Outgoing, Sent, TelegramClient},
    dns::PolicyResolver,
    failure::SendError,
    text::MAX_MESSAGE,
};
use kcc_testkit::fake_telegram::{FakeTelegram, Fault};
use reqwest::Url;
use serde_json::json;

use crate::support::{TestResult, bounded, chat, client, token, token_text};

/// Todo 8: a message goes out with exactly the plain-text body; the thread only when set.
#[tokio::test]
async fn body_is_plain_text_and_thread_only_when_set() -> TestResult {
    let fake = FakeTelegram::spawn().await?;
    fake.expect_token(&token_text());
    let bot = client(&fake).await?;
    let plain = chat(42)?;
    let mut topic = chat(-1_001_234)?;
    topic.thread = Some(7);
    topic.silent = true;
    let sent = bounded(bot.send(&token(), &Outgoing::new(&plain, "router home is down"))).await??;
    assert_eq!(sent.message_id, Some(1), "Telegram's message id");
    let _sent: Sent = bounded(bot.send(&token(), &Outgoing::new(&topic, "in a topic"))).await??;
    let requests = fake.requests();
    let bodies: Vec<_> = requests
        .iter()
        .map(|request| request.body().clone())
        .collect();
    assert_eq!(
        bodies,
        [
            json!({"chat_id": 42_i64, "text": "router home is down", "disable_notification": false,
                "link_preview_options": {"is_disabled": true}}),
            json!({"chat_id": -1_001_234_i64, "text": "in a topic", "disable_notification": true,
                "link_preview_options": {"is_disabled": true}, "message_thread_id": 7_i64}),
        ],
        "exact bodies"
    );
    fake.shutdown().await?;
    Ok(())
}

/// Todo 8: refusals map to their decisions.
#[tokio::test]
async fn refusals_map_to_decisions() -> TestResult {
    let fake = FakeTelegram::spawn().await?;
    let bot = client(&fake).await?;
    let message = Outgoing::new(&chat(42)?, "x");
    let faults = [
        (
            Fault::TooManyRequests { retry_after: 3 },
            SendError::RetryAfter(Duration::from_secs(3)),
        ),
        (Fault::Unauthorized, SendError::TokenRejected),
        (
            Fault::Forbidden,
            SendError::ChatUnavailable(DisabledReason::Forbidden),
        ),
        (
            Fault::ChatNotFound,
            SendError::ChatUnavailable(DisabledReason::ChatNotFound),
        ),
        (
            Fault::InternalServerError,
            SendError::Transient { status: Some(500) },
        ),
    ];
    for (fault, expected) in faults {
        fake.push_fault(fault);
        let outcome = bounded(bot.send(&token(), &message)).await?;
        assert_eq!(outcome, Err(expected), "{expected:?}");
    }
    fake.shutdown().await?;
    Ok(())
}

/// Todo 8: a 302 is a transient failure and its `Location` is never requested.
#[tokio::test]
async fn redirect_is_not_followed() -> TestResult {
    let fake = FakeTelegram::spawn().await?;
    let elsewhere = FakeTelegram::spawn().await?;
    let bot = client(&fake).await?;
    fake.push_fault(Fault::Redirect(format!(
        "{}/bot{}/sendMessage",
        elsewhere.url(),
        token_text()
    )));
    let outcome = bounded(bot.send(&token(), &Outgoing::new(&chat(42)?, "x"))).await?;
    assert_eq!(
        outcome,
        Err(SendError::Transient { status: Some(302) }),
        "302 is transient"
    );
    let (asked, redirected) = (fake.requests(), elsewhere.requests());
    let log: Vec<String> = asked
        .iter()
        .map(|request| format!("chat_id={} text={}", request.chat_id(), request.text()))
        .collect();
    writeln!(
        io::stderr(),
        "redirect proof: fake requests {} [{}]; Location target requests {}",
        asked.len(),
        log.join(", "),
        redirected.len()
    )?;
    assert_eq!(
        (asked.len(), redirected.len()),
        (1, 0),
        "the Location was never requested: {redirected:?}"
    );
    fake.shutdown().await?;
    elsewhere.shutdown().await?;
    Ok(())
}

/// Todo 8: a 5000-character text and a 3000-emoji text are cut so that the fake, which
/// refuses more than 4096 UTF-16 units, accepts both.
#[tokio::test]
async fn long_texts_fit_both_limits() -> TestResult {
    let fake = FakeTelegram::spawn().await?;
    let bot = client(&fake).await?;
    let target = chat(42)?;
    for text in ["a".repeat(5000), "\u{1F600}".repeat(3000)] {
        let _sent: Sent = bounded(bot.send(&token(), &Outgoing::new(&target, &text))).await??;
    }
    for request in fake.requests() {
        let text = request.text();
        assert!(
            text.chars().count() <= MAX_MESSAGE,
            "characters within the limit"
        );
        assert!(
            text.encode_utf16().count() <= MAX_MESSAGE,
            "UTF-16 within the limit"
        );
        assert!(text.ends_with('\u{2026}'), "cut texts end with an ellipsis");
    }
    fake.shutdown().await?;
    Ok(())
}

/// Todo 8: a host the lookup maps to a metadata address is refused before any
/// connection; one mapped to loopback reaches the fake.
#[tokio::test]
async fn resolver_refuses_metadata_addresses() -> TestResult {
    let fake = FakeTelegram::spawn().await?;
    let port = Url::parse(&fake.url())?.port().ok_or("port")?;
    let asked = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&asked);
    let resolver = PolicyResolver::with_lookup(move |host: &str| {
        seen.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(host.to_owned());
        match host {
            "metadata.test" => vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))],
            "loopback.test" => vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            _ => Vec::new(),
        }
    });
    let message = Outgoing::new(&chat(42)?, "x");
    let refused_url = Url::parse(&format!("http://metadata.test:{port}"))?;
    let refused = TelegramClient::with_resolver(&refused_url, None, resolver.clone()).await?;
    let outcome = bounded(refused.send(&token(), &message)).await?;
    assert_eq!(
        outcome,
        Err(SendError::AddressRefused),
        "metadata address refused"
    );
    assert!(fake.requests().is_empty(), "no request reached anything");
    let allowed_url = Url::parse(&format!("http://loopback.test:{port}"))?;
    let allowed = TelegramClient::with_resolver(&allowed_url, None, resolver).await?;
    let _sent: Sent = bounded(allowed.send(&token(), &message)).await??;
    assert_eq!(fake.requests().len(), 1, "loopback delivered");
    let hosts = asked.lock().unwrap_or_else(PoisonError::into_inner).clone();
    assert_eq!(
        hosts,
        ["metadata.test", "loopback.test"],
        "both names went through the lookup"
    );
    let literal = Url::parse("http://169.254.169.254")?;
    let literal_outcome = TelegramClient::new(&literal, None).await;
    assert_eq!(
        literal_outcome.err(),
        Some(SendError::AddressRefused),
        "a literal is refused too"
    );
    fake.shutdown().await?;
    Ok(())
}
