//! The outbox: retries, refusals, backoff, storm control and the state file.

use core::time::Duration;

use kcc_app::notify_store::{DisabledReason, NotifyRuntime};
use kcc_telemetry::notify::{
    delivery::Line,
    failure::SendError,
    text::{MAX_MESSAGE, fits},
};
use kcc_testkit::fake_telegram::{FakeTelegram, Fault, Request};
use tokio::time::Instant;

use crate::support::{TestResult, WAIT, bounded, chat, outbox, requests, status};

/// A line that happened now.
fn line(text: &str) -> Line {
    Line::new(text.to_owned(), Instant::now())
}

/// Todo 8: after a 429 with `retry_after: 1` the retry waits at least one second.
#[tokio::test]
async fn retry_after_is_honoured() -> TestResult {
    let fake = FakeTelegram::spawn().await?;
    fake.push_fault(Fault::TooManyRequests { retry_after: 1 });
    let (handle, _store, _dir) = outbox(&fake, vec![chat(42)?]).await?;
    handle.push(line("router home is down"));
    requests(&fake, 2).await?;
    let sent = fake.requests();
    let gap = sent
        .get(1)
        .zip(sent.first())
        .map(|(retry, first)| retry.at().saturating_duration_since(first.at()));
    assert!(
        gap.is_some_and(|waited| waited >= Duration::from_secs(1)),
        "waited {gap:?}"
    );
    assert_eq!(
        sent.get(1).map(Request::text),
        Some("router home is down"),
        "same text"
    );
    handle.shutdown().await;
    fake.shutdown().await?;
    Ok(())
}

/// Todo 8: a 401 stops all sending and is recorded in `notify_state.json`.
#[tokio::test]
async fn refused_token_stops_everything() -> TestResult {
    let fake = FakeTelegram::spawn().await?;
    fake.push_fault(Fault::Unauthorized);
    let (handle, store, _dir) = outbox(&fake, vec![chat(42)?, chat(43)?]).await?;
    handle.push(line("one"));
    drop(status(&handle, |current| current.token_rejected).await?);
    handle.push(line("two"));
    assert!(bounded(handle.flush(WAIT)).await?, "idle after the refusal");
    let outcome = bounded(handle.send_now(chat(42)?, "test".to_owned())).await?;
    assert_eq!(
        outcome,
        Err(SendError::TokenRejected),
        "test message refused at once"
    );
    assert_eq!(fake.requests().len(), 1, "nothing sent after the 401");
    let runtime: Option<NotifyRuntime> = store.read()?;
    assert!(
        runtime.is_some_and(|state| state.token_rejected_at.is_some()),
        "refusal recorded"
    );
    handle.shutdown().await;
    fake.shutdown().await?;
    Ok(())
}

/// Todo 8: a 403 and a "chat not found" disable only their chats; the other chat still
/// receives.
#[tokio::test]
async fn refused_chats_are_disabled_alone() -> TestResult {
    let fake = FakeTelegram::spawn().await?;
    fake.push_fault_for(41_i64, Fault::Forbidden);
    fake.push_fault_for(42_i64, Fault::ChatNotFound);
    let (handle, store, _dir) = outbox(&fake, vec![chat(41)?, chat(42)?, chat(43)?]).await?;
    handle.push(line("one"));
    drop(status(&handle, |current| current.disabled_chats.len() == 2).await?);
    handle.push(line("two"));
    requests(&fake, 4).await?;
    assert!(bounded(handle.flush(WAIT)).await?, "idle");
    let per_chat = |id: i64| {
        fake.requests()
            .iter()
            .filter(|request| request.chat_id().as_i64() == Some(id))
            .map(|request| request.text().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        (per_chat(41), per_chat(42)),
        (vec!["one".to_owned()], vec!["one".to_owned()]),
        "one try each"
    );
    assert_eq!(
        per_chat(43),
        ["one", "two"],
        "the other chat still receives"
    );
    let runtime: NotifyRuntime = store.read()?.unwrap_or_default();
    let reasons: Vec<_> = runtime
        .disabled_chats
        .values()
        .map(|mark| mark.reason)
        .collect();
    assert_eq!(
        reasons,
        [DisabledReason::Forbidden, DisabledReason::ChatNotFound],
        "both recorded"
    );
    handle.shutdown().await;
    fake.shutdown().await?;
    Ok(())
}

/// Todo 8: two 500s back off (200 ms, then 400 ms) before the delivery; without drops no
/// summary follows.
#[tokio::test]
async fn transient_failures_back_off() -> TestResult {
    let fake = FakeTelegram::spawn().await?;
    fake.push_fault(Fault::InternalServerError);
    fake.push_fault(Fault::InternalServerError);
    let (handle, _store, _dir) = outbox(&fake, vec![chat(42)?]).await?;
    handle.push(line("one"));
    requests(&fake, 3).await?;
    assert!(bounded(handle.flush(WAIT)).await?, "idle");
    let sent = fake.requests();
    let texts: Vec<&str> = sent.iter().map(Request::text).collect();
    assert_eq!(texts, ["one", "one", "one"], "retried, no summary");
    let gaps: Vec<Duration> = sent
        .windows(2)
        .filter_map(|pair| {
            Some(
                pair.get(1)?
                    .at()
                    .saturating_duration_since(pair.first()?.at()),
            )
        })
        .collect();
    assert!(
        gaps.first()
            .is_some_and(|gap| *gap >= Duration::from_millis(200))
            && gaps
                .get(1)
                .is_some_and(|gap| *gap >= Duration::from_millis(400)),
        "backoff doubles: {gaps:?}"
    );
    handle.shutdown().await;
    fake.shutdown().await?;
    Ok(())
}

/// Todo 8: while the first send is held, 300 more lines keep the newest 256; after the
/// release they arrive joined, in push order, within the length limit, opened by one
/// summary of the 44 dropped lines.
#[tokio::test]
async fn full_queue_keeps_the_newest_lines() -> TestResult {
    let fake = FakeTelegram::spawn().await?;
    fake.push_fault(Fault::Slow(Duration::from_secs(1)));
    let (handle, _store, _dir) = outbox(&fake, vec![chat(42)?]).await?;
    handle.push(line("first"));
    requests(&fake, 1).await?;
    let pushed: Vec<String> = (0..300_u32)
        .map(|index| format!("router line {index:0>4} {}", "-".repeat(16)))
        .collect();
    for text in &pushed {
        handle.push(line(text));
    }
    let held = status(&handle, |current| current.dropped == 44).await?;
    assert!(held.queued <= 256, "at most 256 waiting: {held:?}");
    assert!(bounded(handle.flush(WAIT)).await?, "everything delivered");
    let sent = fake.requests();
    let later: Vec<&str> = sent.iter().skip(1).map(Request::text).collect();
    assert!(
        later
            .iter()
            .all(|text| fits(text) && text.len() <= MAX_MESSAGE),
        "each within the limit"
    );
    let lines: Vec<&str> = later.iter().flat_map(|text| text.lines()).collect();
    let summaries = lines
        .iter()
        .filter(|text| text.starts_with("dropped"))
        .count();
    let delivered: Vec<&str> = lines
        .into_iter()
        .filter(|text| !text.starts_with("dropped"))
        .collect();
    let newest: Vec<&str> = pushed.iter().skip(44).map(String::as_str).collect();
    assert_eq!(delivered, newest, "the newest 256 in push order");
    assert_eq!(summaries, 1, "one summary");
    assert!(
        later
            .first()
            .is_some_and(|text| text.starts_with("dropped 44\n")),
        "it opens the backlog"
    );
    assert!(later.len() >= 2, "the backlog needs more than one message");
    handle.shutdown().await;
    fake.shutdown().await?;
    Ok(())
}
