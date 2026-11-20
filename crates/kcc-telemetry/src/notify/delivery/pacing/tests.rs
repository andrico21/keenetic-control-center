//! Pacing rules without a clock: every instant is derived from one base.
#![expect(
    clippy::missing_panics_doc,
    reason = "test assertions are not rendered API documentation"
)]

use core::time::Duration;

use tokio::time::Instant;

use super::{ChatQueue, QUEUE_LINES, later};
use crate::notify::{delivery::Timings, text::fits};

/// The production timings.
fn timings() -> Timings {
    Timings::default()
}

/// `base` plus `seconds`.
fn at(base: Instant, seconds: u64) -> Instant {
    later(base, Duration::from_secs(seconds))
}

/// Queues `text` that happened and arrived at `when`.
fn queue_at(queue: &mut ChatQueue, text: &str, when: Instant) -> u64 {
    queue.push(text.to_owned(), when, when)
}

/// The text of the next message at `now`, if any.
fn next_text(queue: &mut ChatQueue, now: Instant) -> Option<String> {
    queue
        .take(now, &timings())
        .0
        .map(|batch| batch.text().to_owned())
}

/// Todo 8: the first line after a quiet merge window goes at once; a line within the
/// window after a send waits for the window's end.
#[test]
fn merge_window_decides_when_lines_go() {
    let base = Instant::now();
    let mut queue = ChatQueue::default();
    assert_eq!(queue_at(&mut queue, "first", base), 0, "room left");
    assert_eq!(
        queue.due(&timings(), false),
        Some(base),
        "first line at once"
    );
    assert_eq!(
        next_text(&mut queue, base).as_deref(),
        Some("first"),
        "sent alone"
    );
    queue.started(base, &timings());
    assert_eq!(queue_at(&mut queue, "second", at(base, 2)), 0, "room left");
    assert_eq!(queue_at(&mut queue, "third", at(base, 5)), 0, "room left");
    assert_eq!(
        queue.due(&timings(), false),
        Some(at(base, 30)),
        "waits for the window"
    );
    assert_eq!(
        queue.due(&timings(), true),
        Some(at(base, 2)),
        "a flush skips the window, not the spacing"
    );
    assert_eq!(
        next_text(&mut queue, at(base, 30)).as_deref(),
        Some("second\nthird"),
        "joined oldest first"
    );
    assert_eq!(queue_at(&mut queue, "late", at(base, 100)), 0, "room left");
    assert_eq!(
        queue.due(&timings(), false),
        Some(at(base, 100)),
        "quiet window: at once"
    );
}

/// Todo 8: lines that did not fit wait only for the rate limits, and at most 20
/// messages go out per rate window.
#[test]
fn backlog_waits_for_rate_limits_only() {
    let base = Instant::now();
    let mut queue = ChatQueue::default();
    for index in 0..300_u32 {
        let _shed: u64 = queue_at(&mut queue, &format!("{index:0>40}"), base);
    }
    let first = queue.take(base, &timings()).0;
    let shape = first.map(|batch| (batch.len(), fits(batch.text())));
    assert!(
        shape.is_some_and(|(lines, fitting)| lines > 0 && lines < QUEUE_LINES && fitting),
        "the first message fits and leaves lines: {shape:?}"
    );
    queue.started(base, &timings());
    assert_eq!(
        queue.due(&timings(), false),
        Some(at(base, 1)),
        "the rest after the spacing"
    );
    let mut busy = ChatQueue::default();
    for second in 0..20_u64 {
        busy.started(at(base, second), &timings());
    }
    assert_eq!(
        busy.rate_due(&timings()),
        Some(at(base, 60)),
        "21st message after the window"
    );
}

/// Todo 8: a full queue drops its oldest lines and the next message opens with exactly
/// one summary; nothing is summarized without drops.
#[test]
fn drops_lead_to_one_summary() {
    let base = Instant::now();
    let mut queue = ChatQueue::default();
    let mut dropped = 0_u64;
    for index in 0..300_u32 {
        dropped = dropped.saturating_add(queue_at(&mut queue, &format!("line {index}"), base));
    }
    assert_eq!(
        (dropped, queue.queued()),
        (44, QUEUE_LINES),
        "oldest 44 dropped"
    );
    queue.delivered(base, |count| format!("dropped {count}"));
    let text = next_text(&mut queue, base).unwrap_or_default();
    let opening: Vec<&str> = text.lines().take(2).collect();
    assert_eq!(
        opening,
        ["dropped 44", "line 44"],
        "summary, then the oldest kept line"
    );
    queue.delivered(base, |count| format!("dropped {count}"));
    assert_eq!(queue.queued(), 0, "every kept line fit into one message");
    assert_eq!(next_text(&mut queue, base), None, "no second summary");
}

/// Todo 8: a line older than the maximum age is dropped and counted; a failed batch
/// goes back in order.
#[test]
fn expiry_and_restore() {
    let base = Instant::now();
    let mut queue = ChatQueue::default();
    assert_eq!(queue_at(&mut queue, "old", base), 0, "room left");
    assert_eq!(queue_at(&mut queue, "new", at(base, 3000)), 0, "room left");
    let (taken, expired) = queue.take(at(base, 3600), &timings());
    assert_eq!(expired, 1, "the old line expired");
    assert_eq!(
        taken.as_ref().map(super::Batch::text),
        Some("new"),
        "only the new line"
    );
    if let Some(failed) = taken {
        queue.restore(failed);
    }
    assert_eq!(queue.queued(), 1, "back in the queue");
    queue.delivered(base, |count| format!("dropped {count}"));
    assert_eq!(
        next_text(&mut queue, at(base, 3600)).as_deref(),
        Some("dropped 1\nnew"),
        "expiry is summarized"
    );
}
