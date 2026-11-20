//! Per-chat pacing without I/O: the line queue, merge windows, rate limits, the length
//! limit and line expiry. The outbox task drives it with instants it reads itself.

use alloc::collections::VecDeque;
use core::time::Duration;

use tokio::time::Instant;

use super::Timings;
use crate::notify::text::{fit, fits};

/// Most messages to one chat within [`Timings::rate_window`].
const BURST: usize = 20;
/// Most lines waiting for one chat; the oldest is dropped beyond it.
pub(super) const QUEUE_LINES: usize = 256;

/// `at + by`, or `at` in the impossible case that the sum overflows.
pub(super) fn later(at: Instant, by: Duration) -> Instant {
    at.checked_add(by).unwrap_or(at)
}

/// One waiting line.
#[derive(Debug)]
struct Pending {
    /// The line.
    text: String,
    /// When the event happened; decides expiry.
    at: Instant,
    /// When the outbox queued it; decides merging.
    queued: Instant,
}

/// The lines and the summary of one message being sent.
#[derive(Debug)]
pub(super) struct Batch {
    /// The lines in queue order.
    lines: Vec<Pending>,
    /// The summary that opens the message, with when it was made.
    summary: Option<(String, Instant)>,
    /// The joined text, within the length limit.
    text: String,
}

impl Batch {
    /// The joined text.
    pub(super) fn text(&self) -> &str {
        &self.text
    }

    /// How many queued lines the message carries.
    pub(super) const fn len(&self) -> usize {
        self.lines.len()
    }
}

/// The queue and send history of one chat.
#[derive(Debug, Default)]
pub(super) struct ChatQueue {
    /// Waiting lines, oldest first.
    lines: VecDeque<Pending>,
    /// Start of the latest send.
    last_sent: Option<Instant>,
    /// Starts of the sends within the rate window, oldest first.
    recent: VecDeque<Instant>,
    /// Lines of this chat dropped since its latest delivered message.
    dropped: u64,
    /// The drop summary that opens the next message, with when it was made.
    summary: Option<(String, Instant)>,
}

impl ChatQueue {
    /// Queues a line; answers how many lines were dropped to make room (0 or 1).
    pub(super) fn push(&mut self, text: String, at: Instant, now: Instant) -> u64 {
        let mut dropped = 0_u64;
        while self.lines.len() >= QUEUE_LINES {
            drop(self.lines.pop_front());
            dropped = dropped.saturating_add(1);
        }
        self.lines.push_back(Pending {
            text,
            at,
            queued: now,
        });
        self.note_dropped(dropped);
        dropped
    }

    /// Counts lines of this chat dropped elsewhere, for the next summary.
    pub(super) const fn note_dropped(&mut self, count: u64) {
        self.dropped = self.dropped.saturating_add(count);
    }

    /// Waiting lines.
    pub(super) fn queued(&self) -> usize {
        self.lines.len()
    }

    /// Drops every waiting line and the summary; answers how many lines there were.
    pub(super) fn clear(&mut self) -> u64 {
        let count = u64::try_from(self.lines.len()).unwrap_or(u64::MAX);
        self.lines.clear();
        self.summary = None;
        count
    }

    /// The earliest instant the rate limits allow the next message.
    pub(super) fn rate_due(&self, timings: &Timings) -> Option<Instant> {
        let spacing = self.last_sent.map(|sent| later(sent, timings.rate_spacing));
        let burst = self
            .recent
            .len()
            .checked_sub(BURST)
            .and_then(|index| self.recent.get(index))
            .map(|start| later(*start, timings.rate_window));
        spacing.max(burst)
    }

    /// When the next message of queued lines is due, or `None` with nothing waiting.
    ///
    /// The first line after a quiet merge window goes at once; a line that arrived
    /// within the window after a send waits for the window's end; a line that was
    /// already waiting when the latest send started (queued at or before its start) (it did not fit) waits only for the
    /// rate limits. `flushing` ignores merge windows.
    pub(super) fn due(&self, timings: &Timings, flushing: bool) -> Option<Instant> {
        let arrived = match (self.lines.front(), &self.summary) {
            (Some(line), _) => line.queued,
            (None, Some((_, made))) => *made,
            (None, None) => return None,
        };
        let merged = match self.last_sent {
            Some(sent) if !flushing && arrived > sent => {
                arrived.max(later(sent, timings.merge_window))
            }
            Some(_) | None => arrived,
        };
        Some(
            self.rate_due(timings)
                .map_or(merged, |rate| rate.max(merged)),
        )
    }

    /// Drops lines older than [`Timings::max_age`] (answered as the count) and takes
    /// the next message: the summary, then as many lines as fit, joined by newlines.
    pub(super) fn take(&mut self, now: Instant, timings: &Timings) -> (Option<Batch>, u64) {
        let before = self.lines.len();
        self.lines
            .retain(|line| now.saturating_duration_since(line.at) < timings.max_age);
        let expired = u64::try_from(before.saturating_sub(self.lines.len())).unwrap_or(u64::MAX);
        self.note_dropped(expired);
        let summary = self.summary.take();
        let mut text = summary
            .as_ref()
            .map_or_else(String::new, |(line, _)| line.clone());
        let mut lines = Vec::new();
        while let Some(line) = self.lines.front() {
            let joined = if text.is_empty() {
                line.text.clone()
            } else {
                format!("{text}\n{}", line.text)
            };
            if !fits(&joined) && (!lines.is_empty() || summary.is_some()) {
                break;
            }
            text = fit(&joined);
            if let Some(taken) = self.lines.pop_front() {
                lines.push(taken);
            }
        }
        if text.is_empty() {
            return (None, expired);
        }
        let batch = Batch {
            lines,
            summary,
            text,
        };
        (Some(batch), expired)
    }

    /// Puts a batch that was not delivered back at the front, in its order.
    pub(super) fn restore(&mut self, batch: Batch) {
        for line in batch.lines.into_iter().rev() {
            self.lines.push_front(line);
        }
        if batch.summary.is_some() {
            self.summary = batch.summary;
        }
    }

    /// Records the start of a send for the merge window and the rate limits.
    pub(super) fn started(&mut self, now: Instant, timings: &Timings) {
        self.last_sent = Some(now);
        while self
            .recent
            .front()
            .is_some_and(|start| later(*start, timings.rate_window) <= now)
        {
            let _outside: Option<Instant> = self.recent.pop_front();
        }
        self.recent.push_back(now);
    }

    /// After a delivered message: with lines dropped before it, the next message opens
    /// with `summary(count)`.
    pub(super) fn delivered<F>(&mut self, now: Instant, summary: F)
    where
        F: FnOnce(u64) -> String,
    {
        if self.dropped > 0 {
            self.summary = Some((summary(self.dropped), now));
            self.dropped = 0;
        }
    }
}

#[cfg(test)]
mod tests;
