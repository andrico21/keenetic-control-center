//! The outbox's bookkeeping: waits after failures, drop and message counts, and the
//! test messages waiting for their turn.

use alloc::{collections::VecDeque, sync::Arc};
use core::time::Duration;

use kcc_app::notify_store::recipients::ChatId;
use tokio::time::Instant;

use super::Test;
use crate::{
    metrics::instrumentation::SelfMetrics,
    notify::{
        delivery::{Timings, pacing::later},
        failure::SendError,
    },
};

/// Waits imposed by failures: a 429 holds every request, transient failures hold queued
/// messages with a doubling backoff.
#[derive(Debug)]
pub(super) struct Holds {
    /// First backoff.
    base: Duration,
    /// Longest backoff.
    cap: Duration,
    /// The next backoff.
    next: Duration,
    /// No request before this (429).
    retry_until: Option<Instant>,
    /// No queued message before this (transient failures).
    backoff_until: Option<Instant>,
}

impl Holds {
    /// No holds yet.
    pub(super) const fn new(timings: &Timings) -> Self {
        Self {
            base: timings.backoff_base,
            cap: timings.backoff_cap,
            next: timings.backoff_base,
            retry_until: None,
            backoff_until: None,
        }
    }

    /// When a test message due at `due` may go.
    pub(super) fn test(&self, due: Option<Instant>) -> Option<Instant> {
        due.max(self.retry_until)
    }

    /// When queued lines due at `due` may go.
    pub(super) fn lines(&self, due: Instant) -> Instant {
        due.max(self.retry_until.unwrap_or(due))
            .max(self.backoff_until.unwrap_or(due))
    }

    /// After a delivery: the backoff starts over.
    pub(super) const fn delivered(&mut self) {
        self.next = self.base;
        self.backoff_until = None;
    }

    /// After a 429 asking to wait `wait`.
    pub(super) fn retry_after(&mut self, now: Instant, wait: Duration) {
        self.retry_until = Some(later(now, wait));
    }

    /// After a transient failure: wait the current backoff and double the next.
    pub(super) fn transient(&mut self, now: Instant) {
        self.backoff_until = Some(later(now, self.next));
        self.next = self.next.saturating_mul(2).min(self.cap);
    }
}

/// Drop and message counts, mirrored into the self-metrics.
#[derive(Debug)]
pub(super) struct Tally {
    /// Self-metrics.
    metrics: Option<Arc<SelfMetrics>>,
    /// Line copies dropped since the start.
    dropped: u64,
}

impl Tally {
    /// Nothing counted yet.
    pub(super) const fn new(metrics: Option<Arc<SelfMetrics>>) -> Self {
        Self {
            metrics,
            dropped: 0,
        }
    }

    /// Line copies dropped since the start.
    pub(super) const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Counts `count` line copies dropped for `reason`.
    pub(super) fn drop_lines(&mut self, reason: &str, count: u64) {
        if count == 0 {
            return;
        }
        self.dropped = self.dropped.saturating_add(count);
        if let Some(metrics) = &self.metrics {
            metrics.notify_dropped(reason, count);
        }
    }

    /// Counts one finished message: `sent`, `rejected` or `failed`.
    pub(super) fn message(&self, result: &str) {
        if let Some(metrics) = &self.metrics {
            metrics.notify_message(result);
        }
    }
}

/// Test messages waiting for their chat's rate limit, oldest first.
#[derive(Default)]
pub(super) struct Tests(VecDeque<Test>);

impl Tests {
    /// Queues a test message.
    pub(super) fn push(&mut self, test: Test) {
        self.0.push_back(test);
    }

    /// Whether none is waiting.
    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The chat of the oldest one.
    pub(super) fn front_chat(&self) -> Option<&ChatId> {
        self.0.front().map(|test| &test.chat.id)
    }

    /// Takes the oldest one.
    pub(super) fn pop(&mut self) -> Option<Test> {
        self.0.pop_front()
    }

    /// Answers every waiting one with `error`.
    pub(super) fn answer_all(&mut self, error: SendError) {
        for test in self.0.drain(..) {
            let _unheard: Result<(), Result<(), SendError>> = test.reply.send(Err(error));
        }
    }
}
