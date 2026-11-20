//! The outbox's delivery state, without I/O.
//!
//! Per-chat queues, test messages, holds after failures and drop counts, over the
//! settings and refusals of [`Access`]. The task does the requests and the state-file
//! writes this state asks for.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use kcc_app::notify_store::{
    DisabledReason, NotifyRuntime,
    recipients::{Chat, ChatId},
};
use secrecy::SecretString;
use tokio::time::Instant;

use super::{
    Cargo, Record, Reply, Settings, Test,
    access::Access,
    books::{Holds, Tally, Tests},
};
use crate::{
    metrics::instrumentation::SelfMetrics,
    notify::{
        bot::{Outgoing, Sent},
        delivery::{
            Line, OutboxConfig, OutboxStatus, Timings,
            pacing::{Batch, ChatQueue},
        },
        failure::SendError,
    },
};

/// Delivery state.
pub(super) struct Delivery {
    /// Timing rules.
    timings: Timings,
    /// Drop and message counts.
    tally: Tally,
    /// Waits after failures.
    holds: Holds,
    /// Settings and refusals.
    access: Access,
    /// Per chat: its queue and send history.
    queues: BTreeMap<ChatId, ChatQueue>,
    /// Test messages, oldest first.
    tests: Tests,
    /// Ignore merge windows until idle.
    flushing: bool,
}

impl Delivery {
    /// Unconfigured state: nothing is sent.
    pub(super) fn new(timings: Timings, metrics: Option<Arc<SelfMetrics>>) -> Self {
        Self {
            holds: Holds::new(&timings),
            timings,
            tally: Tally::new(metrics),
            access: Access::default(),
            queues: BTreeMap::new(),
            tests: Tests::default(),
            flushing: false,
        }
    }

    /// The status, given whether a message is in flight; ends a flush once idle.
    pub(super) fn status(&mut self, sending: bool) -> OutboxStatus {
        let queued = self.queues.values().map(ChatQueue::queued).sum();
        if queued == 0 && !sending && self.tests.is_empty() {
            self.flushing = false;
        }
        OutboxStatus {
            token_rejected: self.access.token_rejected(),
            disabled_chats: self.access.disabled(),
            queued,
            dropped: self.tally.dropped(),
            sending,
        }
    }

    /// Ignores merge windows until idle.
    pub(super) const fn flush(&mut self) {
        self.flushing = true;
    }

    /// Whether these settings end a token refusal (another token while refused).
    pub(super) fn ends_refusal(&self, settings: &Settings) -> bool {
        self.access.token_rejected() && self.access.token_changed(settings)
    }

    /// Applies new settings; drops the queues of chats that no longer receive. Answers
    /// the chats still listed.
    pub(super) fn configure(
        &mut self,
        settings: Settings,
        runtime: &NotifyRuntime,
    ) -> BTreeSet<ChatId> {
        let listed = self.access.configure(settings, runtime);
        let access = &self.access;
        self.queues.retain(|chat, _| access.receives(chat));
        listed
    }

    /// Fans a line out to every chat that receives; while the token is refused the
    /// copies are dropped and counted.
    pub(super) fn push(&mut self, line: &Line, now: Instant) {
        if !self.access.accepting() {
            return;
        }
        let (mut shed, mut refused) = (0_u64, 0_u64);
        for chat in self.access.chats() {
            let queue = self.queues.entry(chat.id.clone()).or_default();
            if self.access.token_rejected() {
                queue.note_dropped(1);
                refused = refused.saturating_add(1);
            } else {
                shed = shed.saturating_add(queue.push(line.text.clone(), line.at, now));
            }
        }
        self.tally.drop_lines("queue_full", shed);
        self.tally.drop_lines("token_rejected", refused);
    }

    /// Queues a test message, or answers at once when it cannot be sent.
    pub(super) fn test(&mut self, chat: Chat, text: String, reply: Reply) {
        match self.access.refusal(&chat.id) {
            Some(error) => {
                let _unheard: Result<(), Result<(), SendError>> = reply.send(Err(error));
            }
            None => self.tests.push(Test { chat, text, reply }),
        }
    }

    /// Answers every waiting test message: the outbox stopped.
    pub(super) fn stop(&mut self) {
        self.tests.answer_all(SendError::Stopped);
    }

    /// The earliest due message: its instant and chat, `None` as the chat for a test
    /// message (which goes first on a tie).
    pub(super) fn next(&self, now: Instant) -> Option<(Instant, Option<ChatId>)> {
        let test = self.tests.front_chat().map(|chat| {
            let rate = self
                .queues
                .get(chat)
                .and_then(|queue| queue.rate_due(&self.timings));
            (self.holds.test(rate).unwrap_or(now), None)
        });
        if !self.access.sending() {
            return test;
        }
        let lines = self
            .queues
            .iter()
            .filter_map(|(chat, queue)| {
                let due = queue.due(&self.timings, self.flushing)?;
                Some((self.holds.lines(due), Some(chat.clone())))
            })
            .min_by_key(|(due, _)| *due);
        match (test, lines) {
            (Some(first), Some(other)) if other.0 < first.0 => Some(other),
            (Some(first), _) => Some(first),
            (None, other) => other,
        }
    }

    /// Takes the message due at `now`, if any, and records its start: its chat, cargo,
    /// request and token.
    pub(super) fn start(
        &mut self,
        now: Instant,
    ) -> Option<(ChatId, Cargo, Outgoing, SecretString)> {
        let (due, chat) = self.next(now)?;
        if due > now {
            return None;
        }
        let token = self.access.token()?;
        let (target, text, cargo) = if let Some(id) = chat {
            let target = self.access.chat(&id)?.clone();
            let (next_batch, expired) = self.queues.get_mut(&id)?.take(now, &self.timings);
            self.tally.drop_lines("expired", expired);
            let batch = next_batch?;
            (target, batch.text().to_owned(), Cargo::Lines(batch))
        } else {
            let test = self.tests.pop()?;
            (test.chat, test.text, Cargo::Test(test.reply))
        };
        self.queues
            .entry(target.id.clone())
            .or_default()
            .started(now, &self.timings);
        let message = Outgoing::new(&target, &text);
        Some((target.id, cargo, message, token))
    }

    /// Applies the outcome of a message to `chat`; answers the state-file write it needs.
    pub(super) fn finish(
        &mut self,
        (chat, cargo): (ChatId, Cargo),
        result: Result<Sent, SendError>,
        (now, config): (Instant, &OutboxConfig),
    ) -> Record {
        let outcome = result.map(drop);
        let (lines, reply) = match cargo {
            Cargo::Lines(batch) => (Some(batch), None),
            Cargo::Test(reply) => (None, Some(reply)),
        };
        let record = match outcome {
            Ok(()) => {
                self.tally.message("sent");
                self.holds.delivered();
                if lines.is_some()
                    && let Some(queue) = self.queues.get_mut(&chat)
                {
                    queue.delivered(now, |count| config.summary(count));
                }
                Record::Nothing
            }
            Err(SendError::TokenRejected) => {
                self.tally.message("rejected");
                self.reject_token(lines.as_ref().map_or(0, Batch::len));
                Record::TokenRejected
            }
            Err(SendError::ChatUnavailable(reason)) => {
                self.tally.message("rejected");
                self.disable(&chat, reason, lines.as_ref().map_or(0, Batch::len));
                Record::Disabled(chat.clone(), reason)
            }
            Err(SendError::Rejected) => {
                self.tally.message("rejected");
                Record::Nothing
            }
            Err(failure) => {
                self.tally.message("failed");
                if let SendError::RetryAfter(wait) = failure {
                    self.holds.retry_after(now, wait);
                } else {
                    self.holds.transient(now);
                }
                if let (Some(batch), Some(queue)) = (lines, self.queues.get_mut(&chat)) {
                    queue.restore(batch);
                }
                Record::Nothing
            }
        };
        if let Some(answer) = reply {
            let _unheard: Result<(), Result<(), SendError>> = answer.send(outcome);
        }
        record
    }

    /// Stops all sending: every waiting line is dropped and counted.
    fn reject_token(&mut self, in_flight: usize) {
        self.access.reject_token();
        let mut count = u64::try_from(in_flight).unwrap_or(u64::MAX);
        for queue in self.queues.values_mut() {
            let cleared = queue.clear();
            queue.note_dropped(cleared);
            count = count.saturating_add(cleared);
        }
        self.tally.drop_lines("token_rejected", count);
        self.tests.answer_all(SendError::TokenRejected);
    }

    /// Disables `chat`: its waiting lines are dropped and counted.
    fn disable(&mut self, chat: &ChatId, reason: DisabledReason, in_flight: usize) {
        let cleared = self
            .queues
            .remove(chat)
            .map_or(0, |mut queue| queue.clear());
        let count = cleared.saturating_add(u64::try_from(in_flight).unwrap_or(u64::MAX));
        self.tally.drop_lines("chat_disabled", count);
        self.access.disable(chat.clone(), reason);
    }
}
