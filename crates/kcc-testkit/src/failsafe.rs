//! Documented fail-safe timer state machine for the simulator.

use core::time::Duration;

use serde_json::{Value, json};

/// Armed fail-safe timer state.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct FailSafe {
    /// Configured full timer period.
    period: Option<Duration>,
    /// Monotonic time at which rollback occurs.
    deadline: Option<Duration>,
}

/// Armed scheduled-reboot timer state.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ScheduledReboot {
    /// Monotonic time at which reboot occurs.
    deadline: Option<Duration>,
}

impl FailSafe {
    /// Arms or re-arms the reboot timer.
    pub(crate) fn arm(&mut self, now: Duration, seconds: u64) -> bool {
        if !(60..=86_400).contains(&seconds) {
            return false;
        }
        let period = Duration::from_secs(seconds);
        self.period = Some(period);
        self.deadline = Some(now.saturating_add(period));
        true
    }

    /// Restarts an armed timer.
    pub(crate) const fn keep_alive(&mut self, now: Duration) -> bool {
        let Some(period) = self.period else {
            return false;
        };
        self.deadline = Some(now.saturating_add(period));
        true
    }

    /// Disarms the timer.
    pub(crate) const fn disarm(&mut self) {
        self.period = None;
        self.deadline = None;
    }

    /// Whether an armed timer has expired.
    pub(crate) fn take_expired(&mut self, now: Duration) -> bool {
        if self.deadline.is_some_and(|deadline| now >= deadline) {
            self.disarm();
            true
        } else {
            false
        }
    }

    /// RCI fail-safe object exposed by `show last-change`.
    pub(crate) fn as_json(self, now: Duration) -> Value {
        let remaining = self
            .deadline
            .map_or(0, |deadline| deadline.saturating_sub(now).as_secs());
        json!({
            "active": self.deadline.is_some(),
            "mode": self.deadline.map(|_| "reboot"),
            "timeout": self.period.map(|period| period.as_secs()),
            "remaining": remaining,
        })
    }
}

impl ScheduledReboot {
    /// Whether a scheduled recovery reboot remains pending.
    pub(crate) const fn active(&self) -> bool {
        self.deadline.is_some()
    }
    /// Arms or re-arms the reboot timer.
    pub(crate) const fn arm(&mut self, now: Duration, seconds: u64) -> bool {
        if seconds == 0 {
            return false;
        }
        self.deadline = Some(now.saturating_add(Duration::from_secs(seconds)));
        true
    }

    /// Disarms the timer.
    pub(crate) const fn disarm(&mut self) {
        self.deadline = None;
    }

    /// Whether an armed timer has expired.
    pub(crate) fn take_expired(&mut self, now: Duration) -> bool {
        if self.deadline.is_some_and(|deadline| now >= deadline) {
            self.disarm();
            true
        } else {
            false
        }
    }
}
