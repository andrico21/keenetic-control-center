//! Typed router log records.

use chrono::{DateTime, FixedOffset};

/// One parsed router log record.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct LogRecord {
    /// Router profile id.
    pub router: String,
    /// Router-assigned numeric record id.
    pub id: u64,
    /// Timestamp interpreted in the router timezone.
    pub ts: DateTime<FixedOffset>,
    /// Normalized severity label.
    pub level: String,
    /// Original short router severity label.
    pub label: Option<String>,
    /// Process name parsed from `process[pid]:`.
    pub process: Option<String>,
    /// Process id parsed from `process[pid]:`.
    pub pid: Option<u32>,
    /// Component prefix parsed from `Component::Sub:`.
    pub component: Option<String>,
    /// Message text with continuation lines merged.
    pub message: String,
}

impl LogRecord {
    /// Creates a record from the required router fields.
    #[inline]
    #[must_use]
    pub const fn new(
        router: String,
        id: u64,
        ts: DateTime<FixedOffset>,
        level: String,
        message: String,
    ) -> Self {
        Self {
            router,
            id,
            ts,
            level,
            label: None,
            process: None,
            pid: None,
            component: None,
            message,
        }
    }

    /// Attaches process identity parsed from a router prefix.
    #[inline]
    #[must_use]
    pub fn with_process(mut self, process: String, pid: u32) -> Self {
        self.process = Some(process);
        self.pid = Some(pid);
        self
    }
}
