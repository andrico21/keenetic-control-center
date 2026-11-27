//! Collapsed warnings carry the count of the lines left out before them.

#![expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]

use alloc::sync::Arc;
use core::time::Duration;
use std::{
    io,
    sync::{Mutex, PoisonError},
    time::Instant,
};

use reqwest::Method;
use tracing::{Level, subscriber::with_default};
use tracing_subscriber::fmt::MakeWriter;

use super::Journal;
use crate::{RciError, TransportCause};

/// Everything the subscriber writes.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
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

impl MakeWriter<'_> for Captured {
    type Writer = Self;

    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

/// Runs `body` under a TRACE subscriber and returns the lines written at WARN.
fn warnings(body: impl FnOnce()) -> Vec<String> {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(Level::TRACE)
        .with_writer(captured.clone())
        .finish();
    with_default(subscriber, body);
    let text = String::from_utf8_lossy(&captured.0.lock().unwrap_or_else(PoisonError::into_inner))
        .into_owned();
    text.lines()
        .filter(|line| line.contains(" WARN "))
        .map(str::to_owned)
        .collect()
}

/// Identical failures within a minute log once; the next one after it says how many were
/// left out, and a missing resource never warns.
#[test]
fn identical_failures_collapse_and_the_next_line_counts_them() {
    let journal = Journal::new("router-1".to_owned());
    let label = journal.label(&Method::GET, "/rci/show/system");
    let refused = RciError::Transport(TransportCause::ConnectRefused);
    let start = Instant::now();
    let later = |seconds| {
        start
            .checked_add(Duration::from_secs(seconds))
            .unwrap_or(start)
    };

    let lines = warnings(|| {
        journal.failed_at(&label, Duration::from_millis(3), &refused, start);
        journal.failed_at(&label, Duration::from_millis(3), &refused, later(10));
        journal.failed_at(&label, Duration::from_millis(3), &refused, later(20));
        journal.failed_at(
            &label,
            Duration::from_millis(3),
            &RciError::NotFound,
            later(30),
        );
        journal.failed_at(&label, Duration::from_millis(3), &refused, later(61));
    });

    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines
            .first()
            .is_some_and(|line| !line.contains("suppressed")),
        "{lines:?}"
    );
    assert!(
        lines
            .get(1)
            .is_some_and(|line| line.contains("suppressed=2")
                && line.contains("cause=connect_refused")
                && line.contains("router=router-1")),
        "{lines:?}"
    );
}
