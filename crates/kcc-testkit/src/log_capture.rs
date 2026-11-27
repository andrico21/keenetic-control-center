//! Captures the tracing output of the current thread for a test.
//!
//! [`start`] installs a thread-local subscriber at TRACE and returns the buffer it writes
//! to; events of tasks on other threads are not captured, so use it with a current-thread
//! runtime.

use alloc::sync::Arc;
use std::{
    io,
    sync::{Mutex, OnceLock, PoisonError},
};

use tracing::{
    Dispatch, Level,
    subscriber::{DefaultGuard, NoSubscriber, set_default},
};
use tracing_subscriber::fmt::MakeWriter;

/// Two dispatchers that live as long as the process.
///
/// With at most one dispatcher alive, tracing decides a callsite's interest from the
/// dispatcher of the thread that reaches it first, and a thread without one disables the
/// callsite for every test; with two or more it asks every live dispatcher.
static PERMANENT: OnceLock<[Dispatch; 2]> = OnceLock::new();

/// Everything the subscriber wrote.
#[derive(Clone, Debug, Default)]
pub struct Captured(Arc<Mutex<Vec<u8>>>);

/// Starts capturing every event of this thread at TRACE until the guard drops.
#[inline]
#[must_use]
pub fn start() -> (Captured, DefaultGuard) {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(Level::TRACE)
        .with_writer(captured.clone())
        .finish();
    let _permanent: &[Dispatch; 2] = PERMANENT.get_or_init(|| {
        [
            Dispatch::new(NoSubscriber::default()),
            Dispatch::new(NoSubscriber::default()),
        ]
    });
    (captured, set_default(subscriber))
}

impl Captured {
    /// The text written so far.
    #[inline]
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
    }

    /// The lines written so far at `level` (`DEBUG`, `WARN`, ...).
    #[inline]
    #[must_use]
    pub fn lines_at(&self, level: &str) -> Vec<String> {
        let marker = format!(" {level} ");
        self.text()
            .lines()
            .filter(|line| line.contains(&marker))
            .map(str::to_owned)
            .collect()
    }
}

impl io::Write for Captured {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl MakeWriter<'_> for Captured {
    type Writer = Self;

    #[inline]
    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}
