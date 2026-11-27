//! The one admission path of every router request: a budget permit, then an outcome report.

use reqwest::Method;
use tokio::{
    sync::{Semaphore, SemaphorePermit},
    time,
};

use crate::{
    LocalCause, RciError, TransportCause,
    observe::{RciObserver, RequestOutcome},
    session::journal::Journal,
};

/// One admitted router request: it holds a permit of the router budget until its outcome is
/// reported.
pub(crate) struct Admission<'budget> {
    /// Released when the outcome is reported, or when the request is dropped.
    _permit: SemaphorePermit<'budget>,
    /// Receives the outcome.
    observer: Option<&'budget dyn RciObserver>,
    /// When the permit was granted.
    started: time::Instant,
}

impl<'budget> Admission<'budget> {
    /// Waits for one permit of `semaphore`.
    ///
    /// # Errors
    /// Returns [`RciError::Transport`] when the budget is closed.
    // cancel-safe: a cancelled wait holds no permit.
    pub(crate) async fn take(
        semaphore: &'budget Semaphore,
        observer: Option<&'budget dyn RciObserver>,
    ) -> Result<Self, RciError> {
        let permit = semaphore
            .acquire()
            .await
            .map_err(|_closed| RciError::Transport(TransportCause::Local(LocalCause::Budget)))?;
        Ok(Self {
            _permit: permit,
            observer,
            started: time::Instant::now(),
        })
    }

    /// Reports the request's outcome and duration, releases the permit and passes `result`
    /// through.
    ///
    /// # Errors
    /// Returns `result`'s own error.
    pub(crate) fn report<T>(self, result: Result<T, RciError>) -> Result<T, RciError> {
        if let Some(observer) = self.observer {
            observer.request(RequestOutcome::of(&result), self.started.elapsed());
        }
        result
    }

    /// Reports like [`Self::report`], and logs a failure of the request to `target` by
    /// `method` to `journal`.
    ///
    /// # Errors
    /// Returns `result`'s own error.
    pub(crate) fn report_logged<T>(
        self,
        (journal, method, target): (&Journal, &Method, &str),
        result: Result<T, RciError>,
    ) -> Result<T, RciError> {
        if let Err(error) = &result {
            journal.failed(
                &journal.label(method, target),
                self.started.elapsed(),
                error,
            );
        }
        self.report(result)
    }
}
