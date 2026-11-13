//! Web requests the server owns while they hold a router's fail-safe bracket.
//!
//! A management change arms the router's fail-safe timer, does its work, disarms the
//! timer and reports. Once the arm is sent, only the request's own end may stop it: not
//! the request budget, not a dropped connection, not the server shutting down, or the
//! router restores its saved configuration minutes later with nobody told.
//!
//! - `own`, the outermost layer, runs every request as a task the server owns. When
//!   the connection stops waiting, the task is aborted unless it holds a bracket.
//! - `hold` is called by the change workflow right before it arms: it holds the
//!   request, or refuses when the request has no owner or was already cancelled.
//! - `budget` answers 408 at [`REQUEST_TIMEOUT`] only for a request that holds no
//!   bracket; a request that holds one is answered when it ends.
//!
//! The bracket itself enters the process-wide count of open brackets
//! ([`kcc_app::brackets::Brackets`], owned by the change workflow), so `kcc serve` can wait
//! for it before it exits.

use alloc::sync::Arc;
use core::{
    pin::pin,
    sync::atomic::{AtomicU8, Ordering},
};
use std::panic;

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse as _, Response},
};
use tokio::{task::AbortHandle, time::timeout};

use crate::REQUEST_TIMEOUT;

#[cfg(test)]
mod tests;

/// A request that holds no bracket and may still be cancelled.
const OPEN: u8 = 0;
/// A request that armed, or is about to arm, a fail-safe timer: it runs until it ends.
const HELD: u8 = 1;
/// A request that ended or was cancelled before it armed: it may not arm any more.
const ENDED: u8 = 2;

tokio::task_local! {
    /// The claim of the request the current task serves.
    static CLAIM: Arc<Claim>;
}

/// Whether one request holds a bracket.
#[derive(Debug)]
struct Claim {
    /// [`OPEN`], [`HELD`] or [`ENDED`].
    state: AtomicU8,
}

impl Claim {
    /// Holds the request; false once it ended or was cancelled.
    fn hold(&self) -> bool {
        match self
            .state
            .compare_exchange(OPEN, HELD, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_open) => true,
            Err(current) => current == HELD,
        }
    }

    /// Ends the request unless it holds a bracket; whether it may be cancelled.
    fn cancel(&self) -> bool {
        match self
            .state
            .compare_exchange(OPEN, ENDED, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_open) => true,
            Err(current) => current == ENDED,
        }
    }

    /// Ends the request.
    fn end(&self) {
        let _: u8 = self.state.swap(ENDED, Ordering::AcqRel);
    }
}

/// Ends the claim when the request's task ends, however it ends.
struct Ending(Arc<Claim>);

impl Drop for Ending {
    fn drop(&mut self) {
        self.0.end();
    }
}

/// Aborts the request's task when nobody waits for it any more, unless it holds a
/// bracket.
struct Abandon {
    /// The request's claim.
    claim: Arc<Claim>,
    /// Its task.
    task: AbortHandle,
}

impl Drop for Abandon {
    fn drop(&mut self) {
        if self.claim.cancel() {
            self.task.abort();
        }
    }
}

/// Runs the request as a task the server owns.
// NOT cancel-safe by design: dropped before the request holds a bracket, the task is
// aborted as the request would have been; dropped after, the task runs to its end.
pub(crate) async fn own(request: Request, next: Next) -> Response {
    let claim = Arc::new(Claim {
        state: AtomicU8::new(OPEN),
    });
    let ending = Ending(Arc::clone(&claim));
    let task = tokio::spawn(CLAIM.scope(Arc::clone(&claim), async move {
        let _ending = ending;
        next.run(request).await
    }));
    let _abandon = Abandon {
        claim,
        task: task.abort_handle(),
    };
    match task.await {
        Ok(response) => response,
        Err(error) if error.is_panic() => panic::resume_unwind(error.into_panic()),
        Err(_cancelled) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

/// The request budget: a request that holds no bracket is answered 408 after
/// [`REQUEST_TIMEOUT`]; one that holds a bracket is answered when it ends.
// NOT cancel-safe: see `own`.
pub(crate) async fn budget(request: Request, next: Next) -> Response {
    let mut answer = pin!(next.run(request));
    if let Ok(response) = timeout(REQUEST_TIMEOUT, answer.as_mut()).await {
        return response;
    }
    if CLAIM.try_with(|claim| claim.cancel()).unwrap_or(true) {
        return StatusCode::REQUEST_TIMEOUT.into_response();
    }
    answer.await
}

/// Holds the current request for a bracket about to arm a router's fail-safe timer.
///
/// A held request is no longer cancelled. False when the request has no owner or was
/// already cancelled; nothing may be armed then.
pub(crate) fn hold() -> bool {
    CLAIM.try_with(|claim| claim.hold()).unwrap_or(false)
}
