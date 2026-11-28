//! Dedicated background sessions under the parent router's admission budget.
//!
//! A router continues a background command in one of two ways. One answers the POST with a
//! process id; `GET ?id=` then reads on and `DELETE ?id=` stops the process. KN-1811 on
//! 5.1.10 instead answers the POST with the first output chunk marked `continued: true`;
//! each `GET` of the same resource without a query in the same session reads the next
//! chunk, the last has no `continued`, a second POST would restart the command, and
//! signing the session out ends it.

use alloc::sync::Arc;
use core::{fmt, time::Duration};
use std::sync::Mutex;

use reqwest::Method;
use serde_json::{Map, Value};
use tokio::{runtime, sync::Semaphore, time};
use tokio_util::sync::CancellationToken;

use super::{RciBody, RciClient, admit::Admission, decode_response, missing_pointer, session};
use crate::{
    RciError, RciPath, RciResponse, encode_query,
    observe::RciObserver,
    session::{Manager, RequestKind, journal::Journal, lock},
};

/// Longest wait for the router to acknowledge the sign-out of a dedicated session.
const LOGOUT_BOUND: Duration = Duration::from_secs(5);

/// A dedicated session that signs itself out of the router when it is dropped.
struct Dedicated(Arc<Manager>);

impl Dedicated {
    /// Signs out now, within [`LOGOUT_BOUND`]; a router that stays silent is left to expire
    /// the cookie.
    // NOT cancel-safe: dropped after the sign-out is sent, the router may keep the session, an
    // orphaned router session; the local cookie is cleared before the wire operation, so
    // `Drop` has nothing to repeat.
    async fn release(&self) {
        drop(time::timeout(LOGOUT_BOUND, self.0.logout()).await);
    }
}

impl Drop for Dedicated {
    fn drop(&mut self) {
        if !self.0.has_session() {
            return;
        }
        // Dropping cannot await: hand the sign-out to the runtime when there is one.
        if let Ok(runtime) = runtime::Handle::try_current() {
            let session = Arc::clone(&self.0);
            drop(runtime.spawn(async move {
                drop(time::timeout(LOGOUT_BOUND, session.logout()).await);
            }));
        }
    }
}

/// How the router continues one background command.
enum Continuation {
    /// The router answered this process id.
    Process(String),
    /// The router continues in the dedicated session; holds the POST answer, the first
    /// chunk, until the first read takes it.
    Session(Mutex<Option<Box<RciBody>>>),
}

impl Continuation {
    /// The continuation the POST `answer` starts: a process id when it has `/process/id`,
    /// otherwise the session's, with `answer` as its first chunk (a finished command when
    /// that chunk is not `continued`).
    ///
    /// # Errors
    /// Returns [`RciError::Decode`] (missing `/process/id`) for an answer that is no JSON
    /// object.
    fn of(answer: RciBody) -> Result<Self, RciError> {
        let RciBody::Json(response) = answer else {
            return Err(missing_pointer("background command", "/process/id"));
        };
        if !response.value.is_object() {
            return Err(missing_pointer("background command", "/process/id"));
        }
        let process_id = response
            .value
            .pointer("/process/id")
            .and_then(Value::as_str)
            .map(str::to_owned);
        Ok(process_id.map_or_else(
            || Self::Session(Mutex::new(Some(Box::new(RciBody::Json(response))))),
            Self::Process,
        ))
    }

    /// The router process id, when the router answered one.
    fn process_id(&self) -> Option<&str> {
        match self {
            Self::Process(id) => Some(id),
            Self::Session(_) => None,
        }
    }
}

/// Whether `answer` says more output follows.
fn continued(answer: &RciBody) -> bool {
    match answer {
        RciBody::Json(json) => json
            .value
            .get("continued")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        RciBody::Text(_) => false,
    }
}

/// Starts a background command with a dedicated cookie but the same router admission
/// budget, in the continuation its POST answer shows.
///
/// # Errors
/// Returns policy, authentication, transport, HTTP or router errors, and
/// [`RciError::Decode`] (missing `/process/id`) for an answer that is no JSON object.
// NOT cancel-safe: a transmitted POST may start work without returning its answer.
pub(super) async fn start(
    client: &RciClient,
    path: RciPath,
    body: &Value,
) -> Result<Handle, RciError> {
    let session = Dedicated(Arc::new(
        session(
            (&client.router, &client.pinned),
            &client.credentials,
            (&client.options, &client.journal),
        )?
        .with_key_cache(client.session.key_cache()),
    ));
    let target = format!("/rci/{path}");
    // The permit (the receiver) is taken before the request (the argument) runs.
    let answer = Admission::take(&client.semaphore, client.options.observer.as_deref())
        .await?
        .report_logged(
            (&client.journal, &Method::POST, &target),
            async {
                let response = session.0.post(&target, body).await?;
                decode_response(response, client.options.response_bytes).await
            }
            .await,
        )?;
    let continuation = Continuation::of(answer)?;
    Ok(Handle {
        session,
        semaphore: Arc::clone(&client.semaphore),
        observer: client.options.observer.clone(),
        journal: Arc::clone(&client.journal),
        path,
        continuation,
        response_bytes: client.options.response_bytes,
        poll_interval: Duration::from_secs(1),
        deadline: Duration::from_secs(300),
    })
}

/// A dedicated-session handle for one router background process.
#[non_exhaustive]
pub struct Handle {
    /// Session isolated from the main request engine.
    session: Dedicated,
    /// Router-wide admission shared with ordinary requests.
    semaphore: Arc<Semaphore>,
    /// The parent client's request and login observer.
    observer: Option<Arc<dyn RciObserver>>,
    /// The parent client's log identity and collapsed warnings.
    journal: Arc<Journal>,
    /// Process resource path.
    path: RciPath,
    /// How the router continues the command.
    continuation: Continuation,
    /// Response cap.
    response_bytes: usize,
    /// Delay between continued responses.
    poll_interval: Duration,
    /// Overall polling deadline.
    deadline: Duration,
}

impl fmt::Debug for Handle {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackgroundHandle")
            .field("path", &self.path)
            .field("process_id", &self.continuation.process_id())
            .field("poll_interval", &self.poll_interval)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl Handle {
    /// Reads the next answer without waiting for the command to finish.
    ///
    /// With a process id this is `GET ?id=`. When the router continues in the session the
    /// first call returns the POST answer without a request, and each later call is a `GET`
    /// of the resource without a query in the dedicated session.
    ///
    /// # Errors
    /// Returns authentication, transport, HTTP, size or response errors.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, dropping the future releases its permit and partial local
    // response; in the session continuation the chunk of a dropped `GET` is lost, as the router
    // has moved on. Taking the stored first chunk has no await point.
    #[inline]
    pub async fn next(&self) -> Result<RciBody, RciError> {
        let path = match &self.continuation {
            Continuation::Process(id) => process_path(&self.path, id)?,
            Continuation::Session(first) => {
                let stored = lock(first).take();
                if let Some(answer) = stored {
                    return Ok(*answer);
                }
                format!("/rci/{}", self.path)
            }
        };
        let admission = Admission::take(&self.semaphore, self.observer.as_deref()).await?;
        admission.report_logged(
            (&self.journal, &Method::GET, &path),
            async {
                let response = self.session.0.get(&path).await?;
                decode_response(response, self.response_bytes).await
            }
            .await,
        )
    }

    /// Overrides the default one-second poll interval.
    #[inline]
    #[must_use]
    pub const fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Overrides the default 300-second polling deadline.
    #[inline]
    #[must_use]
    pub const fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// Polls to completion and returns the first answer without `continued: true`, like
    /// [`Self::poll_each`] without looking at the answers before it.
    ///
    /// # Errors
    /// As [`Self::poll_each`].
    // NOT cancel-safe: as `poll_each`.
    #[inline]
    pub async fn poll(&self, token: &CancellationToken) -> Result<RciBody, RciError> {
        self.poll_each(token, |_chunk| {}).await
    }

    /// Polls to completion, handing every answer to `on_chunk` in order (when the router
    /// continues in the session, the POST answer first), and returns the first answer
    /// without `continued: true`.
    ///
    /// On token cancellation or deadline expiry it stops the command (see [`Self::stop`]);
    /// it signs the dedicated session out whatever the outcome.
    ///
    /// # Errors
    /// Returns [`RciError::Cancelled`] when the token fires, [`RciError::Timeout`] when the
    /// deadline passes, and cleanup, request or response errors otherwise.
    // NOT cancel-safe: token cancellation stops the command; dropping the future instead leaves
    // the sign-out to the handle's drop, and an answer read but not yet handed over is lost.
    #[inline]
    pub async fn poll_each<F>(
        &self,
        token: &CancellationToken,
        mut on_chunk: F,
    ) -> Result<RciBody, RciError>
    where
        F: FnMut(&RciBody),
    {
        let operation = async {
            loop {
                let decoded = self.next().await?;
                on_chunk(&decoded);
                if !continued(&decoded) {
                    return Ok(decoded);
                }
                time::sleep(self.poll_interval).await;
            }
        };
        let result = tokio::select! {
            () = token.cancelled() => Err(RciError::Cancelled),
            result = time::timeout(self.deadline, operation) => match result {
                Ok(value) => value,
                Err(_elapsed) => Err(RciError::Timeout),
            },
        };
        let stopped = if matches!(result, Err(RciError::Timeout | RciError::Cancelled)) {
            self.stop().await.map(drop)
        } else {
            Ok(())
        };
        self.session.release().await;
        stopped?;
        result
    }

    /// Stops the command: `DELETE ?id=` of a router process, or, when the router continues
    /// in the session, signing the dedicated session out (the router ends a session's
    /// command with it), which answers an empty JSON object.
    ///
    /// # Errors
    /// Returns request or response errors of the `DELETE`.
    // NOT cancel-safe: cancellation after transmission may leave an uncertain stop result; the
    // sign-out clears the local cookie before its request, so the handle's drop has nothing to
    // repeat.
    #[inline]
    pub async fn stop(&self) -> Result<RciBody, RciError> {
        let Some(process_id) = self.continuation.process_id() else {
            let admission = Admission::take(&self.semaphore, self.observer.as_deref()).await?;
            self.session.release().await;
            return admission
                .report(RciResponse::from_value(Value::Object(Map::new())).map(RciBody::Json));
        };
        let path = process_path(&self.path, process_id)?;
        let admission = Admission::take(&self.semaphore, self.observer.as_deref()).await?;
        admission.report_logged(
            (&self.journal, &Method::DELETE, &path),
            async {
                let response = self
                    .session
                    .0
                    .request::<()>(Method::DELETE, &path, None, RequestKind::NonRetryable)
                    .await?;
                decode_response(response, self.response_bytes).await
            }
            .await,
        )
    }
}

/// The request path of one process; the router-supplied id is a query value, never syntax.
///
/// # Errors
/// Returns validation errors when the query cannot be serialized.
fn process_path(path: &RciPath, process_id: &str) -> Result<String, RciError> {
    let query = encode_query(&[("id", process_id)])?;
    Ok(format!("/rci/{path}?{query}"))
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions are not rendered API documentation"
)]
mod tests {
    use super::{RciPath, process_path};

    /// A-07: a hostile process id stays one query value.
    #[test]
    fn a_hostile_process_id_stays_one_query_value() -> Result<(), crate::RciError> {
        let path = RciPath::from_segments(["tools", "ping"])
            .map_err(|_error| crate::RciError::Validation)?;

        assert_eq!(
            process_path(&path, "7&admin=1#x y")?,
            "/rci/tools/ping?id=7%26admin%3D1%23x+y"
        );
        Ok(())
    }
}
