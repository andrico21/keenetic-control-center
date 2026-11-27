//! Dedicated background sessions under the parent router's admission budget.

use alloc::sync::Arc;
use core::{fmt, time::Duration};

use reqwest::Method;
use serde_json::Value;
use tokio::{runtime, sync::Semaphore, time};
use tokio_util::sync::CancellationToken;

use super::{
    RciBody, RciClient, admit::Admission, decode_response, missing_pointer, response_json, session,
};
use crate::{
    RciError, RciPath, encode_query,
    observe::RciObserver,
    session::{Manager, RequestKind, journal::Journal},
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

/// Starts a process with a dedicated cookie but the same router admission budget.
///
/// # Errors
/// Returns policy, authentication, transport or response errors.
// NOT cancel-safe: a transmitted POST may start work without returning its identifier.
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
    let process_id = Admission::take(&client.semaphore, client.options.observer.as_deref())
        .await?
        .report_logged(
            (&client.journal, &Method::POST, &target),
            async {
                let response = session.0.post(&target, body).await?;
                let value = response_json(response, client.options.response_bytes).await?;
                Ok(value
                    .pointer("/process/id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| missing_pointer("background command", "/process/id"))?
                    .to_owned())
            }
            .await,
        )?;
    Ok(Handle {
        session,
        semaphore: Arc::clone(&client.semaphore),
        observer: client.options.observer.clone(),
        journal: Arc::clone(&client.journal),
        path,
        process_id,
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
    /// Router process identifier.
    process_id: String,
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
            .field("process_id", &self.process_id)
            .field("poll_interval", &self.poll_interval)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl Handle {
    /// Reads the next response without waiting for process completion.
    ///
    /// # Errors
    /// Returns authentication, transport, HTTP, size or response errors.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, dropping the future releases its permit and partial local
    // response.
    #[inline]
    pub async fn next(&self) -> Result<RciBody, RciError> {
        let path = process_path(&self.path, &self.process_id)?;
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

    /// Polls to completion, sending DELETE on token cancellation or deadline expiry, then
    /// signs the dedicated session out whatever the outcome.
    ///
    /// # Errors
    /// Returns [`RciError::Cancelled`] when the token fires, [`RciError::Timeout`] when the
    /// deadline passes, and cleanup, request or response errors otherwise.
    // NOT cancel-safe: token cancellation sends DELETE; dropping the future instead leaves the
    // sign-out to the handle's drop.
    #[inline]
    pub async fn poll(&self, token: &CancellationToken) -> Result<RciBody, RciError> {
        let operation = async {
            loop {
                let decoded = self.next().await?;
                let continued = match &decoded {
                    RciBody::Json(json) => json
                        .value
                        .get("continued")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    RciBody::Text(_) => false,
                };
                if !continued {
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

    /// Stops the remote process with DELETE.
    ///
    /// # Errors
    /// Returns request or response errors.
    // NOT cancel-safe: cancellation after transmission may leave an uncertain stop result.
    #[inline]
    pub async fn stop(&self) -> Result<RciBody, RciError> {
        let path = process_path(&self.path, &self.process_id)?;
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
