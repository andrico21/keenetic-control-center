//! Dedicated background sessions under the parent router's admission budget.

use alloc::sync::Arc;
use core::{fmt, time::Duration};

use reqwest::Method;
use serde_json::Value;
use tokio::{runtime, sync::Semaphore, time};
use tokio_util::sync::CancellationToken;

use super::{RciBody, RciClient, decode_response, response_json, session};
use crate::{
    RciError, RciPath, encode_query,
    session::{Manager, RequestKind},
};

/// Longest wait for the router to acknowledge the sign-out of a dedicated session.
const LOGOUT_BOUND: Duration = Duration::from_secs(5);

/// A dedicated session that signs itself out of the router when it is dropped.
struct Dedicated(Arc<Manager>);

impl Dedicated {
    /// Signs out now, within [`LOGOUT_BOUND`]; a router that stays silent is left to expire
    /// the cookie.
    // cancel-safe: the local cookie is cleared before the wire operation, so a cancelled
    // sign-out leaves nothing for `Drop` to repeat.
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
            &client.options,
        )?
        .with_key_cache(client.session.key_cache()),
    ));
    let _permit = client
        .semaphore
        .acquire()
        .await
        .map_err(|_closed| RciError::Transport)?;
    let response = session.0.post(&format!("/rci/{path}"), body).await?;
    let value = response_json(response, client.options.response_bytes).await?;
    let process_id = value
        .pointer("/process/id")
        .and_then(Value::as_str)
        .ok_or(RciError::Decode)?
        .to_owned();
    Ok(Handle {
        session,
        semaphore: Arc::clone(&client.semaphore),
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
    // cancel-safe: dropping the future releases its permit and partial local response.
    #[inline]
    pub async fn next(&self) -> Result<RciBody, RciError> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_closed| RciError::Transport)?;
        let path = process_path(&self.path, &self.process_id)?;
        let response = self.session.0.get(&path).await?;
        decode_response(response, self.response_bytes).await
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
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_closed| RciError::Transport)?;
        let path = process_path(&self.path, &self.process_id)?;
        let response = self
            .session
            .0
            .request::<()>(Method::DELETE, &path, None, RequestKind::NonRetryable)
            .await?;
        decode_response(response, self.response_bytes).await
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
