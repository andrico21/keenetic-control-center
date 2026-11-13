//! Dedicated background sessions under the parent router's admission budget.

use alloc::sync::Arc;
use core::{fmt, time::Duration};

use reqwest::Method;
use serde_json::Value;
use tokio::{sync::Semaphore, time};
use tokio_util::sync::CancellationToken;

use super::{RciBody, RciClient, decode_response, response_json, session};
use crate::{
    RciError, RciPath,
    session::{Manager, RequestKind},
};

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
    let session = Arc::new(session(&client.router, &client.credentials, &client.options).await?);
    let _permit = client
        .semaphore
        .acquire()
        .await
        .map_err(|_closed| RciError::Transport)?;
    let response = session.post(&format!("/rci/{path}"), body).await?;
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
    session: Arc<Manager>,
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
        let path = format!("/rci/{}?id={}", self.path, self.process_id);
        let response = self.session.get(&path).await?;
        decode_response(response, self.response_bytes).await
    }

    /// Overrides the default one-second poll interval.
    #[inline]
    #[must_use]
    pub const fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Polls to completion, sending DELETE on token cancellation or deadline expiry.
    ///
    /// # Errors
    /// Returns timeout, cancellation cleanup, request or response errors.
    // NOT cancel-safe: token cancellation sends DELETE; directly dropping cannot await cleanup.
    #[inline]
    #[expect(
        clippy::integer_division_remainder_used,
        reason = "tokio::select expansion uses remainder arithmetic"
    )]
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
            () = token.cancelled() => Err(RciError::Timeout),
            result = time::timeout(self.deadline, operation) => match result {
                Ok(value) => value,
                Err(_elapsed) => Err(RciError::Timeout),
            },
        };
        if matches!(result, Err(RciError::Timeout)) {
            drop(self.stop().await?);
        }
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
        let path = format!("/rci/{}?id={}", self.path, self.process_id);
        let response = self
            .session
            .request::<()>(Method::DELETE, &path, None, RequestKind::NonRetryable)
            .await?;
        decode_response(response, self.response_bytes).await
    }
}
