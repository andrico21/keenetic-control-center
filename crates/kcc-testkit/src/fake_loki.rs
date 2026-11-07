//! Additive in-process Loki push endpoint for integration tests.

use alloc::{collections::VecDeque, sync::Arc};
use core::{net::SocketAddr, time::Duration};
use std::{io, sync::Mutex};

use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::post,
};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle, time::sleep};

/// One deterministic response fault consumed by the next Loki request.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Fault {
    /// Respond with HTTP 429 and the supplied `Retry-After` delay.
    TooManyRequests(Duration),
    /// Respond with HTTP 500.
    InternalServerError,
    /// Delay the successful response.
    Slow(Duration),
}

/// One Loki request captured without interpreting credentials or payload bytes.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Request {
    /// Request headers.
    headers: HeaderMap,
    /// Raw request body, possibly gzip encoded.
    body: Bytes,
}

impl Request {
    /// Returns the request headers.
    #[inline]
    #[must_use]
    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Returns the raw request body.
    #[inline]
    #[must_use]
    pub const fn body(&self) -> &Bytes {
        &self.body
    }
}

/// Running fake Loki endpoint.
#[derive(Debug)]
#[must_use = "dropping the fake Loki handle stops the server"]
pub struct FakeLoki {
    /// Bound loopback address.
    address: SocketAddr,
    /// Captured push requests.
    requests: Arc<Mutex<Vec<Request>>>,
    /// Response faults consumed in request order.
    faults: Arc<Mutex<VecDeque<Fault>>>,
    /// Graceful-shutdown sender.
    stop: oneshot::Sender<()>,
    /// Serving task.
    task: JoinHandle<io::Result<()>>,
}

impl FakeLoki {
    /// Starts a successful Loki endpoint on an ephemeral loopback port.
    ///
    /// # Errors
    ///
    /// Returns listener binding errors.
    // cancel-safe: dropping before the bind completes leaves nothing running.
    #[inline]
    pub async fn spawn() -> io::Result<Self> {
        Self::spawn_with_faults(Vec::new()).await
    }

    /// Starts a Loki endpoint with deterministic response faults.
    ///
    /// # Errors
    ///
    /// Returns listener binding errors.
    // cancel-safe: dropping before the bind completes leaves nothing running.
    #[inline]
    pub async fn spawn_with_faults(initial_faults: Vec<Fault>) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let address = listener.local_addr()?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let faults = Arc::new(Mutex::new(VecDeque::from(initial_faults)));
        let request_store = Arc::clone(&requests);
        let fault_store = Arc::clone(&faults);
        let app = Router::new().route(
            "/loki/api/v1/push",
            post(move |headers: HeaderMap, body: Bytes| {
                let handler_store = Arc::clone(&request_store);
                let handler_faults = Arc::clone(&fault_store);
                handle(handler_store, handler_faults, headers, body)
            }),
        );
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    match stopped.await {
                        Ok(()) | Err(_) => {}
                    }
                })
                .await
        });
        Ok(Self {
            address,
            requests,
            faults,
            stop,
            task,
        })
    }

    /// Returns the HTTP base URL.
    #[inline]
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    /// Returns a snapshot of captured requests.
    #[inline]
    #[must_use]
    pub fn requests(&self) -> Vec<Request> {
        match self.requests.lock() {
            Ok(requests) => requests.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Appends a fault to the response sequence.
    #[inline]
    pub fn push_fault(&self, fault: Fault) {
        match self.faults.lock() {
            Ok(mut faults) => faults.push_back(fault),
            Err(poisoned) => poisoned.into_inner().push_back(fault),
        }
    }

    /// Stops the server and returns its result.
    ///
    /// # Errors
    ///
    /// Returns the server I/O error or a join error.
    // NOT cancel-safe: after signaling shutdown, cancellation loses the server result.
    #[inline]
    pub async fn shutdown(self) -> io::Result<()> {
        match self.stop.send(()) {
            Ok(()) | Err(()) => {}
        }
        self.task.await.map_err(io::Error::other)?
    }
}

/// Captures a request and applies its next response fault.
// NOT cancel-safe: cancellation during a configured delay consumes that fault.
async fn handle(
    requests: Arc<Mutex<Vec<Request>>>,
    faults: Arc<Mutex<VecDeque<Fault>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match requests.lock() {
        Ok(mut entries) => entries.push(Request { headers, body }),
        Err(poisoned) => poisoned.into_inner().push(Request { headers, body }),
    }
    let fault = match faults.lock() {
        Ok(mut queued) => queued.pop_front(),
        Err(poisoned) => poisoned.into_inner().pop_front(),
    };
    match fault {
        Some(Fault::TooManyRequests(delay)) => {
            let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
            if let Ok(value) = HeaderValue::from_str(&delay.as_secs().to_string()) {
                drop(response.headers_mut().insert(header::RETRY_AFTER, value));
            }
            response
        }
        Some(Fault::InternalServerError) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Some(Fault::Slow(delay)) => {
            sleep(delay).await;
            StatusCode::NO_CONTENT.into_response()
        }
        None => StatusCode::NO_CONTENT.into_response(),
    }
}
