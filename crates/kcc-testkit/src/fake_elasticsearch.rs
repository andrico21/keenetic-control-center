//! Additive in-process Elasticsearch Bulk API endpoint for integration tests.

use alloc::{collections::VecDeque, sync::Arc};
use core::{net::SocketAddr, time::Duration};
use std::{io, sync::Mutex};

use axum::{
    Json, Router,
    body::Bytes,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::post,
};
use serde_json::{Value, json};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle, time::sleep};

/// One deterministic response fault consumed by the next Bulk API request.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Fault {
    /// Respond with HTTP 429 and the supplied `Retry-After` delay.
    TooManyRequests(Duration),
    /// Respond with HTTP 500.
    InternalServerError,
    /// Return a successful HTTP response with one rejected item.
    MapperParsing {
        /// Zero-based item position to reject.
        item: usize,
    },
    /// Delay the successful response.
    Slow(Duration),
}

/// One captured Bulk API request.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Request {
    /// Request headers.
    headers: HeaderMap,
    /// Raw request body.
    body: Bytes,
}

impl Request {
    /// Returns the request headers.
    #[inline]
    #[must_use]
    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Returns the raw NDJSON request body.
    #[inline]
    #[must_use]
    pub const fn body(&self) -> &Bytes {
        &self.body
    }
}

/// Running fake Elasticsearch endpoint.
#[derive(Debug)]
#[must_use = "dropping the fake Elasticsearch handle stops the server"]
pub struct FakeElasticsearch {
    /// Bound loopback address.
    address: SocketAddr,
    /// Captured Bulk API requests.
    requests: Arc<Mutex<Vec<Request>>>,
    /// Response faults consumed in request order.
    faults: Arc<Mutex<VecDeque<Fault>>>,
    /// Graceful-shutdown sender.
    stop: oneshot::Sender<()>,
    /// Serving task.
    task: JoinHandle<io::Result<()>>,
}

impl FakeElasticsearch {
    /// Starts a successful Bulk API endpoint on an ephemeral loopback port.
    ///
    /// # Errors
    ///
    /// Returns listener binding errors.
    // cancel-safe: dropping before the bind completes leaves nothing running.
    #[inline]
    pub async fn spawn() -> io::Result<Self> {
        Self::spawn_with_faults(Vec::new()).await
    }

    /// Starts a Bulk API endpoint with deterministic response faults.
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
            "/_bulk",
            post(move |headers: HeaderMap, body: Bytes| {
                handle(
                    Arc::clone(&request_store),
                    Arc::clone(&fault_store),
                    headers,
                    body,
                )
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

/// Captures one request and applies its next response fault.
// NOT cancel-safe: cancellation during a configured delay consumes that fault.
async fn handle(
    requests: Arc<Mutex<Vec<Request>>>,
    faults: Arc<Mutex<VecDeque<Fault>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (item_count, _) = body
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .fold((0_usize, true), |(count, action), _line| {
            (count.saturating_add(usize::from(action)), !action)
        });
    match requests.lock() {
        Ok(mut entries) => entries.push(Request { headers, body }),
        Err(poisoned) => poisoned.into_inner().push(Request { headers, body }),
    }
    let fault = match faults.lock() {
        Ok(mut queued) => queued.pop_front(),
        Err(poisoned) => poisoned.into_inner().pop_front(),
    };
    match fault {
        Some(Fault::TooManyRequests(delay)) => retry_after(delay),
        Some(Fault::InternalServerError) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Some(Fault::MapperParsing { item }) => bulk_response(item_count, Some(item)),
        Some(Fault::Slow(delay)) => {
            sleep(delay).await;
            bulk_response(item_count, None)
        }
        None => bulk_response(item_count, None),
    }
}

/// Builds an HTTP 429 response with a whole-second `Retry-After` value.
fn retry_after(delay: Duration) -> Response {
    let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
    if let Ok(value) = HeaderValue::from_str(&delay.as_secs().to_string()) {
        drop(response.headers_mut().insert(header::RETRY_AFTER, value));
    }
    response
}

/// Builds a typed Bulk API response, optionally rejecting one item.
fn bulk_response(item_count: usize, rejected: Option<usize>) -> Response {
    let items = (0..item_count)
        .map(|index| {
            if rejected == Some(index) {
                json!({"create":{"status":400_u16,"error":{"type":"mapper_parsing_exception","reason":"fixture rejection"}}})
            } else {
                json!({"create":{"status":201_u16}})
            }
        })
        .collect::<Vec<Value>>();
    (
        StatusCode::OK,
        Json(json!({"errors":rejected.is_some(),"items":items})),
    )
        .into_response()
}
