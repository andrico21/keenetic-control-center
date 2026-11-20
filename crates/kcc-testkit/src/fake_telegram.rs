//! Additive in-process Telegram Bot API endpoint for integration tests.
//!
//! Serves `POST /bot<token>/sendMessage` and nothing else. The fake never logs a token.

use alloc::sync::Arc;
use core::{fmt, net::SocketAddr, time::Duration};
use std::{
    io,
    sync::{Mutex, MutexGuard, PoisonError},
};

use axum::{Router, routing::post};
use serde_json::Value;
use tokio::{
    net::TcpListener,
    sync::{oneshot, watch},
    task::JoinHandle,
    time::Instant,
};

use self::handler::{not_allowed, not_found, send_message};

mod handler;

/// One deterministic response fault consumed by the next matching request.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Fault {
    /// Respond with 429 and `parameters.retry_after` seconds.
    TooManyRequests {
        /// Seconds the client is told to wait.
        retry_after: u64,
    },
    /// Respond with 401, as for a revoked token.
    Unauthorized,
    /// Respond with 403, as when the user blocked the bot.
    Forbidden,
    /// Respond with 400 "chat not found".
    ChatNotFound,
    /// Respond with 500.
    InternalServerError,
    /// Respond with 302 to the given location.
    Redirect(String),
    /// Delay the response, then answer it normally.
    Slow(Duration),
}

/// One captured `sendMessage` request.
#[derive(Clone)]
#[non_exhaustive]
pub struct Request {
    /// Bot token taken from the path.
    token: String,
    /// `chat_id` as sent, `null` when missing.
    chat_id: Value,
    /// `text` as sent, empty when missing.
    text: String,
    /// The whole JSON body, `null` when it did not parse.
    body: Value,
    /// Arrival time on the tokio clock: the virtual instant under a paused clock.
    at: Instant,
}

impl Request {
    /// Returns the bot token of the path.
    #[inline]
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Returns the `chat_id` as sent.
    #[inline]
    #[must_use]
    pub const fn chat_id(&self) -> &Value {
        &self.chat_id
    }

    /// Returns the message text.
    #[inline]
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns the whole JSON body.
    #[inline]
    #[must_use]
    pub const fn body(&self) -> &Value {
        &self.body
    }

    /// Returns when the request arrived, on the tokio clock.
    #[inline]
    #[must_use]
    pub const fn at(&self) -> Instant {
        self.at
    }
}

impl fmt::Debug for Request {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("token", &"[REDACTED]")
            .field("chat_id", &self.chat_id)
            .field("text", &self.text)
            .field("at", &self.at)
            .finish_non_exhaustive()
    }
}

/// Mutable state shared by the handler and the handle.
struct Inner {
    /// Captured requests.
    requests: Vec<Request>,
    /// Faults with their optional chat scope, oldest first.
    faults: Vec<(Option<Value>, Fault)>,
    /// The only accepted token; any token when `None`.
    expected: Option<String>,
    /// Next `message_id`.
    next_id: u64,
}

/// State plus the request counter observers wait on.
struct Shared {
    /// Guarded state.
    state: Mutex<Inner>,
    /// Number of captured requests.
    count: watch::Sender<usize>,
}

impl Shared {
    /// Locks the state; a poisoned lock still holds consistent data.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Running fake Telegram Bot API.
#[derive(Debug)]
#[must_use = "dropping the fake Telegram handle stops the server"]
pub struct FakeTelegram {
    /// Bound loopback address.
    address: SocketAddr,
    /// State shared with the handler.
    shared: Arc<Shared>,
    /// Graceful-shutdown sender.
    stop: oneshot::Sender<()>,
    /// Serving task.
    task: JoinHandle<io::Result<()>>,
}

impl fmt::Debug for Shared {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shared").finish_non_exhaustive()
    }
}

impl FakeTelegram {
    /// Starts the fake on an ephemeral loopback port, accepting any token.
    ///
    /// # Errors
    ///
    /// Returns listener binding errors.
    // cancel-safe: dropping before the bind completes leaves nothing running.
    #[inline]
    pub async fn spawn() -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let address = listener.local_addr()?;
        let (count, _initial) = watch::channel(0_usize);
        let shared = Arc::new(Shared {
            state: Mutex::new(Inner {
                requests: Vec::new(),
                faults: Vec::new(),
                expected: None,
                next_id: 1,
            }),
            count,
        });
        let app = Router::new()
            .route("/{bot}/sendMessage", post(send_message))
            .fallback(not_found)
            .method_not_allowed_fallback(not_allowed)
            .with_state(Arc::clone(&shared));
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
            shared,
            stop,
            task,
        })
    }

    /// Returns the HTTP base URL, which a client extends with `/bot<token>/sendMessage`.
    #[inline]
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    /// Accepts only `token`; every other token gets 401.
    #[inline]
    pub fn expect_token(&self, token: &str) {
        self.shared.lock().expected = Some(token.to_owned());
    }

    /// Returns a snapshot of captured requests, including rejected ones.
    #[inline]
    #[must_use]
    pub fn requests(&self) -> Vec<Request> {
        self.shared.lock().requests.clone()
    }

    /// Queues a fault for the next request.
    #[inline]
    pub fn push_fault(&self, fault: Fault) {
        self.shared.lock().faults.push((None, fault));
    }

    /// Queues a fault for the next request addressed to `chat_id` (a JSON number or
    /// string, compared as sent).
    #[inline]
    pub fn push_fault_for<C>(&self, chat_id: C, fault: Fault)
    where
        C: Into<Value>,
    {
        self.shared
            .lock()
            .faults
            .push((Some(chat_id.into()), fault));
    }

    /// Resolves once at least `count` requests were captured, without polling.
    ///
    /// Callers bound the wait with their own timeout.
    // cancel-safe: only observes the request counter.
    #[inline]
    pub async fn wait_for_requests(&self, count: usize) {
        let mut seen = self.shared.count.subscribe();
        match seen.wait_for(|captured| *captured >= count).await {
            Ok(_) | Err(_) => {}
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
