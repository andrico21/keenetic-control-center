//! Scripted authentication router that records every request it receives.

extern crate alloc;

use alloc::sync::Arc;
use core::net::SocketAddr;
use std::{
    io,
    sync::{Mutex, PoisonError},
};

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::{IntoResponse as _, Response},
};
use tokio::{net::TcpListener, task::JoinHandle};

/// How the router answers requests.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Script {
    /// `GET /auth` advertises ndw4 at this endpoint; every other request gets 404.
    Ndw4Endpoint(&'static str),
    /// Unsigned requests get 401 with this `WWW-Authenticate`; signed requests get 200.
    Digest(&'static str),
}

/// One observed request: method, path and its `Authorization` header.
pub(crate) type Seen = (Method, String, Option<String>);

/// State shared with the handler.
#[derive(Debug)]
struct Shared {
    /// Selected answers.
    script: Script,
    /// Every request in arrival order.
    requests: Mutex<Vec<Seen>>,
}

/// A running scripted router, aborted on drop.
#[derive(Debug)]
pub(crate) struct Recorder {
    /// Loopback listener address.
    address: SocketAddr,
    /// Handler state.
    shared: Arc<Shared>,
    /// Server task.
    task: JoinHandle<io::Result<()>>,
}

impl Recorder {
    /// Starts the router on an ephemeral loopback port.
    // cancel-safe: dropping setup closes the listener before the task is spawned.
    pub(crate) async fn spawn(script: Script) -> io::Result<Self> {
        let shared = Arc::new(Shared {
            script,
            requests: Mutex::new(Vec::new()),
        });
        let app = Router::new()
            .fallback(answer)
            .with_state(Arc::clone(&shared));
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        Ok(Self {
            address,
            shared,
            task,
        })
    }

    /// Returns the listener address.
    pub(crate) const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Returns the requests observed so far.
    pub(crate) fn requests(&self) -> Vec<Seen> {
        self.shared
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Records the request, then answers from the script.
// cancel-safe: all work is synchronous.
async fn answer(
    State(shared): State<Arc<Shared>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let is_auth_probe = method == Method::GET && uri.path() == "/auth";
    shared
        .requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((method, uri.path().to_owned(), authorization.clone()));
    match shared.script {
        Script::Ndw4Endpoint(endpoint) if is_auth_probe => (
            StatusCode::UNAUTHORIZED,
            [
                (header::SET_COOKIE, "SCRIPTED=session; Path=/".to_owned()),
                (
                    header::WWW_AUTHENTICATE,
                    format!("x-ndw4-interactive realm=\"scripted\", endpoint=\"{endpoint}\""),
                ),
            ],
        )
            .into_response(),
        Script::Ndw4Endpoint(_) => StatusCode::NOT_FOUND.into_response(),
        Script::Digest(_) if authorization.is_some() => StatusCode::OK.into_response(),
        Script::Digest(challenge) => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, challenge)],
        )
            .into_response(),
    }
}
