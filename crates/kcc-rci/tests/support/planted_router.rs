//! Scripted ndw2 router with a known session cookie whose answers carry planted values.

extern crate alloc;

use alloc::sync::Arc;
use core::{
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::io;

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{Method, StatusCode, Uri, header},
    response::{IntoResponse as _, Response},
};
use serde_json::{Value, json};
use tokio::{net::TcpListener, task::JoinHandle};

/// Name of the session cookie.
pub(crate) const COOKIE_NAME: &str = "PLANTEDCOOKIE";

/// The values the router plants in its answers and session.
#[derive(Clone, Debug)]
pub(crate) struct Planted {
    /// The session cookie value (also the ndw2 session id).
    pub cookie: String,
    /// A password inside an answer.
    pub answer_password: String,
    /// A MAC address inside an answer.
    pub mac: String,
    /// A client name inside an answer.
    pub host: String,
    /// The `show version` answer.
    pub version: Value,
    /// How many times `show flapping` was read.
    pub flaps: Arc<AtomicUsize>,
}

impl Planted {
    /// Values built at run time, so no literal in this file looks like a captured one.
    pub(crate) fn new() -> Self {
        Self {
            cookie: format!("COOKIE{}VALUE{}", 40_u8, 2_u8),
            answer_password: ["PLANTED", "PW"].join("-"),
            mac: ["02", "12", "34", "56", "78", "9a"].join(":"),
            host: ["PLANTED", "HOST"].join("-"),
            version: json!({"release": "5.1.1"}),
            flaps: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Every planted value.
    pub(crate) fn all(&self) -> [&str; 4] {
        [&self.cookie, &self.answer_password, &self.mac, &self.host]
    }

    /// A JSON object carrying every planted answer value.
    fn body(&self) -> Value {
        json!({
            "host": [{
                "mac": self.mac,
                "name": self.host,
                "password": self.answer_password,
            }]
        })
    }
}

/// A running scripted router, aborted on drop.
#[derive(Debug)]
pub(crate) struct PlantedRouter {
    /// Loopback listener address.
    address: SocketAddr,
    /// Server task.
    task: JoinHandle<io::Result<()>>,
}

impl PlantedRouter {
    /// Starts the router on an ephemeral loopback port.
    // cancel-safe: dropping setup closes the listener before the task is spawned.
    pub(crate) async fn spawn(planted: Planted) -> io::Result<Self> {
        let app = Router::new().fallback(answer).with_state(Arc::new(planted));
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        Ok(Self { address, task })
    }

    /// The router origin.
    pub(crate) fn url(&self) -> String {
        format!("http://{}", self.address)
    }
}

impl Drop for PlantedRouter {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Answers from the script; the request body is always read first.
// cancel-safe: all work is synchronous once the body is read.
async fn answer(
    State(planted): State<Arc<Planted>>,
    method: Method,
    uri: Uri,
    _body: Bytes,
) -> Response {
    let json = |status: StatusCode, value: Value| {
        (
            status,
            [(header::CONTENT_TYPE, "application/json")],
            value.to_string(),
        )
            .into_response()
    };
    match (method, uri.path()) {
        (Method::GET, "/auth") => (
            StatusCode::UNAUTHORIZED,
            [
                (
                    header::SET_COOKIE,
                    format!("{COOKIE_NAME}={}; Path=/", planted.cookie),
                ),
                (
                    header::WWW_AUTHENTICATE,
                    format!(
                        "x-ndw2-interactive realm=\"planted\" challenge=\"challenge\" session_id=\"{}\" session_cookie=\"{COOKIE_NAME}\"",
                        planted.cookie
                    ),
                ),
            ],
        )
            .into_response(),
        (Method::POST | Method::DELETE, "/auth") => StatusCode::OK.into_response(),
        (Method::GET, "/rci/show/planted") => json(StatusCode::OK, planted.body()),
        (Method::GET, "/rci/show/version") => json(StatusCode::OK, planted.version.clone()),
        (Method::GET, "/rci/show/flapping") => {
            let status = if planted.flaps.fetch_add(1, Ordering::SeqCst) == 0 {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            json(status, json!({}))
        }
        (Method::GET, "/rci/show/broken") => json(StatusCode::INTERNAL_SERVER_ERROR, planted.body()),
        (Method::GET, "/rci/show/refusing") => json(
            StatusCode::OK,
            json!({"status": [{
                "status": "error",
                "code": "7405600",
                "ident": "Command::Base",
                "message": planted.host,
            }]}),
        ),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}
