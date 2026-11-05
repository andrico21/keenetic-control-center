//! Isolated authentication router for protocol and rejection tests.
//!
//! Dummy credentials are admin/admin. These protocol fixtures model the reference
//! implementation, not captured hardware behavior.

use alloc::sync::Arc;
use core::{
    fmt,
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::{io, sync::Mutex};

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse as _, Response},
    routing::{any, get, post},
};
use serde_json::{Value, json};
use tokio::{net::TcpListener, sync::oneshot, task::spawn_blocking};

use crate::{
    Handle, auth_fixture_digest,
    auth_fixture_ndw4::{self, Handshake, Salted},
    ndw2,
    server::lock,
};

/// Selected fixture protocol.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub enum Protocol {
    /// Advertises ndw4 and ndw2, with low Argon2 costs.
    #[default]
    Ndw4,
    /// Accepts only the dummy `fixture-token` token.
    Token,
    /// Challenges each resource with MD5 digest authentication.
    DigestMd5,
    /// Challenges each resource with SHA-256 digest authentication.
    DigestSha256,
}

/// Fault controls for untrusted challenge fields.
#[derive(Clone, Debug)]
#[non_exhaustive]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent adversarial fixture faults may be combined"
)]
pub struct Options {
    /// Enabled protocol.
    pub protocol: Protocol,
    /// Advertised memory cost; fixture KDF always uses 64 KiB.
    pub memory: Value,
    /// Advertised iteration count; fixture KDF always uses two iterations.
    pub iterations: Value,
    /// Replace the server signature with incorrect bytes.
    pub tamper_signature: bool,
    /// Replace the nonce prefix.
    pub tamper_nonce: bool,
    /// Replace the 16-byte salt with a short salt.
    pub tamper_salt: bool,
    /// Return a short-name error beside an empty long-name error.
    pub short_error: bool,
}

impl Default for Options {
    #[inline]
    fn default() -> Self {
        Self {
            protocol: Protocol::Ndw4,
            memory: json!(64_u32),
            iterations: json!(2_u32),
            tamper_signature: false,
            tamper_nonce: false,
            tamper_salt: false,
            short_error: false,
        }
    }
}

/// Observed authentication traffic; no bodies or credentials are recorded.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Counts {
    /// `/auth` probes.
    pub auth_get: AtomicUsize,
    /// Legacy password POSTs.
    pub ndw2_posts: AtomicUsize,
    /// Final ndw4 confirmations.
    pub phase_three: AtomicUsize,
    /// Proof POSTs (zero when the cost guard rejects phase one).
    pub phase_two: AtomicUsize,
    /// Token-bearing requests.
    pub token_requests: AtomicUsize,
    /// Successfully digest-authenticated requests.
    pub digest_requests: AtomicUsize,
}

/// One fixture's private protocol state.
pub(crate) struct Shared {
    /// Public fault settings.
    pub options: Options,
    /// Traffic counters.
    pub counts: Arc<Counts>,
    /// Server-side salted password, computed once.
    pub salted: Salted,
    /// Pending handshake and successful cookie state.
    pub handshake: Mutex<Option<Handshake>>,
    /// Greatest accepted digest nonce count.
    pub digest_count: Mutex<u32>,
}

impl fmt::Debug for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            options: _,
            counts,
            salted: _,
            handshake: _,
            digest_count: _,
        } = self;
        f.debug_struct("AuthFixture")
            .field("counts", counts)
            .finish_non_exhaustive()
    }
}

/// Spawns an isolated auth router on an ephemeral loopback port.
///
/// # Errors
/// Returns listener or fixture key-derivation errors.
// cancel-safe: before spawning, cancellation drops the listener; blocking KDF owns only dummy input.
#[inline]
pub async fn spawn(options: Options) -> io::Result<(SocketAddr, Handle, Arc<Counts>)> {
    let salted = spawn_blocking(Salted::new)
        .await
        .map_err(io::Error::other)??;
    let counts = Arc::new(Counts::default());
    let shared = Arc::new(Shared {
        options,
        counts: Arc::clone(&counts),
        salted,
        handshake: Mutex::new(None),
        digest_count: Mutex::new(0),
    });
    let app = Router::new()
        .route("/auth", get(auth_get).post(auth_post).delete(auth_delete))
        .route("/auth/ndw4", post(auth_fixture_ndw4::phase))
        .route("/rci/{*path}", any(resource))
        .with_state(shared);
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let address = listener.local_addr()?;
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                drop(stopped.await);
            })
            .await
    });
    Ok((address, Handle { stop, task }, counts))
}

/// Checks the fixed dummy fixture cookie and completed handshake.
pub(crate) fn authorized(shared: &Shared, headers: &HeaderMap) -> bool {
    headers
        .get("cookie")
        .is_some_and(|value| value == "AUTHFIXTURE=session")
        && lock(&shared.handshake)
            .as_ref()
            .is_some_and(Handshake::is_authenticated)
}

/// Returns a composite advertisement with legacy parameters preserved.
// cancel-safe: all state access is synchronous.
async fn auth_get(State(shared): State<Arc<Shared>>, headers: HeaderMap) -> Response {
    let _: usize = shared.counts.auth_get.fetch_add(1, Ordering::SeqCst);
    if authorized(&shared, &headers) {
        return StatusCode::OK.into_response();
    }
    (StatusCode::UNAUTHORIZED, [
        ("set-cookie", "AUTHFIXTURE=session; Path=/; Max-Age=300"),
        ("www-authenticate", "x-ndw4-interactive realm=\"fixture\" endpoint=\"/auth/ndw4\", x-ndw2-interactive realm=\"fixture\" challenge=\"challenge\" session_id=\"session\" session_cookie=\"AUTHFIXTURE\"")
    ]).into_response()
}

/// Supports explicit ndw2 selection and records attempted downgrades.
// cancel-safe: state changes occur without suspension.
async fn auth_post(State(shared): State<Arc<Shared>>, body: Bytes) -> Response {
    let _: usize = shared.counts.ndw2_posts.fetch_add(1, Ordering::SeqCst);
    let accepted = serde_json::from_slice::<Value>(&body).is_ok_and(|value| {
        value.get("login").and_then(Value::as_str) == Some("admin")
            && value.get("password").and_then(Value::as_str)
                == Some(
                    ndw2::response_from_ha1("challenge", &ndw2::ha1("admin", "fixture", "admin"))
                        .as_str(),
                )
    });
    if accepted {
        *lock(&shared.handshake) = Some(Handshake::authenticated());
        StatusCode::OK.into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

/// Clears the fixture's active session.
// cancel-safe: synchronous state change.
async fn auth_delete(State(shared): State<Arc<Shared>>) -> StatusCode {
    *lock(&shared.handshake) = None;
    StatusCode::OK
}

/// Protects real resource responses with the selected authentication protocol.
// cancel-safe: all authorization work is synchronous and bounded.
async fn resource(
    State(shared): State<Arc<Shared>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let accepted = match shared.options.protocol {
        Protocol::Token => {
            if headers.contains_key("x-ndma-tkn") {
                let _: usize = shared.counts.token_requests.fetch_add(1, Ordering::SeqCst);
            }
            headers
                .get("x-ndma-tkn")
                .is_some_and(|value| value == "fixture-token")
                || authorized(&shared, &headers)
        }
        Protocol::Ndw4 => authorized(&shared, &headers),
        Protocol::DigestMd5 | Protocol::DigestSha256 => {
            return auth_fixture_digest::resource(&shared, &headers, (&method, &uri));
        }
    };
    if accepted {
        axum::Json(json!({"authenticated": true})).into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}
