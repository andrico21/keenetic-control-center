//! ndw4 router whose Argon2 iteration count changes after the first handshake.
//!
//! The router derives its verifier from the parameters it advertises, so a client that
//! reuses keys derived from earlier parameters sends a proof the router refuses.

extern crate alloc;

use alloc::sync::Arc;
use core::net::SocketAddr;
use std::{
    io,
    sync::{Mutex, MutexGuard, PoisonError},
};

use argon2::{Algorithm, Argon2, Params, Version};
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{KeyInit as _, Mac as _, SimpleHmac};
use serde_json::{Value, json};
use sha3::{Digest as _, Sha3_512};
use tokio::{net::TcpListener, task::JoinHandle};

/// Fixed dummy salt; only the iteration count rotates.
const SALT: [u8; 16] = [7_u8; 16];
/// Session cookie issued with every challenge.
const COOKIE: &str = "ROTATING=session";

/// One handshake's server-side material.
struct Handshake {
    /// Exact signed message.
    message: String,
    /// Argon2 output for the advertised parameters.
    salted: [u8; 64],
    /// Signature returned in phase two.
    signature: Option<String>,
}

/// Mutable router state.
#[derive(Default)]
struct Inner {
    /// Completed phase-one challenges.
    challenges: u32,
    /// Current handshake.
    handshake: Option<Handshake>,
    /// Whether phase three succeeded and no logout followed.
    authenticated: bool,
}

/// A running rotating-parameter router, aborted on drop.
pub(crate) struct Rotating {
    /// Loopback listener address.
    address: SocketAddr,
    /// Server task.
    task: JoinHandle<io::Result<()>>,
}

impl Rotating {
    /// Starts the router for the dummy `admin` password.
    // cancel-safe: dropping setup closes the listener before the task is spawned.
    pub(crate) async fn spawn() -> io::Result<Self> {
        let app = Router::new()
            .route("/auth", get(probe).delete(logout))
            .route("/auth/ndw4", post(phase))
            .with_state(Arc::new(Mutex::new(Inner::default())));
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        Ok(Self { address, task })
    }

    /// Returns the listener address.
    pub(crate) const fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for Rotating {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Locks the router state, tolerating a poisoned test thread.
fn lock(state: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// HMAC-SHA3-512, the ndw4 MAC; HMAC accepts any key length, so the fallback is never used.
fn mac(key: &[u8], data: &[u8]) -> [u8; 64] {
    let Ok(mut hasher) = SimpleHmac::<Sha3_512>::new_from_slice(key) else {
        return [0_u8; 64];
    };
    hasher.update(data);
    hasher.finalize().into_bytes().into()
}

/// The client proof the router expects for `message`.
fn expected_proof(salted: &[u8; 64], message: &str) -> String {
    let client = mac(salted, b"NDW4 Interactive Client Key");
    let stored = Sha3_512::digest(client);
    let mut proof = mac(&stored, message.as_bytes());
    for (byte, key) in proof.iter_mut().zip(client) {
        *byte ^= key;
    }
    STANDARD.encode(proof)
}

/// Encodes a reply in the `x-ndm-data` header.
fn reply(value: &Value) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [("x-ndm-data", STANDARD.encode(value.to_string()))],
    )
        .into_response()
}

/// `GET /auth`: 200 for the authenticated cookie, otherwise an ndw4 challenge.
// cancel-safe: synchronous state access.
async fn probe(State(state): State<Arc<Mutex<Inner>>>, headers: HeaderMap) -> Response {
    let cookie = headers
        .get(header::COOKIE)
        .is_some_and(|value| value == COOKIE);
    if cookie && lock(&state).authenticated {
        return StatusCode::OK.into_response();
    }
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::SET_COOKIE, format!("{COOKIE}; Path=/")),
            (
                header::WWW_AUTHENTICATE,
                "x-ndw4-interactive realm=\"rotating\", endpoint=\"/auth/ndw4\"".to_owned(),
            ),
        ],
    )
        .into_response()
}

/// `DELETE /auth`: ends the router session.
// cancel-safe: synchronous state change.
async fn logout(State(state): State<Arc<Mutex<Inner>>>) -> StatusCode {
    lock(&state).authenticated = false;
    StatusCode::OK
}

/// The three ndw4 phases; phase one advertises two iterations first, then three.
// cancel-safe: synchronous state access and bounded hashing.
async fn phase(State(state): State<Arc<Mutex<Inner>>>, body: Bytes) -> Response {
    let Ok(value) = serde_json::from_slice::<Value>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    advance(&mut lock(&state), &value)
}

/// Applies one phase body to the router state.
fn advance(inner: &mut Inner, value: &Value) -> Response {
    let text = |name: &str| value.get(name).and_then(Value::as_str).map(str::to_owned);
    if let Some(confirmation) = text("signature-proof") {
        let accepted = inner.handshake.as_ref().is_some_and(|handshake| {
            handshake.signature.as_ref().is_some_and(|signature| {
                let signed = format!("{};signature4={signature}", handshake.message);
                expected_proof(&handshake.salted, &signed) == confirmation
            })
        });
        inner.authenticated = accepted;
        return if accepted {
            StatusCode::OK.into_response()
        } else {
            reply(&json!({"error": "proof"}))
        };
    }
    if let Some(proof) = text("proof") {
        let Some(handshake) = inner.handshake.as_mut() else {
            return reply(&json!({"error": "state"}));
        };
        if expected_proof(&handshake.salted, &handshake.message) != proof {
            return reply(&json!({"error": "proof"}));
        }
        let server = mac(&handshake.salted, b"NDW4 Interactive Server Key");
        let signature = STANDARD.encode(mac(&server, handshake.message.as_bytes()));
        handshake.signature = Some(signature.clone());
        return reply(&json!({"signature": signature}));
    }
    let Some(nonce) = text("nonce") else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let iterations = if inner.challenges == 0 { 2_u32 } else { 3_u32 };
    inner.challenges = inner.challenges.saturating_add(1);
    let Ok(params) = Params::new(64, iterations, 1, Some(64)) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut salted = [0_u8; 64];
    if Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(b"admin", &SALT, &mut salted)
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let combined = format!("{nonce}rotating");
    let salt = STANDARD.encode(SALT);
    let message = format!(
        "login1=admin,nonce1={nonce};iter2={iterations},memcost2=64,nonce2={combined},salt2={salt};login3=admin,nonce3={combined}"
    );
    inner.handshake = Some(Handshake {
        message,
        salted,
        signature: None,
    });
    reply(&json!({"salt": salt, "nonce": combined, "iter": iterations, "memcost": 64_u32}))
}
