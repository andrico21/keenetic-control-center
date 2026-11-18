//! Server-side SCRAM fixture independent of the client implementation.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use std::io;

use argon2::{Algorithm, Argon2, Params, Version};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{KeyInit as _, Mac as _, SimpleHmac};
use serde_json::{Value, json};
use sha3::{Digest as _, Sha3_512};
use subtle::ConstantTimeEq as _;
use tokio::time::sleep;
use zeroize::Zeroizing;

use crate::{
    auth_fixture::{HANG_FOR, Hang, Shared},
    server::lock,
};

/// Fixture salt, independent of each fresh challenge nonce.
const SALT: [u8; 16] = [7_u8; 16];

/// Server-side salted password storage.
pub(crate) struct Salted(Zeroizing<[u8; 64]>);

impl Salted {
    /// Computes the dummy account's salted password once, outside async execution.
    ///
    /// # Errors
    /// Returns an error if the KDF parameters are invalid.
    pub(crate) fn new(iterations: u32) -> io::Result<Self> {
        let params = Params::new(64, iterations, 1, Some(64)).map_err(io::Error::other)?;
        let mut output = Zeroizing::new([0_u8; 64]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(b"admin", &SALT, output.as_mut())
            .map_err(io::Error::other)?;
        Ok(Self(output))
    }
}

/// Per-session exchange data, deliberately without Debug.
pub(crate) struct Handshake {
    /// Combined nonce.
    nonce: String,
    /// Exact signed message.
    message: String,
    /// Verified phase-two signature.
    signature: Option<String>,
    /// Whether phase three completed.
    authenticated: bool,
}

impl Handshake {
    /// Whether the final confirmation succeeded.
    pub(crate) const fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Creates an authenticated legacy session.
    pub(crate) const fn authenticated() -> Self {
        Self {
            nonce: String::new(),
            message: String::new(),
            signature: None,
            authenticated: true,
        }
    }
}

/// Encodes the reply in the header; the body intentionally contains unrelated data.
fn reply(value: &Value, status: StatusCode) -> Response {
    (
        status,
        [("x-ndm-data", STANDARD.encode(value.to_string()))],
        "body-is-not-the-reply",
    )
        .into_response()
}

/// Computes the fixture's HMAC without exposing failures or key material.
fn mac(key: &[u8], data: &[u8]) -> Option<Zeroizing<[u8; 64]>> {
    let mut hasher = SimpleHmac::<Sha3_512>::new_from_slice(key).ok()?;
    hasher.update(data);
    Some(Zeroizing::new(hasher.finalize().into_bytes().into()))
}

/// Verifies a SCRAM proof against the server's stored key.
fn verify(salted: &Salted, message: &str, proof: &str) -> bool {
    let Some(client) = mac(salted.0.as_slice(), b"NDW4 Interactive Client Key") else {
        return false;
    };
    let stored = Zeroizing::new(Sha3_512::digest(client.as_slice()).to_vec());
    let Some(signature) = mac(&stored, message.as_bytes()) else {
        return false;
    };
    let Ok(decoded) = STANDARD.decode(proof) else {
        return false;
    };
    let mut recovered = Zeroizing::new(decoded);
    if recovered.len() != 64 {
        return false;
    }
    for (byte, mask) in recovered.iter_mut().zip(signature.iter()) {
        *byte ^= mask;
    }
    bool::from(
        Sha3_512::digest(recovered.as_slice())
            .as_slice()
            .ct_eq(&stored),
    )
}

/// Handles the three phases while counting effects independently from client code.
// cancel-safe: low-cost hashes and state mutations are synchronous; Argon2 ran at fixture creation;
// a hanging fixture waits before any state change.
pub(crate) async fn phase(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if shared.options.hang == Hang::Ndw4Phases {
        sleep(HANG_FOR).await;
    }
    if headers
        .get("cookie")
        .is_none_or(|value| value != "AUTHFIXTURE=session")
    {
        return reply(&json!({"error":"cookie"}), StatusCode::UNAUTHORIZED);
    }
    let Ok(value) = serde_json::from_slice::<Value>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if value.get("login").and_then(Value::as_str) != Some("admin") {
        return reply(&json!({"error":"login"}), StatusCode::UNAUTHORIZED);
    }
    if shared.options.short_error {
        return reply(
            &json!({"error":"", "e":"rejected"}),
            StatusCode::UNAUTHORIZED,
        );
    }
    let Some(nonce) = value.get("nonce").and_then(Value::as_str) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if let Some(proof) = value.get("signature-proof").and_then(Value::as_str) {
        let _: usize = shared.counts.phase_three.fetch_add(1, Ordering::SeqCst);
        let mut state = lock(&shared.handshake);
        if let Some(handshake) = state.as_mut()
            && let Some(signature) = &handshake.signature
            && handshake.nonce == nonce
            && verify(
                &shared.salted,
                &format!("{};signature4={signature}", handshake.message),
                proof,
            )
        {
            handshake.authenticated = true;
            drop(state);
            return StatusCode::OK.into_response();
        }
        drop(state);
        return reply(&json!({"error":"proof"}), StatusCode::UNAUTHORIZED);
    }
    if let Some(proof) = value.get("proof").and_then(Value::as_str) {
        let _: usize = shared.counts.phase_two.fetch_add(1, Ordering::SeqCst);
        let mut state = lock(&shared.handshake);
        if let Some(handshake) = state.as_mut()
            && handshake.nonce == nonce
            && verify(&shared.salted, &handshake.message, proof)
            && let Some(server) = mac(shared.salted.0.as_slice(), b"NDW4 Interactive Server Key")
            && let Some(signature) = mac(server.as_slice(), handshake.message.as_bytes())
        {
            let encoded = if shared.options.tamper_signature {
                STANDARD.encode([0_u8; 64])
            } else {
                STANDARD.encode(signature.as_slice())
            };
            handshake.signature = Some(encoded.clone());
            drop(state);
            return reply(&json!({"signature":encoded}), StatusCode::UNAUTHORIZED);
        }
        drop(state);
        return reply(&json!({"error":"proof"}), StatusCode::UNAUTHORIZED);
    }
    if !STANDARD.decode(nonce).is_ok_and(|bytes| bytes.len() == 16) {
        return reply(&json!({"error":"nonce"}), StatusCode::UNAUTHORIZED);
    }
    let combined = if shared.options.tamper_nonce {
        "invalid-prefix".to_owned()
    } else {
        format!("{nonce}server-nonce")
    };
    let salt = if shared.options.tamper_salt {
        STANDARD.encode([7_u8; 8])
    } else {
        STANDARD.encode(SALT)
    };
    let raw = |cost: &Value| {
        cost.as_str()
            .map_or_else(|| cost.to_string(), str::to_owned)
    };
    let message = format!(
        "login1=admin,nonce1={nonce};iter2={},memcost2={},nonce2={combined},salt2={salt};login3=admin,nonce3={combined}",
        raw(&shared.options.iterations),
        raw(&shared.options.memory)
    );
    *lock(&shared.handshake) = Some(Handshake {
        nonce: combined.clone(),
        message,
        signature: None,
        authenticated: false,
    });
    reply(
        &json!({"salt":salt,"nonce":combined,"iter":shared.options.iterations,"memcost":shared.options.memory}),
        StatusCode::UNAUTHORIZED,
    )
}
