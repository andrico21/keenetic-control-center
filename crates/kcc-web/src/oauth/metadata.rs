//! Discovery: the authorization server metadata (RFC 8414), the public keys, and
//! [`serve_jwks`], the internal loopback listener the kit fetches the keys from.

extern crate alloc;

use alloc::sync::Arc;
use std::io;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::get,
};
use kcc_app::mcp_auth::signing::SigningKey;
use serde_json::{Value, json};
use tokio::{net::TcpListener, task::spawn_blocking};
use url::Url;

use super::{OAuthServer, absent, serving};
use crate::WebState;

/// `GET /.well-known/oauth-authorization-server`.
// cancel-safe: it only reads.
pub(crate) async fn document(State(state): State<WebState>) -> Response {
    serving(&state).map_or_else(absent, |(server, _active)| {
        Json(described(&server)).into_response()
    })
}

/// `GET /.well-known/oauth-authorization-server/<path>`: the same document for an issuer
/// with a path (RFC 8414 section 3), only at that path.
// cancel-safe: it only reads.
pub(crate) async fn document_at(
    State(state): State<WebState>,
    Path(path): Path<String>,
) -> Response {
    match serving(&state) {
        Some((server, _active))
            if issuer_path(server.issuer()).as_deref() == Some(path.as_str()) =>
        {
            Json(described(&server)).into_response()
        }
        Some(_) | None => absent(),
    }
}

/// The issuer's path without its leading `/`, when it has one.
fn issuer_path(issuer: &str) -> Option<String> {
    let url = Url::parse(issuer).ok()?;
    let path = url.path().trim_matches('/');
    (!path.is_empty()).then(|| path.to_owned())
}

/// The metadata document of `server`.
fn described(server: &OAuthServer) -> Value {
    let issuer = server.issuer();
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "registration_endpoint": format!("{issuer}/oauth/register"),
        "revocation_endpoint": format!("{issuer}/oauth/revoke"),
        "jwks_uri": format!("{issuer}/oauth/jwks"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "revocation_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["mcp"],
        "authorization_response_iss_parameter_supported": true,
    })
}

/// `GET /oauth/jwks`: the public signing key.
// cancel-safe: the key is read (or created) on a blocking thread that completes on its own.
pub(crate) async fn jwks(State(state): State<WebState>) -> Response {
    let Some((server, _active)) = serving(&state) else {
        return absent();
    };
    match spawn_blocking(move || server.signing_key().map(SigningKey::jwks)).await {
        Ok(Ok(keys)) => Json(keys).into_response(),
        Ok(Err(error)) => {
            tracing::error!(%error, "the OAuth signing key is unusable");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        Err(error) => {
            tracing::error!(%error, "the OAuth signing key task failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

/// Serves `keys` (a JWKS document) at `GET /jwks` on `listener`, and nothing else, until
/// the process ends: the internal loopback listener the kit validates kcc's tokens with.
///
/// # Errors
///
/// The listener's accept loop failed.
// cancel-safe: dropping it closes the listener; no request changes state.
#[inline]
pub async fn serve_jwks(listener: TcpListener, keys: Arc<[u8]>) -> io::Result<()> {
    let router = Router::new()
        .route("/jwks", get(keys_body))
        .fallback(unknown)
        .with_state(keys);
    axum::serve(listener, router).await
}

/// Any other path or method: `404`, the request body read first.
// cancel-safe: no await point.
async fn unknown(_body: Bytes) -> StatusCode {
    StatusCode::NOT_FOUND
}

/// The JWKS document, never cached.
// cancel-safe: no await point.
async fn keys_body(State(keys): State<Arc<[u8]>>) -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        keys.to_vec(),
    )
        .into_response()
}
