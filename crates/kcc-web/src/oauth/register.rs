//! `POST /oauth/register` (RFC 7591: public clients only, kcc's limits) and
//! `POST /oauth/revoke` (RFC 7009).

extern crate alloc;

use alloc::sync::Arc;
use core::net::{IpAddr, Ipv4Addr};

use axum::{
    Extension,
    extract::State,
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use kcc_app::mcp_auth::clients::{ClientError, ClientRegistration};
use rmcp_server_kit::transport::ClientIp;
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::json;
use tokio::task::spawn_blocking;

use super::{absent, serving, single_params, token::no_store};
use crate::WebState;

/// The client metadata kcc reads; every other field is ignored (`logo_uri` and
/// `client_uri` are never fetched or shown).
#[derive(Debug, Deserialize)]
struct Metadata {
    /// The client's name, shown as unverified on the consent page.
    #[serde(default)]
    client_name: Option<String>,
    /// The redirect URIs.
    #[serde(default)]
    redirect_uris: Vec<String>,
    /// Must be `none` when given: kcc has public clients only.
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
    /// Must be a subset of what kcc supports when given.
    #[serde(default)]
    grant_types: Option<Vec<String>>,
    /// Must be `["code"]` when given.
    #[serde(default)]
    response_types: Option<Vec<String>>,
}

/// `POST /oauth/register`.
// NOT cancel-safe: the client is written on a blocking thread that completes on its own.
pub(crate) async fn register(
    State(state): State<WebState>,
    client: Option<Extension<ClientIp>>,
    body: String,
) -> Response {
    let Some((server, _active)) = serving(&state) else {
        return absent();
    };
    let address = client.map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |Extension(resolved)| {
        resolved.ip
    });
    if !server.registrations.admit(address) {
        return no_store(
            StatusCode::TOO_MANY_REQUESTS,
            json!({"error": "temporarily_unavailable"}),
        );
    }
    let Ok(metadata) = serde_json::from_str::<Metadata>(&body) else {
        return refused("invalid_client_metadata");
    };
    let public = metadata
        .token_endpoint_auth_method
        .as_deref()
        .is_none_or(|method| method == "none");
    let grants = metadata.grant_types.as_deref().is_none_or(|types| {
        types
            .iter()
            .all(|kind| kind == "authorization_code" || kind == "refresh_token")
    });
    let responses = metadata
        .response_types
        .as_deref()
        .is_none_or(|types| types.iter().all(|kind| kind == "code"));
    if !(public && grants && responses) {
        return refused("invalid_client_metadata");
    }
    let registration = ClientRegistration::new(metadata.client_name, metadata.redirect_uris);
    let store = Arc::clone(&server);
    match spawn_blocking(move || store.clients.register(&registration)).await {
        Ok(Ok(registered)) => no_store(
            StatusCode::CREATED,
            json!({
                "client_id": registered.id(),
                "client_id_issued_at": registered.registered_at(),
                "client_name": registered.name(),
                "redirect_uris": registered.redirect_uris(),
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            }),
        ),
        Ok(Err(ClientError::RedirectUri {
            index: _,
            reason: _,
        })) => refused("invalid_redirect_uri"),
        Ok(Err(ClientError::Invalid { field: _ } | ClientError::TooMany)) => {
            refused("invalid_client_metadata")
        }
        Ok(Err(error)) => {
            tracing::error!(%error, "a client could not be registered");
            no_store(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "server_error"}),
            )
        }
        Err(error) => {
            tracing::error!(%error, "the registration task failed");
            no_store(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "server_error"}),
            )
        }
    }
}

/// A `400` registration refusal with `error`.
fn refused(error: &'static str) -> Response {
    no_store(StatusCode::BAD_REQUEST, json!({ "error": error }))
}

/// `POST /oauth/revoke`: a refresh token of the named client revokes its whole family;
/// anything else (an access token, an unknown token) is answered `200` as RFC 7009 asks.
// NOT cancel-safe: the revocation is written on a blocking thread that completes on its own.
pub(crate) async fn revoke(State(state): State<WebState>, body: String) -> Response {
    let Some((_server, active)) = serving(&state) else {
        return absent();
    };
    let Some(params) = single_params(&body) else {
        return refused("invalid_request");
    };
    let (Some(token), Some(client)) = (params.get("token"), params.get("client_id")) else {
        return refused("invalid_request");
    };
    let (secret, owner) = (SecretString::from(token.clone()), client.clone());
    match spawn_blocking(move || active.grants.revoke_token(&secret, &owner)).await {
        Ok(Ok(_revoked)) => StatusCode::OK.into_response(),
        Ok(Err(error)) => {
            tracing::error!(%error, "a token could not be revoked");
            no_store(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "temporarily_unavailable"}),
            )
        }
        Err(error) => {
            tracing::error!(%error, "the revocation task failed");
            no_store(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "temporarily_unavailable"}),
            )
        }
    }
}
