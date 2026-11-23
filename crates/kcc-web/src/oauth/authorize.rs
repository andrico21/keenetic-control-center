//! `GET /oauth/authorize`: checks the request and keeps it for the consent page.
//!
//! An unknown client or a redirect URI the client did not register gets an error page and
//! never a redirect; once both are known good, every other refusal goes back to that
//! redirect URI with `error`, the `state` and the `iss` (RFC 9207).

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::net::{IpAddr, Ipv4Addr};

use axum::{
    Extension,
    extract::{RawQuery, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use kcc_app::mcp_auth::{
    clients::Client,
    pending::{AuthorizationRequest, CodeTarget, PkceChallenge},
};
use kcc_i18n::keys;
use rmcp_server_kit::transport::ClientIp;
use secrecy::ExposeSecret as _;
use tokio::task::spawn_blocking;
use url::{Url, UrlQuery, form_urlencoded::Serializer};

use super::{Active, OAuthServer, absent, serving, single_params};
use crate::{WebState, auth::CONSENT_PAGE, oauth_consent::error_page, prefs};

/// The scope kcc grants; a request may name it or nothing.
pub(crate) const SCOPE: &str = "mcp";

/// `GET /oauth/authorize`.
// cancel-safe: the client list is read on a blocking thread; a pending request is stored
// whole or not at all.
pub(crate) async fn authorize(
    State(state): State<WebState>,
    client: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let Some((server, active)) = serving(&state) else {
        return absent();
    };
    let page = |status, key| {
        error_page(
            prefs::shell(&headers, state.default_locale()).signed_out(),
            status,
            key,
        )
    };
    let address = client.map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |Extension(resolved)| {
        resolved.ip
    });
    if !server.authorizations.admit(address) {
        return page(StatusCode::TOO_MANY_REQUESTS, keys::WEB_OAUTH_ERROR_BUSY);
    }
    let Some(params) = single_params(query.as_deref().unwrap_or_default()) else {
        return page(StatusCode::BAD_REQUEST, keys::WEB_OAUTH_ERROR_REQUEST);
    };
    let clients = Arc::clone(&server);
    let document = match spawn_blocking(move || clients.clients.document()).await {
        Ok(Ok(document)) => document,
        Ok(Err(error)) => {
            tracing::error!(%error, "the OAuth clients cannot be read");
            return page(
                StatusCode::SERVICE_UNAVAILABLE,
                keys::WEB_OAUTH_ERROR_REQUEST,
            );
        }
        Err(error) => {
            tracing::error!(%error, "the OAuth clients task failed");
            return page(
                StatusCode::SERVICE_UNAVAILABLE,
                keys::WEB_OAUTH_ERROR_REQUEST,
            );
        }
    };
    let Some(registered) = params.get("client_id").and_then(|id| document.client(id)) else {
        return page(StatusCode::BAD_REQUEST, keys::WEB_OAUTH_ERROR_CLIENT);
    };
    let Some(redirect) = params
        .get("redirect_uri")
        .filter(|uri| registered.redirect_matches(uri))
    else {
        return page(StatusCode::BAD_REQUEST, keys::WEB_OAUTH_ERROR_REDIRECT);
    };
    let answer = Answer {
        redirect,
        state: params.get("state").map(String::as_str),
        issuer: server.issuer(),
    };
    match pending(&server, (&active, address), registered, &params) {
        Ok(id) => found(&format!("{CONSENT_PAGE}{id}")),
        Err(Refusal::Stateless(error)) => answer.refused(error, false),
        Err(Refusal::Echoed(error)) => answer.refused(error, true),
    }
}

/// Why a well-addressed request was refused: the RFC 6749 error code, and whether the
/// `state` may be echoed (not when the state itself is invalid).
enum Refusal {
    /// The error, echoing the state.
    Echoed(&'static str),
    /// The error, without the state.
    Stateless(&'static str),
}

/// Checks a request of the `registered` client whose redirect URI matched, and keeps it
/// as sent from the client address `from`; the pending request's id.
///
/// # Errors
///
/// The [`Refusal`] to send back to the client.
fn pending(
    server: &OAuthServer,
    (active, from): (&Active, IpAddr),
    registered: &Client,
    params: &BTreeMap<String, String>,
) -> Result<String, Refusal> {
    let param = |name: &str| params.get(name).map(String::as_str);
    if param("response_type") != Some("code") {
        return Err(Refusal::Echoed("unsupported_response_type"));
    }
    if param("scope").is_some_and(|scope| scope.split(' ').any(|token| token != SCOPE)) {
        return Err(Refusal::Echoed("invalid_scope"));
    }
    let resource = param("resource")
        .filter(|resource| active.accepts(resource))
        .ok_or(Refusal::Echoed("invalid_target"))?;
    let challenge = PkceChallenge::parse(
        param("code_challenge_method").unwrap_or_default(),
        param("code_challenge").unwrap_or_default(),
    )
    .map_err(|_refused| Refusal::Echoed("invalid_request"))?;
    let target = CodeTarget::new(
        registered.id(),
        param("redirect_uri").unwrap_or_default(),
        resource,
    );
    let request = AuthorizationRequest::new(registered, target, challenge)
        .map_err(|_refused| Refusal::Echoed("invalid_request"))?
        .with_state(param("state"))
        .map_err(|_refused| Refusal::Stateless("invalid_request"))?;
    match server.pending.begin(request, from) {
        Ok(id) => Ok(id.expose_secret().to_owned()),
        Err(error) => {
            tracing::error!(%error, "an authorization request could not be kept");
            Err(Refusal::Echoed("server_error"))
        }
    }
}

/// Where a refusal goes: the registered redirect URI, with the request's state and the
/// issuer.
struct Answer<'request> {
    /// The registered redirect URI the request named.
    redirect: &'request str,
    /// The request's `state`.
    state: Option<&'request str>,
    /// The issuer.
    issuer: &'request str,
}

impl Answer<'_> {
    /// Sends the browser back to the client with `error` (and the state when `echo`).
    fn refused(&self, error: &str, echo: bool) -> Response {
        let mut pairs = vec![("error", error)];
        if let Some(state) = self.state.filter(|_| echo) {
            pairs.push(("state", state));
        }
        pairs.push(("iss", self.issuer));
        with_query(self.redirect, &pairs).map_or_else(
            || StatusCode::BAD_REQUEST.into_response(),
            |target| found(&target),
        )
    }
}

/// `redirect` with `pairs` appended to its query; `None` when it is not an absolute URL.
pub(crate) fn with_query(redirect: &str, pairs: &[(&str, &str)]) -> Option<String> {
    let mut url = Url::parse(redirect).ok()?;
    let _: &mut Serializer<'_, UrlQuery<'_>> = url.query_pairs_mut().extend_pairs(pairs);
    Some(url.into())
}

/// A `303 See Other` to `target`.
fn found(target: &str) -> Response {
    match HeaderValue::from_str(target) {
        Ok(value) => (StatusCode::SEE_OTHER, [(header::LOCATION, value)]).into_response(),
        Err(_invalid) => StatusCode::BAD_REQUEST.into_response(),
    }
}
