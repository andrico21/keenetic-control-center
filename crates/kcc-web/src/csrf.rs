//! CSRF token and browser-origin enforcement for state-changing Web UI requests.

use axum::{
    extract::{Request, State},
    http::{Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse as _, Response},
};
use subtle::ConstantTimeEq as _;

use crate::{WebState, session::SessionStore};

/// Header carrying the session-bound CSRF token.
pub(crate) const HEADER_NAME: &str = "x-csrf-token";

/// Rejects non-safe methods without a valid token and same-origin browser metadata.
pub(crate) async fn middleware(
    State(state): State<WebState>,
    request: Request,
    next: Next,
) -> Response {
    if matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) {
        return next.run(request).await;
    }
    let Some(id) = SessionStore::id_from_headers(request.headers(), state.cookie_security()) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let Some(session) = state.sessions().peek(&id).await else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let token_valid = request
        .headers()
        .get(HEADER_NAME)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|presented| {
            bool::from(session.csrf_token().as_bytes().ct_eq(presented.as_bytes()))
        });
    if !token_valid || !same_origin(&state, &request) {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(request).await
}

/// Whether Origin and Fetch Metadata identify a same-origin browser request.
fn same_origin(state: &WebState, request: &Request) -> bool {
    let mut origins = request.headers().get_all(header::ORIGIN).iter();
    let origin_valid = origins.next().is_some_and(|value| {
        origins.next().is_none()
            && value.to_str().is_ok_and(|origin| {
                state
                    .allowed_origins()
                    .iter()
                    .any(|allowed| allowed == origin)
            })
    });
    let fetch_site_valid = request
        .headers()
        .get("sec-fetch-site")
        .is_none_or(|value| value == "same-origin");
    origin_valid && fetch_site_valid
}
