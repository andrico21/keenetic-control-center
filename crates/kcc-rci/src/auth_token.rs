//! Experimental token authentication without an `/auth` handshake.

use reqwest::{RequestBuilder, Response, StatusCode, header::HeaderValue};
use secrecy::{ExposeSecret as _, SecretString};

use crate::{AuthError, RciError, session::map_reqwest_error};

/// Sends a token as a sensitive header, preserving a 401 for policy-controlled fallback.
///
/// # Errors
/// Returns transport errors or invalid token-header errors.
// NOT cancel-safe: a mutating request may complete remotely before cancellation.
pub(crate) async fn send(
    request: RequestBuilder,
    token: &SecretString,
) -> Result<Response, RciError> {
    let mut value = HeaderValue::from_str(token.expose_secret())
        .map_err(|_error| RciError::Auth(AuthError::TokenRejected))?;
    value.set_sensitive(true);
    let response = request
        .header("x-ndma-tkn", value)
        .send()
        .await
        .map_err(|error| map_reqwest_error(&error))?;
    Ok(response)
}

/// Maps a token rejection without exposing the token or router response.
///
/// # Errors
/// Returns [`AuthError::TokenRejected`] for HTTP 401.
pub(crate) fn accepted(response: Response) -> Result<Response, RciError> {
    if response.status() == StatusCode::UNAUTHORIZED {
        Err(RciError::Auth(AuthError::TokenRejected))
    } else {
        Ok(response)
    }
}
