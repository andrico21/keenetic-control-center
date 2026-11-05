//! Three-phase ndw4 mutual authentication over header-carried replies.

use alloc::sync::Arc;
use core::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::{Client, Response, StatusCode, header};
use serde::Serialize;
use subtle::ConstantTimeEq as _;
use tokio::sync::Mutex;

use crate::{
    AuthError, RciError,
    auth::{Credentials, Ndw4Challenge},
    ndw4_keys::{Keys, Parameters},
    ndw4_reply::Reply,
    session::{Session, parse_set_cookie},
};

/// One cached parameter set; its manager binds the router, login, and password.
#[derive(Debug, Default)]
pub(crate) struct Cache(Mutex<Option<(Parameters, Arc<Keys>)>>);

/// Borrowed transport and identity for an exchange.
pub(crate) struct Exchange<'session> {
    /// Redirect-disabled manager client.
    pub client: &'session Client,
    /// Validated router origin.
    pub origin: &'session str,
    /// Immutable manager credentials.
    pub credentials: &'session Credentials,
    /// Local memory ceiling.
    pub memory_cap: u32,
    /// Keys bound to this manager's router and credentials.
    pub cache: &'session Cache,
}

impl fmt::Debug for Exchange<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            client: _,
            origin: _,
            credentials: _,
            memory_cap,
            cache: _,
        } = self;
        f.debug_struct("Exchange")
            .field("memory_cap", memory_cap)
            .finish_non_exhaustive()
    }
}

/// Every phase has a login and nonce; proof fields are mutually exclusive on the wire.
#[derive(Serialize)]
struct Phase<'value> {
    /// Account name.
    login: &'value str,
    /// Client or combined nonce.
    nonce: &'value str,
    /// Client proof in phase two.
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<&'value str>,
    /// Signature confirmation in phase three.
    #[serde(rename = "signature-proof", skip_serializing_if = "Option::is_none")]
    signature_proof: Option<&'value str>,
}

impl Exchange<'_> {
    /// Authenticates, verifying the server before sending the final confirmation.
    ///
    /// # Errors
    /// Returns typed rejection, cost, signature, or transport errors.
    // NOT cancel-safe: cancellation may leave a remote handshake; no local session is published until verified.
    pub(crate) async fn authenticate(
        &self,
        challenge: &Ndw4Challenge,
        initial: &Response,
    ) -> Result<Session, RciError> {
        if !challenge.endpoint.starts_with('/')
            || challenge.endpoint.starts_with("//")
            || challenge.endpoint.contains(['\\', '#'])
        {
            return Err(RciError::Auth(AuthError::Rejected));
        }
        let url = format!("{}{}", self.origin, challenge.endpoint);
        let mut pending = parse_set_cookie(initial.headers(), None)?.map(Session::from);
        let mut nonce_bytes = [0_u8; 16];
        getrandom::getrandom(&mut nonce_bytes).map_err(|_error| RciError::Transport)?;
        let client_nonce = STANDARD.encode(nonce_bytes);
        let login = self.credentials.login.as_str();
        let first = self
            .post(
                &url,
                &Phase {
                    login,
                    nonce: &client_nonce,
                    proof: None,
                    signature_proof: None,
                },
                &mut pending,
            )
            .await?;
        let parsed =
            Reply::decode(first.headers())?.challenge(login, &client_nonce, self.memory_cap)?;
        let keys = {
            let mut cached = self.cache.0.lock().await;
            let keys = match cached.as_ref() {
                Some((parameters, keys)) if *parameters == parsed.parameters => Arc::clone(keys),
                Some(_) | None => {
                    let derived =
                        Arc::new(Keys::derive(self.credentials, parsed.parameters).await?);
                    *cached = Some((parsed.parameters, Arc::clone(&derived)));
                    derived
                }
            };
            drop(cached);
            keys
        };
        let proof = keys.proof(&parsed.message)?;
        let second = self
            .post(
                &url,
                &Phase {
                    login,
                    nonce: &parsed.nonce,
                    proof: Some(&proof),
                    signature_proof: None,
                },
                &mut pending,
            )
            .await?;
        let signature = Reply::decode(second.headers())?.signature()?;
        let decoded = STANDARD
            .decode(&signature)
            .map_err(|_error| RciError::Auth(AuthError::ServerSignatureMismatch))?;
        let expected = keys.signature(&parsed.message)?;
        if !bool::from(expected.as_slice().ct_eq(&decoded)) {
            return Err(RciError::Auth(AuthError::ServerSignatureMismatch));
        }
        let confirmation = keys.proof(&format!("{};signature4={signature}", parsed.message))?;
        let third = self
            .post(
                &url,
                &Phase {
                    login,
                    nonce: &parsed.nonce,
                    proof: None,
                    signature_proof: Some(&confirmation),
                },
                &mut pending,
            )
            .await?;
        if third.headers().contains_key("x-ndm-data") {
            drop(Reply::decode(third.headers())?);
        }
        if third.status() != StatusCode::OK {
            return Err(RciError::Auth(AuthError::Rejected));
        }
        let mut session = pending.ok_or(RciError::Auth(AuthError::Rejected))?;
        let check = self
            .client
            .get(format!("{}/auth", self.origin))
            .header(header::COOKIE, session.header_value()?)
            .send()
            .await
            .map_err(|_error| RciError::Transport)?;
        if check.status() != StatusCode::OK {
            return Err(RciError::Auth(AuthError::Rejected));
        }
        session.refresh_from_headers(check.headers())?;
        Ok(session)
    }

    /// Sends one phase and carries forward any refreshed session cookie.
    ///
    /// # Errors
    /// Returns transport or malformed-cookie errors.
    // NOT cancel-safe: a phase may be processed before cancellation.
    async fn post(
        &self,
        url: &str,
        phase: &Phase<'_>,
        pending: &mut Option<Session>,
    ) -> Result<Response, RciError> {
        let mut request = self.client.post(url).json(phase);
        if let Some(session) = pending.as_ref() {
            request = request.header(header::COOKIE, session.header_value()?);
        }
        let response = request.send().await.map_err(|_error| RciError::Transport)?;
        match pending {
            Some(session) => session.refresh_from_headers(response.headers())?,
            None => *pending = parse_set_cookie(response.headers(), None)?.map(Session::from),
        }
        Ok(response)
    }
}
