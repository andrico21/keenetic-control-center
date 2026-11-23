//! `POST /oauth/token`: the authorization code with its PKCE verifier and resource, and
//! the refresh token with rotation. Every answer is `no-store`.

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::{fmt::Display, time::Duration};

use axum::{
    Json,
    extract::State,
    http::{HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use kcc_app::{
    accounts::{AccountStore, standing::PasswordFingerprint},
    audit::{Actor, ActorKind, AuditError, AuditEvent, receipt::AUDIT_WAIT, request_id},
    mcp_auth::{
        grants::{Grant, GrantError, IssuedGrant, RefreshRequest},
        pending::CodeTarget,
        signing::{AccessClaims, Validity},
    },
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use tokio::task::spawn_blocking;

use super::{Active, OAuthServer, absent, authorize::SCOPE, serving, single_params};
use crate::WebState;

/// A token endpoint refusal: its status and RFC 6749 error code.
type Refused = (StatusCode, &'static str);

/// `POST /oauth/token`.
// NOT cancel-safe: the exchange runs on a blocking thread that completes on its own; its
// audit entry may be written after the future is dropped.
pub(crate) async fn token(State(state): State<WebState>, body: String) -> Response {
    let Some((server, active)) = serving(&state) else {
        return absent();
    };
    let Some(params) = single_params(&body) else {
        return refused((StatusCode::BAD_REQUEST, "invalid_request"));
    };
    let accounts = Arc::clone(state.accounts());
    let exchanged = spawn_blocking(move || exchange(&server, &active, &accounts, &params)).await;
    let (issued, account, grant_type) = match exchanged {
        Ok(Ok(Exchanged::Issued(issued))) => *issued,
        Ok(Ok(Exchanged::Reused { client })) => {
            let event = event(
                &state,
                ("oauth".to_owned(), "mcp.oauth_refresh_reuse"),
                json!({"client": client}),
            )
            .with_result("refused".to_owned(), request_id::next("mcp"));
            drop(written(&state, event).await);
            return refused((StatusCode::BAD_REQUEST, "invalid_grant"));
        }
        Ok(Err(refusal)) => return refused(refusal),
        Err(error) => {
            tracing::error!(%error, "the token exchange task failed");
            return refused((StatusCode::INTERNAL_SERVER_ERROR, "server_error"));
        }
    };
    let fields = json!({
        "client": issued.grant.client(),
        "grant": issued.grant.id(),
        "grant_type": grant_type,
    });
    let event = event(
        &state,
        (format!("oauth:{account}"), "mcp.oauth_token_issued"),
        fields,
    )
    .with_result("success".to_owned(), request_id::next("mcp"));
    if let Err(error) = written(&state, event).await {
        tracing::error!(%error, "the token issuance could not be audited");
        return refused((StatusCode::INTERNAL_SERVER_ERROR, "server_error"));
    }
    no_store(
        StatusCode::OK,
        json!({
            "access_token": issued.access.expose_secret(),
            "token_type": "Bearer",
            "expires_in": issued.lifetime.as_secs(),
            "refresh_token": issued.refresh.expose_secret(),
            "scope": SCOPE,
        }),
    )
}

/// What an exchange produced.
enum Exchanged {
    /// New tokens, for the account, by the grant type.
    Issued(Box<(Tokens, String, &'static str)>),
    /// A rotated refresh token was used again: its family is revoked now.
    Reused {
        /// The client that presented it.
        client: String,
    },
}

/// Newly issued tokens.
struct Tokens {
    /// The grant they belong to.
    grant: Grant,
    /// The access token.
    access: SecretString,
    /// The access token's lifetime.
    lifetime: Duration,
    /// The new refresh token.
    refresh: SecretString,
}

/// Runs one exchange. Blocking.
///
/// # Errors
///
/// The token endpoint refusal.
fn exchange(
    server: &OAuthServer,
    active: &Active,
    accounts: &AccountStore,
    params: &BTreeMap<String, String>,
) -> Result<Exchanged, Refused> {
    let param = |name: &str| params.get(name).map(String::as_str);
    let invalid = (StatusCode::BAD_REQUEST, "invalid_request");
    let client = param("client_id").ok_or(invalid)?;
    let clients = server.clients.document().map_err(|error| {
        tracing::error!(%error, "the OAuth clients cannot be read");
        (StatusCode::INTERNAL_SERVER_ERROR, "server_error")
    })?;
    if clients.client(client).is_none() {
        return Err((StatusCode::UNAUTHORIZED, "invalid_client"));
    }
    if param("scope").is_some_and(|scope| scope.split(' ').any(|token| token != SCOPE)) {
        return Err((StatusCode::BAD_REQUEST, "invalid_scope"));
    }
    if param("resource").is_some_and(|resource| !active.accepts(resource)) {
        return Err((StatusCode::BAD_REQUEST, "invalid_target"));
    }
    let standings = standings(accounts)?;
    let standing = |account: &str| standings.get(account).copied();
    match param("grant_type") {
        Some("authorization_code") => {
            let resource = param("resource").ok_or((StatusCode::BAD_REQUEST, "invalid_target"))?;
            let target = CodeTarget::new(client, param("redirect_uri").ok_or(invalid)?, resource);
            let code = SecretString::from(param("code").ok_or(invalid)?.to_owned());
            let verifier = SecretString::from(param("code_verifier").ok_or(invalid)?.to_owned());
            let grant = (StatusCode::BAD_REQUEST, "invalid_grant");
            let consented = server.consented.take(&code);
            let authorized = server
                .pending
                .redeem(&code, &target, &verifier)
                .map_err(|_refused| grant)?;
            let current = standing(authorized.account()).ok_or(grant)?;
            if consented != Some(current) {
                return Err(grant);
            }
            let issued = active
                .grants
                .issue(&authorized, &current)
                .map_err(|error| refusal_of(&error))?;
            let account = authorized.account().to_owned();
            let tokens = mint(server, active, &issued)?;
            Ok(Exchanged::Issued(Box::new((
                tokens,
                account,
                "authorization_code",
            ))))
        }
        Some("refresh_token") => {
            let token = SecretString::from(param("refresh_token").ok_or(invalid)?.to_owned());
            let request = RefreshRequest::new(&token, client, param("resource"));
            match active.grants.refresh(&request, &standing) {
                Ok(issued) => {
                    if !active.accepts(issued.grant().resource()) {
                        return Err((StatusCode::BAD_REQUEST, "invalid_target"));
                    }
                    let account = issued.grant().account().to_owned();
                    let tokens = mint(server, active, &issued)?;
                    Ok(Exchanged::Issued(Box::new((
                        tokens,
                        account,
                        "refresh_token",
                    ))))
                }
                Err(GrantError::Reused) => Ok(Exchanged::Reused {
                    client: client.to_owned(),
                }),
                Err(error) => Err(refusal_of(&error)),
            }
        }
        Some(_) => Err((StatusCode::BAD_REQUEST, "unsupported_grant_type")),
        None => Err(invalid),
    }
}

/// The fingerprint of every account that may sign in now: enabled, not bound to change
/// its password, with a readable password hash.
///
/// # Errors
///
/// `server_error` when the accounts cannot be read.
fn standings(accounts: &AccountStore) -> Result<BTreeMap<String, PasswordFingerprint>, Refused> {
    let all = accounts.standings().map_err(|error| {
        tracing::error!(%error, "the accounts cannot be read");
        (StatusCode::INTERNAL_SERVER_ERROR, "server_error")
    })?;
    Ok(all
        .into_iter()
        .filter(|(_name, standing)| !standing.disabled && !standing.must_change_password)
        .filter_map(|(name, standing)| standing.fingerprint.map(|fingerprint| (name, fingerprint)))
        .collect())
}

/// The access token of `issued`.
///
/// # Errors
///
/// `server_error` when the signing key is unusable.
fn mint(server: &OAuthServer, active: &Active, issued: &IssuedGrant) -> Result<Tokens, Refused> {
    let unusable = |error: &dyn Display| {
        tracing::error!(%error, "an access token could not be signed");
        (StatusCode::INTERNAL_SERVER_ERROR, "server_error")
    };
    let validity = Validity::new(server.now(), active.access_ttl);
    let claims = AccessClaims::new(server.issuer(), issued.grant(), validity);
    let access = server
        .signing_key()
        .map_err(|error| unusable(&error))?
        .mint_access(&claims)
        .map_err(|error| unusable(&error))?;
    Ok(Tokens {
        grant: issued.grant().clone(),
        access,
        lifetime: active.access_ttl,
        refresh: issued.refresh_token().clone(),
    })
}

/// The token endpoint error of a grant store refusal.
fn refusal_of(error: &GrantError) -> Refused {
    match error {
        GrantError::UnknownClient => (StatusCode::UNAUTHORIZED, "invalid_client"),
        GrantError::Resource => (StatusCode::BAD_REQUEST, "invalid_target"),
        GrantError::State(_) | GrantError::Random(_) => {
            tracing::error!(%error, "the grants cannot be read or written");
            (StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
        GrantError::AccountLimit
        | GrantError::TotalLimit
        | GrantError::Unknown
        | GrantError::Expired
        | GrantError::Revoked
        | GrantError::Reused
        | GrantError::Client
        | GrantError::Account
        | _ => (StatusCode::BAD_REQUEST, "invalid_grant"),
    }
}

/// The MCP audit event `action` of `actor` with `params`, now.
fn event(state: &WebState, (actor, action): (String, &'static str), params: Value) -> AuditEvent {
    AuditEvent::new(
        state.unix_seconds(),
        Actor::new(ActorKind::Mcp, actor),
        action.to_owned(),
    )
    .with_params(params)
}

/// Queues `event` and waits at most [`AUDIT_WAIT`] for it to be written.
///
/// # Errors
///
/// The audit writer's failure, a full queue or an entry still queued at the deadline.
// NOT cancel-safe: once queued, the entry is written even if the caller stops waiting.
async fn written(state: &WebState, event: AuditEvent) -> Result<(), AuditError> {
    state
        .audit()
        .submit_within(event, AUDIT_WAIT)
        .await?
        .wait(AUDIT_WAIT)
        .await
        .map(|_entry| ())
}

/// The refusal `(status, error)` as a `no-store` JSON answer.
fn refused((status, error): Refused) -> Response {
    no_store(status, json!({ "error": error }))
}

/// `body` with `status`, `Cache-Control: no-store` and `Pragma: no-cache`.
pub(crate) fn no_store(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    let headers = response.headers_mut();
    drop(headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store")));
    drop(headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache")));
    drop(headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    ));
    response
}
