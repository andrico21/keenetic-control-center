//! The browser steps of kcc's authorization server: the consent page, its decisions and
//! the error page of a request that cannot go back to its client.
//!
//! Without a session the consent page is the login page carrying the request id. The id
//! travels in the query string and the form body, never in a path: request logs name
//! paths.
//! The consent page shows the client's name marked unverified, the host the browser will
//! be sent to, the account and its role. Approve and deny are htmx POSTs under the
//! session and CSRF rules of every page and answer with `HX-Redirect` to the request's
//! registered redirect URI: `code`, `state` and `iss`, or `error=access_denied`.

extern crate alloc;

use alloc::sync::Arc;

use askama::Template;
use axum::{
    Extension,
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Redirect, Response},
};
use kcc_app::{
    accounts::standing::PasswordFingerprint,
    audit::{Actor, ActorKind, AuditEvent, receipt::AUDIT_WAIT},
};
use kcc_i18n::{bundle::MessageKey, keys};
use rmcp_server_kit::transport::ClientIp;
use secrecy::ExposeSecret as _;
use serde::Deserialize;
use serde_json::json;
use tokio::task::spawn_blocking;
use url::Url;

use crate::{
    WebState, auth,
    authz::{CurrentUser, PASSWORD_CHANGE_PAGE},
    errors::{self, Kind},
    oauth::{authorize::with_query, serving},
    overview::masthead,
    page::{Localize as _, Shell},
    page_kit::{context::fragment_shell, respond},
    prefs,
    session::SessionStore,
};

/// The consent page.
#[derive(Template)]
#[template(path = "pages/oauth_consent.html")]
struct ConsentPage {
    /// Page shell.
    shell: Shell,
    /// The pending request's id.
    id: String,
    /// The client's self-declared name; unverified.
    client: Option<String>,
    /// Where the browser goes after the decision: the redirect URI's host, or its scheme
    /// for a private-use URI.
    host: String,
    /// The MCP server the token is for.
    resource: String,
    /// The signed-in account.
    account: String,
    /// The account's role.
    role: String,
}

localized!(ConsentPage);

/// The pending request a consent page or decision names; empty when absent.
#[derive(Deserialize)]
pub(crate) struct Named {
    /// The pending request's id.
    #[serde(default)]
    request: String,
}

/// A request that cannot be answered at its client.
#[derive(Template)]
#[template(path = "pages/oauth_error.html")]
struct ErrorPage {
    /// Page shell.
    shell: Shell,
    /// What went wrong.
    message: MessageKey,
}

localized!(ErrorPage);

impl ErrorPage {
    /// What went wrong.
    const fn said(&self) -> MessageKey {
        self.message
    }
}

/// A refused decision, shown in the consent page's outcome region.
#[derive(Template)]
#[template(path = "partials/oauth_outcome.html")]
struct Outcome {
    /// Page shell.
    shell: Shell,
    /// What went wrong.
    message: MessageKey,
}

localized!(Outcome);

impl Outcome {
    /// What went wrong.
    const fn said(&self) -> MessageKey {
        self.message
    }
}

/// The error page with `message`, answered with `status`; never a redirect.
pub(crate) fn error_page(shell: Shell, status: StatusCode, message: MessageKey) -> Response {
    (status, errors::render(&ErrorPage { shell, message })).into_response()
}

/// The password fingerprint of `username` when the account may sign in now: it exists,
/// is enabled, need not change its password and has a readable password hash.
// cancel-safe: the account store read runs on a blocking thread; abandoned, it changes nothing.
async fn standing(state: &WebState, username: &str) -> Option<PasswordFingerprint> {
    let accounts = Arc::clone(state.accounts());
    let name = username.to_owned();
    let standings = spawn_blocking(move || accounts.standings())
        .await
        .ok()?
        .ok()?;
    standings
        .get(&name)
        .filter(|standing| !standing.disabled && !standing.must_change_password)
        .and_then(|standing| standing.fingerprint)
}

/// `GET /ui/oauth/consent?request=<id>`: the consent page, or without a session the login
/// page carrying the request id.
// cancel-safe: it only reads; an anonymous session is created whole or not at all.
pub(crate) async fn page(
    State(state): State<WebState>,
    client: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    Query(Named { request: id }): Query<Named>,
) -> Response {
    let shell = prefs::shell(&headers, state.default_locale());
    let Some((server, _active)) = serving(&state) else {
        return errors::response(Kind::NotFound, shell.signed_out());
    };
    let Some(request) = server.pending().peek(&id) else {
        let key = keys::WEB_OAUTH_ERROR_EXPIRED;
        return error_page(shell.signed_out(), StatusCode::BAD_REQUEST, key);
    };
    let signed_in = match SessionStore::id_from_headers(&headers, state.cookie_security()) {
        Some(session) => state.sessions().get(&session).await,
        None => None,
    };
    let Some((session, username, role)) = signed_in.and_then(|session| {
        let username = session.username()?.to_owned();
        let role = state.role(&session.role()?.name)?;
        Some((session, username, role))
    }) else {
        return auth::login_view(&state, client, &headers, Some(id)).await;
    };
    if session.password_change_required() {
        return Redirect::to(PASSWORD_CHANGE_PAGE).into_response();
    }
    let signed = prefs::shell_for_locale(&headers, session.locale())
        .with_csrf_token(session.csrf_token().to_owned())
        .with_fleet(masthead(&state, &role, None).await, None);
    if standing(&state, &username).await.is_none() {
        return error_page(signed, StatusCode::FORBIDDEN, keys::WEB_OAUTH_ERROR_ACCOUNT);
    }
    let clients = Arc::clone(&server);
    let read = spawn_blocking(move || clients.clients().document()).await;
    let Ok(Ok(document)) = read else {
        return errors::internal(&"the OAuth clients cannot be read", signed);
    };
    let name = document
        .client(request.client_id())
        .and_then(|registered| registered.name())
        .map(str::to_owned);
    errors::render(&ConsentPage {
        shell: signed,
        id,
        client: name,
        host: host_of(request.redirect_uri()),
        resource: request.resource().to_owned(),
        account: username,
        role: role.name,
    })
}

/// The host the browser goes to after the decision: the redirect URI's host, or its
/// scheme for a private-use URI without one.
fn host_of(redirect: &str) -> String {
    Url::parse(redirect).map_or_else(
        |_invalid| redirect.to_owned(),
        |url| {
            url.host_str()
                .map_or_else(|| url.scheme().to_owned(), str::to_owned)
        },
    )
}

/// `POST /ui/oauth/consent/approve` with the form field `request`.
// NOT cancel-safe: as `decide`.
pub(crate) async fn approve(
    State(state): State<WebState>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(Named { request: id }): Form<Named>,
) -> Response {
    decide(&state, (&headers, &user), &id, true).await
}

/// `POST /ui/oauth/consent/deny` with the form field `request`.
// NOT cancel-safe: as `decide`.
pub(crate) async fn deny(
    State(state): State<WebState>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(Named { request: id }): Form<Named>,
) -> Response {
    decide(&state, (&headers, &user), &id, false).await
}

/// Approves (`approved`) or denies the pending request `id` as `user`: the request is
/// used up either way; an approval of an account that may not sign in now issues nothing.
// NOT cancel-safe: the request is taken and the decision audited before the answer.
async fn decide(
    state: &WebState,
    (headers, user): (&HeaderMap, &CurrentUser),
    id: &str,
    approved: bool,
) -> Response {
    let refused = |message| {
        let shell = fragment_shell(user.locale());
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            errors::render(&Outcome { shell, message }),
        )
            .into_response()
    };
    let Some((server, active)) = serving(state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(request) = server.pending().take(id) else {
        return refused(keys::WEB_OAUTH_ERROR_EXPIRED);
    };
    let (redirect, client) = (
        request.redirect_uri().to_owned(),
        request.client_id().to_owned(),
    );
    let request_state = request.state().map(str::to_owned);
    let mut pairs = Vec::new();
    let outcome = if !approved {
        pairs.push(("error", "access_denied".to_owned()));
        "denied"
    } else if !active.accepts(request.resource()) {
        pairs.push(("error", "invalid_target".to_owned()));
        "refused"
    } else {
        let Some(fingerprint) = standing(state, user.username()).await else {
            audit(state, user, (&client, "refused")).await;
            return refused(keys::WEB_OAUTH_ERROR_ACCOUNT);
        };
        let Ok(code) = server.pending().issue_code(request, user.username()) else {
            return refused(keys::WEB_OAUTH_ERROR_EXPIRED);
        };
        server.consented().record(&code, fingerprint, server.now());
        pairs.push(("code", code.expose_secret().to_owned()));
        "approved"
    };
    if let Some(value) = request_state {
        pairs.push(("state", value));
    }
    pairs.push(("iss", server.issuer().to_owned()));
    audit(state, user, (&client, outcome)).await;
    let borrowed: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    with_query(&redirect, &borrowed).map_or_else(
        || refused(keys::WEB_OAUTH_ERROR_EXPIRED),
        |target| {
            if headers.contains_key("hx-request") {
                respond::open(&target)
            } else {
                Redirect::to(&target).into_response()
            }
        },
    )
}

/// Audits `user`'s decision on a request of `client` as `outcome`; a failure is logged.
// NOT cancel-safe: once queued, the entry is written even if the request stops waiting.
async fn audit(state: &WebState, user: &CurrentUser, (client, outcome): (&str, &str)) {
    let event = AuditEvent::new(
        state.unix_seconds(),
        Actor::new(ActorKind::Web, user.username().to_owned()),
        "web.oauth_consent".to_owned(),
    )
    .with_params(json!({ "client": client }))
    .with_result(outcome.to_owned(), auth::request_id());
    if let Err(error) = state.audit().submit_within(event, AUDIT_WAIT).await {
        tracing::warn!(%error, "an OAuth consent decision could not be audited");
    }
}
