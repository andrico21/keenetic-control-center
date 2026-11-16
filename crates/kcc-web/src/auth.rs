//! Login, logout, and self-service account handlers.

extern crate alloc;

use alloc::sync::Arc;
use core::{
    error::Error,
    fmt::{self, Display},
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
};

use askama::Template;
use axum::{
    Extension, Form,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Redirect, Response},
};
use kcc_app::{
    accounts::{AccountError, Authentication, INVALID_USERNAME_ACTOR, validate_username},
    audit::{Actor, ActorKind, AuditError, AuditEvent, receipt::LOGIN_AUDIT_WAIT},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use rmcp_server_kit::transport::ClientIp;
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::Value;
use tokio::task::spawn_blocking;

use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser, PASSWORD_CHANGE_PAGE},
    errors,
    overview::masthead,
    page::{Localize as _, Shell},
    page_kit::respond,
    prefs,
    session::{SessionId, SessionStore, account::SignedIn},
};

/// Monotonic correlation id source for Web audit events.
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Login form boundary.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoginForm {
    /// Account name.
    username: String,
    /// Plaintext password, immediately moved into `SecretString`.
    password: String,
}

impl fmt::Debug for LoginForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            username,
            password: _,
        } = self;
        f.debug_struct("LoginForm")
            .field("username", username)
            .field("password", &"[redacted]")
            .finish()
    }
}

/// Own-password change form boundary.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PasswordForm {
    /// Current password required for reauthentication.
    current_password: String,
    /// Replacement password.
    new_password: String,
}

impl fmt::Debug for PasswordForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            current_password: _,
            new_password: _,
        } = self;
        f.debug_struct("PasswordForm")
            .field("current_password", &"[redacted]")
            .field("new_password", &"[redacted]")
            .finish()
    }
}

/// A refused sign-in: the browser's session, where it came from, and the name it gave.
struct Failed {
    /// Session cookie the browser sent.
    id: Option<SessionId>,
    /// Client address the kit resolved for the request.
    client: Option<IpAddr>,
    /// Submitted name, or the fixed marker for an invalid one.
    username: String,
}

impl Failed {
    /// The sign-in `username` refused for the browser holding `id` at `client`.
    const fn new(id: Option<SessionId>, client: Option<IpAddr>, username: String) -> Self {
        Self {
            id,
            client,
            username,
        }
    }
}

/// The account page after an own password change, with its saved notice.
const ACCOUNT_SAVED: &str = "/ui/account?saved=true";

/// Account page query.
#[derive(Debug, Deserialize)]
pub(crate) struct AccountQuery {
    /// Whether to show the saved notice of the change that led here.
    #[serde(default)]
    saved: bool,
}

/// Account-locale form boundary.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocaleForm {
    /// Supported BCP 47 language tag.
    locale: String,
}

/// Login page or first-run instruction page.
#[derive(Template)]
#[template(path = "pages/login.html")]
struct LoginPage {
    /// Page shell.
    shell: Shell,
    /// Whether first-run setup is required.
    no_admin: bool,
    /// Uniform credential error.
    error: String,
    /// Re-rendered account name.
    username: String,
}

localized!(LoginPage);

/// Self-service account page.
#[derive(Template)]
#[template(path = "pages/account.html")]
struct AccountPage {
    /// Page shell.
    shell: Shell,
    /// Signed-in account name.
    username: String,
    /// Whether the preceding update succeeded.
    saved: bool,
    /// Whether the account must choose a new password before anything else.
    password_required: bool,
    /// Uniform password-change error.
    error: String,
}

localized!(AccountPage);

/// `GET /ui/login`: renders login or the closed first-run instruction.
pub(crate) async fn login_page(
    State(state): State<WebState>,
    client: Option<Extension<ClientIp>>,
    headers: HeaderMap,
) -> Response {
    let has_admin = match has_admin(&state).await {
        Ok(value) => value,
        Err(error) => return internal(error),
    };
    let existing = SessionStore::id_from_headers(&headers, state.cookie_security());
    let session = match existing.as_ref() {
        Some(id) => state
            .sessions()
            .peek(id)
            .await
            .map(|stored| (id.clone(), stored)),
        None => None,
    };
    let (id, anonymous) = match session {
        Some(value) => value,
        None => match state
            .sessions()
            .create_anonymous(client.map(|Extension(resolved)| resolved.ip))
            .await
        {
            Ok(value) => value,
            Err(error) => return internal(error),
        },
    };
    let shell = prefs::shell(&headers, state.default_locale())
        .with_csrf_token(anonymous.csrf_token().to_owned());
    let mut response = errors::render(&LoginPage {
        shell,
        no_admin: !has_admin,
        error: String::new(),
        username: String::new(),
    });
    if let Err(error) = set_session_cookie(&mut response, &state, &id) {
        return internal(error);
    }
    response
}

/// `POST /ui/login`: verifies credentials off the async runtime and rotates the id.
pub(crate) async fn login(
    State(state): State<WebState>,
    client: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let old_id = SessionStore::id_from_headers(&headers, state.cookie_security());
    let username = match validate_username(&form.username) {
        Ok(()) => form.username,
        Err(_invalid) => INVALID_USERNAME_ACTOR.to_owned(),
    };
    let password = SecretString::from(form.password);
    let accounts = Arc::clone(state.accounts());
    let auth_username = username.clone();
    let reading = state.sessions().reading_account().await;
    let checked = spawn_blocking(move || {
        let fingerprint = accounts.fingerprint(&auth_username)?;
        accounts
            .authenticate(&auth_username, &password)
            .map(|authentication| (authentication, fingerprint))
    })
    .await;
    let (authentication, fingerprint) = match checked {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => return internal(error),
        Err(error) => return internal(error),
    };
    match authentication {
        Authentication::Authenticated { role, locale } => {
            let Some(resolved_role) = state.role(&role) else {
                return internal("account role is not configured");
            };
            let resolved_locale =
                Locale::from_tag(&locale).unwrap_or_else(|| state.default_locale());
            let account = SignedIn::new(username.clone(), resolved_role, fingerprint);
            let signed_in = state
                .sessions()
                .login(old_id.as_ref(), account, resolved_locale)
                .await;
            drop(reading);
            let (id, _session) = match signed_in {
                Ok(value) => value,
                Err(error) => return internal(error),
            };
            if let Err(error) = audit_login(&state, &username).await {
                state.sessions().invalidate(&id).await;
                return internal(error);
            }
            let landing = match password_change_required(&state, &username).await {
                Ok(true) => {
                    state.sessions().require_password_change(&id).await;
                    PASSWORD_CHANGE_PAGE
                }
                Ok(false) => "/ui/",
                Err(error) => {
                    state.sessions().invalidate(&id).await;
                    return internal(error);
                }
            };
            let mut response = go_to(&headers, landing);
            if let Err(error) = set_session_cookie(&mut response, &state, &id) {
                return internal(error);
            }
            response
        }
        Authentication::Invalid | Authentication::Disabled => {
            drop(reading);
            let failed = Failed::new(
                old_id,
                client.map(|Extension(resolved)| resolved.ip),
                username,
            );
            login_failure(&state, &headers, failed, "invalid").await
        }
        Authentication::Locked { until: _ } => {
            drop(reading);
            let failed = Failed::new(
                old_id,
                client.map(|Extension(resolved)| resolved.ip),
                username,
            );
            login_failure(&state, &headers, failed, "locked").await
        }
        _ => internal("unsupported authentication result"),
    }
}

/// `POST /ui/logout`: invalidates server-side state before deleting the cookie.
pub(crate) async fn logout(
    State(state): State<WebState>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    state.sessions().invalidate(current.id()).await;
    if let Err(error) = audit(&state, user.username(), "web.logout", "success").await {
        return internal(error);
    }
    let mut response = go_to(&headers, "/ui/login");
    let cookie = state.cookie_security().clear_cookie();
    match header::HeaderValue::from_str(&cookie) {
        Ok(value) => {
            drop(response.headers_mut().insert(header::SET_COOKIE, value));
            response
        }
        Err(error) => internal(error),
    }
}

/// `GET /ui/account`: renders current locale and password form.
pub(crate) async fn account_page(
    State(state): State<WebState>,
    Query(query): Query<AccountQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    account_response(&state, &headers, &current, &user, query.saved, None).await
}

/// `POST /ui/account/password`: verifies current password and ends other sessions.
pub(crate) async fn change_password(
    State(state): State<WebState>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
    Form(form): Form<PasswordForm>,
) -> Response {
    let accounts = Arc::clone(state.accounts());
    let username = user.username().to_owned();
    let auth_username = username.clone();
    let current_password = SecretString::from(form.current_password);
    let new_password = SecretString::from(form.new_password);
    let reading = state.sessions().reading_account().await;
    let changed = spawn_blocking(move || {
        accounts.change_password_for_session(&auth_username, &current_password, &new_password)
    })
    .await;
    if let Ok(Ok((_, Some(fingerprint)))) = &changed {
        state
            .sessions()
            .set_fingerprint(current.id(), *fingerprint)
            .await;
    }
    drop(reading);
    let authentication = match changed {
        Ok(Ok((value, _fingerprint))) => value,
        Ok(Err(AccountError::InvalidPasswordLength)) => {
            let error = Some(keys::WEB_ADMIN_ERROR_PASSWORD_LENGTH);
            return account_response(&state, &headers, &current, &user, false, error).await;
        }
        Ok(Err(AccountError::PasswordEqualsUsername)) => {
            let error = Some(keys::WEB_ADMIN_ERROR_PASSWORD_USERNAME);
            return account_response(&state, &headers, &current, &user, false, error).await;
        }
        Ok(Err(error)) => return internal(error),
        Err(error) => return internal(error),
    };
    match authentication {
        Authentication::Authenticated { role: _, locale: _ } => {
            let landing = if current.session().password_change_required() {
                respond::open("/ui/")
            } else {
                go_to(&headers, ACCOUNT_SAVED)
            };
            finish_change(&state, &current, &user, landing).await
        }
        Authentication::Invalid
        | Authentication::Disabled
        | Authentication::Locked { until: _ } => {
            if let Err(error) = audit(&state, &username, "web.password_change", "failure").await {
                return internal(error);
            }
            let error = Some(keys::ERRORS_AUTH_FAILED);
            account_response(&state, &headers, &current, &user, false, error).await
        }
        _ => internal("unsupported authentication result"),
    }
}

/// `POST /ui/account/locale`: persists a supported locale for the signed-in account and
/// gives it to the account's live sessions, so the next page renders in it.
pub(crate) async fn change_locale(
    State(state): State<WebState>,
    headers: HeaderMap,
    current: CurrentSession,
    mut user: CurrentUser,
    Form(form): Form<LocaleForm>,
) -> Response {
    let Some(locale) = Locale::from_tag(&form.locale) else {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    };
    let accounts = Arc::clone(state.accounts());
    let username = user.username().to_owned();
    let auth_username = username.clone();
    let tag = locale.tag().to_owned();
    match spawn_blocking(move || accounts.set_locale(&auth_username, tag)).await {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => return StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => return internal(error),
        Err(error) => return internal(error),
    }
    state.sessions().set_user_locale(&username, locale).await;
    user.set_locale(locale);
    account_response(&state, &headers, &current, &user, true, None).await
}

/// Renders the uniform login failure, in the page's language, and audits only stable
/// metadata. It answers 422, the status the page script swaps in for a refused form.
async fn login_failure(
    state: &WebState,
    headers: &HeaderMap,
    failed: Failed,
    outcome: &'static str,
) -> Response {
    let Failed {
        id,
        client,
        username,
    } = failed;
    if let Err(error) = audit(state, &username, "web.login", outcome).await {
        return internal(error);
    }
    let session = match id.as_ref() {
        Some(value) => state.sessions().peek(value).await,
        None => None,
    };
    let (active_id, anonymous) = match (id, session) {
        (Some(value), Some(active)) => (value, active),
        (Some(_) | None, Some(_) | None) => match state.sessions().create_anonymous(client).await {
            Ok(value) => value,
            Err(error) => return internal(error),
        },
    };
    let shown = if username == INVALID_USERNAME_ACTOR {
        String::new()
    } else {
        username
    };
    let shell = prefs::shell(headers, state.default_locale())
        .with_csrf_token(anonymous.csrf_token().to_owned());
    let refusal = tr(shell.locale(), keys::ERRORS_AUTH_FAILED, None);
    let mut response = (
        StatusCode::UNPROCESSABLE_ENTITY,
        errors::render(&LoginPage {
            shell,
            no_admin: false,
            error: refusal,
            username: shown,
        }),
    )
        .into_response();
    if let Err(error) = set_session_cookie(&mut response, state, &active_id) {
        return internal(error);
    }
    response
}

/// Reads the first-run state away from the async executor.
///
/// # Errors
///
/// Returns account-storage or blocking-task failures.
async fn has_admin(state: &WebState) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let accounts = Arc::clone(state.accounts());
    spawn_blocking(move || accounts.has_admin())
        .await
        .map_err(Box::<dyn Error + Send + Sync>::from)?
        .map_err(Box::<dyn Error + Send + Sync>::from)
}

/// Reads whether `username` must choose a new password, away from the async executor.
///
/// # Errors
///
/// Returns account-storage or blocking-task failures.
async fn password_change_required(
    state: &WebState,
    username: &str,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let accounts = Arc::clone(state.accounts());
    let name = username.to_owned();
    let summaries = spawn_blocking(move || accounts.list())
        .await
        .map_err(Box::<dyn Error + Send + Sync>::from)?
        .map_err(Box::<dyn Error + Send + Sync>::from)?;
    Ok(summaries
        .iter()
        .any(|summary| summary.username == name && summary.must_change_password))
}

/// Completes a successful own password change.
///
/// The session moves to a new id and CSRF token (no longer restricted to the
/// password-change page), the user's other sessions end, and the browser loads `landing`
/// in full with the new cookie, so the page's CSRF token is the new one too.
// NOT cancel-safe: the session rotation and the audit append are not undone.
async fn finish_change(
    state: &WebState,
    current: &CurrentSession,
    user: &CurrentUser,
    landing: Response,
) -> Response {
    let rotated = match state
        .sessions()
        .rotate_privilege(current.id(), user.role().clone())
        .await
    {
        Ok(Some((id, _session))) => id,
        Ok(None) => return Redirect::to("/ui/login").into_response(),
        Err(error) => return internal(error),
    };
    if let Err(error) = audit(state, user.username(), "web.password_change", "success").await {
        return internal(error);
    }
    let mut response = landing;
    if let Err(error) = set_session_cookie(&mut response, state, &rotated) {
        return internal(error);
    }
    response
}

/// Appends one authentication event with no credential-bearing parameters.
///
/// # Errors
///
/// Returns audit-writer failures.
async fn audit(
    state: &WebState,
    username: &str,
    action: &'static str,
    outcome: &'static str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    state
        .audit()
        .append(event(state, username, action, outcome))
        .await
        .map(|_entry| ())
        .map_err(Box::<dyn Error + Send + Sync>::from)
}

/// Records a successful sign-in, waiting at most [`LOGIN_AUDIT_WAIT`] for the entry: one
/// still queued behind another process's append lock is written later, and the user is
/// signed in meanwhile.
///
/// # Errors
///
/// Returns the audit writer's failure.
// NOT cancel-safe: once queued, the entry is written even if the sign-in stops waiting.
async fn audit_login(state: &WebState, username: &str) -> Result<(), AuditError> {
    let mut queued = state
        .audit()
        .submit(event(state, username, "web.login", "success"))
        .await?;
    match queued.wait(LOGIN_AUDIT_WAIT).await {
        Ok(_) | Err(AuditError::Pending) => Ok(()),
        Err(error) => Err(error),
    }
}

/// The Web audit event of `username`'s `action`, ended as `outcome`.
fn event(
    state: &WebState,
    username: &str,
    action: &'static str,
    outcome: &'static str,
) -> AuditEvent {
    AuditEvent::new(
        state.unix_seconds(),
        Actor::new(ActorKind::Web, username.to_owned()),
        action.to_owned(),
    )
    .with_params(Value::Null)
    .with_result(outcome.to_owned(), request_id())
}

/// A new correlation id for one Web audit event.
pub(crate) fn request_id() -> String {
    format!("web-{}", NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed))
}

/// Renders the account page with the current session's CSRF token and the fleet switcher.
// cancel-safe: reads only.
async fn account_response(
    state: &WebState,
    headers: &HeaderMap,
    current: &CurrentSession,
    user: &CurrentUser,
    saved: bool,
    error: Option<MessageKey>,
) -> Response {
    let shell = prefs::shell_for_locale(headers, user.locale())
        .with_csrf_token(current.session().csrf_token().to_owned())
        .with_fleet(masthead(state, user.role(), None).await, None);
    errors::render(&AccountPage {
        shell,
        username: user.username().to_owned(),
        saved,
        password_required: current.session().password_change_required(),
        error: error.map_or_else(String::new, |key| tr(user.locale(), key, None)),
    })
}

/// Sends the browser to `href` after signing in or out.
///
/// An htmx request gets a whole page load (`HX-Redirect`), because swapping only the body
/// would keep the old page's CSRF token in its head; anything else gets a 303.
fn go_to(headers: &HeaderMap, href: &str) -> Response {
    if headers.contains_key("hx-request") {
        respond::open(href)
    } else {
        Redirect::to(href).into_response()
    }
}

/// Attaches the transport-appropriate session cookie.
///
/// # Errors
///
/// Returns an invalid-header error only if the cookie contract regresses.
fn set_session_cookie(
    response: &mut Response,
    state: &WebState,
    id: &SessionId,
) -> Result<(), header::InvalidHeaderValue> {
    let value = SessionStore::cookie_header(state.cookie_security(), id)?;
    drop(response.headers_mut().insert(header::SET_COOKIE, value));
    Ok(())
}

/// Logs an internal cause and returns the generic localized 500 response.
fn internal(error: impl Display) -> Response {
    tracing::error!(%error, "web authentication request failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test assertions are not rendered API documentation"
)]
mod tests {
    use super::{LoginForm, PasswordForm};

    #[test]
    fn login_form_debug_redacts_password() {
        let password = ["runtime", "login", "secret"].join("-");
        let form = LoginForm {
            username: "alice".to_owned(),
            password: password.clone(),
        };

        let debug = format!("{form:?}");

        assert!(!debug.contains(&password), "Debug must omit the password");
    }

    #[test]
    fn password_form_debug_redacts_both_passwords() {
        let current_password = ["runtime", "current", "secret"].join("-");
        let new_password = ["runtime", "replacement", "secret"].join("-");
        let form = PasswordForm {
            current_password: current_password.clone(),
            new_password: new_password.clone(),
        };

        let debug = format!("{form:?}");

        assert!(
            !debug.contains(&current_password),
            "Debug must omit the current password"
        );
        assert!(
            !debug.contains(&new_password),
            "Debug must omit the replacement password"
        );
    }
}
