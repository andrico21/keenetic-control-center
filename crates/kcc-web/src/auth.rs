//! Login, logout, and self-service account handlers.

extern crate alloc;

use alloc::sync::Arc;
use core::{
    error::Error,
    fmt::Display,
    sync::atomic::{AtomicU64, Ordering},
};

use askama::Template;
use axum::{
    Form,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Redirect, Response},
};
use kcc_app::{
    accounts::{AccountError, Authentication},
    audit::{Actor, ActorKind, AuditEvent},
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::Value;
use tokio::task::spawn_blocking;

use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    page::{Localize, Shell},
    prefs,
    session::{SessionId, SessionStore},
};

/// Monotonic correlation id source for Web audit events.
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Login form boundary.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoginForm {
    /// Account name.
    username: String,
    /// Plaintext password, immediately moved into `SecretString`.
    password: String,
}

/// Own-password change form boundary.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PasswordForm {
    /// Current password required for reauthentication.
    current_password: String,
    /// Replacement password.
    new_password: String,
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

impl Localize for LoginPage {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

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
    /// Uniform password-change error.
    error: String,
}

impl Localize for AccountPage {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// `GET /ui/login`: renders login or the closed first-run instruction.
pub(crate) async fn login_page(State(state): State<WebState>, headers: HeaderMap) -> Response {
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
        None => match state.sessions().create_anonymous().await {
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
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let old_id = SessionStore::id_from_headers(&headers, state.cookie_security());
    let username = form.username;
    let password = SecretString::from(form.password);
    let accounts = Arc::clone(state.accounts());
    let auth_username = username.clone();
    let authentication =
        match spawn_blocking(move || accounts.authenticate(&auth_username, &password)).await {
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
            let (id, _session) = match state
                .sessions()
                .login(
                    old_id.as_ref(),
                    username.clone(),
                    resolved_role,
                    resolved_locale,
                )
                .await
            {
                Ok(value) => value,
                Err(error) => return internal(error),
            };
            if let Err(error) = audit(&state, &username, "web.login", "success").await {
                state.sessions().invalidate(&id).await;
                return internal(error);
            }
            let mut response = Redirect::to("/ui/").into_response();
            if let Err(error) = set_session_cookie(&mut response, &state, &id) {
                return internal(error);
            }
            response
        }
        Authentication::Invalid | Authentication::Disabled => {
            login_failure(&state, &headers, old_id, username, "invalid").await
        }
        Authentication::Locked { until: _ } => {
            login_failure(&state, &headers, old_id, username, "locked").await
        }
        _ => internal("unsupported authentication result"),
    }
}

/// `POST /ui/logout`: invalidates server-side state before deleting the cookie.
pub(crate) async fn logout(
    State(state): State<WebState>,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    state.sessions().invalidate(current.id()).await;
    if let Err(error) = audit(&state, user.username(), "web.logout", "success").await {
        return internal(error);
    }
    let mut response = Redirect::to("/ui/login").into_response();
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
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    account_response(&state, &headers, &current, &user, false, false)
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
    let authentication = match spawn_blocking(move || {
        accounts.change_password(&auth_username, &current_password, &new_password)
    })
    .await
    {
        Ok(Ok(value)) => value,
        Ok(Err(AccountError::InvalidPasswordLength | AccountError::PasswordEqualsUsername)) => {
            return account_response(&state, &headers, &current, &user, false, true);
        }
        Ok(Err(error)) => return internal(error),
        Err(error) => return internal(error),
    };
    match authentication {
        Authentication::Authenticated { role: _, locale: _ } => {
            state
                .sessions()
                .invalidate_other_user_sessions(&username, current.id())
                .await;
            if let Err(error) = audit(&state, &username, "web.password_change", "success").await {
                return internal(error);
            }
            account_response(&state, &headers, &current, &user, true, false)
        }
        Authentication::Invalid
        | Authentication::Disabled
        | Authentication::Locked { until: _ } => {
            if let Err(error) = audit(&state, &username, "web.password_change", "failure").await {
                return internal(error);
            }
            account_response(&state, &headers, &current, &user, false, true)
        }
        _ => internal("unsupported authentication result"),
    }
}

/// `POST /ui/account/locale`: persists a supported locale.
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
    user.set_locale(locale);
    account_response(&state, &headers, &current, &user, true, false)
}

/// Renders the uniform login failure and audits only stable metadata.
async fn login_failure(
    state: &WebState,
    headers: &HeaderMap,
    id: Option<SessionId>,
    username: String,
    outcome: &'static str,
) -> Response {
    if let Err(error) = audit(state, &username, "web.login", outcome).await {
        return internal(error);
    }
    let session = match id.as_ref() {
        Some(value) => state.sessions().peek(value).await,
        None => None,
    };
    let (active_id, anonymous) = match (id, session) {
        (Some(value), Some(active)) => (value, active),
        (Some(_) | None, Some(_) | None) => match state.sessions().create_anonymous().await {
            Ok(value) => value,
            Err(error) => return internal(error),
        },
    };
    let shell = prefs::shell(headers, state.default_locale())
        .with_csrf_token(anonymous.csrf_token().to_owned());
    let mut response = (
        StatusCode::UNAUTHORIZED,
        errors::render(&LoginPage {
            shell,
            no_admin: false,
            error: tr(state.default_locale(), keys::ERRORS_AUTH_FAILED, None),
            username,
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
    let request_id = format!("web-{}", NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed));
    let event = AuditEvent::new(
        state.unix_seconds(),
        Actor::new(ActorKind::Web, username.to_owned()),
        action.to_owned(),
    )
    .with_params(Value::Null)
    .with_result(outcome.to_owned(), request_id);
    state
        .audit()
        .append(event)
        .await
        .map(|_entry| ())
        .map_err(Box::<dyn Error + Send + Sync>::from)
}

/// Renders the account page with the current session's CSRF token.
fn account_response(
    _state: &WebState,
    headers: &HeaderMap,
    current: &CurrentSession,
    user: &CurrentUser,
    saved: bool,
    failed: bool,
) -> Response {
    let shell = prefs::shell_for_locale(headers, user.locale())
        .with_csrf_token(current.session().csrf_token().to_owned());
    errors::render(&AccountPage {
        shell,
        username: user.username().to_owned(),
        saved,
        error: if failed {
            tr(user.locale(), keys::ERRORS_AUTH_FAILED, None)
        } else {
            String::new()
        },
    })
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
