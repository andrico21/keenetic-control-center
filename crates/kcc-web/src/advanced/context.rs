//! Request context shared by the advanced handlers: the router a request targets, the
//! page shell around it, the catalog facts, and the audit record of every execution.

use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Response},
};
use kcc_app::{
    audit::{Actor, ActorKind, AuditEvent},
    permissions::Permission,
    registry,
};
use kcc_i18n::locale::Locale;
use serde_json::Value;

use super::facts::{FactsError, RouterFacts};
use crate::{
    WebState, auth,
    authz::{CurrentSession, CurrentUser},
    errors::{self, Kind},
    fleet::Fleet,
    nav::Section,
    overview::{is_profile_id, masthead},
    page::{Shell, Theme},
    prefs, router_access,
};

/// The caller of a page: the request headers, the session and the signed-in user.
#[derive(Clone, Copy)]
pub(crate) struct Caller<'request> {
    /// Request headers, for the theme cookie.
    headers: &'request HeaderMap,
    /// Session, for the CSRF token.
    session: &'request CurrentSession,
    /// Signed-in user.
    user: &'request CurrentUser,
}

impl<'request> Caller<'request> {
    /// The caller of one request.
    pub(crate) const fn new(
        headers: &'request HeaderMap,
        session: &'request CurrentSession,
        user: &'request CurrentUser,
    ) -> Self {
        Self {
            headers,
            session,
            user,
        }
    }

    /// The full-page shell in the Advanced section with `router` selected in the switcher.
    // cancel-safe: reads only.
    pub(crate) async fn shell(self, state: &WebState, router: Option<&str>) -> Shell {
        prefs::shell_for_locale(self.headers, self.user.locale())
            .with_csrf_token(self.session.session().csrf_token().to_owned())
            .with_section(Section::Advanced)
            .with_fleet(masthead(state, self.user.role(), router).await, None)
    }
}

/// A router the user may read and the fleet services that reach it.
#[derive(Clone, Copy)]
pub(crate) struct Target<'state> {
    /// Fleet services.
    fleet: &'state Fleet,
    /// Router profile id.
    router: &'state str,
}

/// Why a request cannot target its router.
pub(crate) enum Refusal {
    /// The fleet services are not attached.
    Unavailable,
    /// The router does not exist or is outside the user's scope.
    Missing,
    /// The registry could not be read.
    Failed,
}

impl Refusal {
    /// The error page of this refusal.
    pub(crate) fn page(self, shell: Shell) -> Response {
        match self {
            Self::Unavailable | Self::Missing => errors::response(Kind::NotFound, shell),
            Self::Failed => errors::response(Kind::Internal, shell),
        }
    }

    /// The bare status of this refusal, for fragments and streams.
    pub(crate) fn status(self) -> Response {
        let status = match self {
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Missing => StatusCode::NOT_FOUND,
            Self::Failed => StatusCode::INTERNAL_SERVER_ERROR,
        };
        status.into_response()
    }
}

/// The router `router` when the user may read it.
///
/// # Errors
///
/// Returns the refusal to answer with.
// cancel-safe: reads only.
pub(crate) async fn target<'state>(
    state: &'state WebState,
    user: &CurrentUser,
    router: &'state str,
) -> Result<Target<'state>, Refusal> {
    let fleet = state.fleet().ok_or(Refusal::Unavailable)?;
    if !is_profile_id(router) {
        return Err(Refusal::Missing);
    }
    match router_access::lookup(fleet, user.role(), router).await {
        Ok(Some(_entry)) => Ok(Target { fleet, router }),
        Ok(None) => Err(Refusal::Missing),
        Err(error) => {
            tracing::error!(%error, "advanced page could not list routers");
            Err(Refusal::Failed)
        }
    }
}

impl<'state> Target<'state> {
    /// Fleet services.
    pub(crate) const fn fleet(self) -> &'state Fleet {
        self.fleet
    }

    /// Router profile id.
    pub(crate) const fn router(self) -> &'state str {
        self.router
    }

    /// The router's catalog facts.
    ///
    /// # Errors
    ///
    /// Returns why the facts are unknown.
    // cancel-safe: detection only reads from the router.
    pub(crate) async fn facts(self, state: &WebState) -> Result<RouterFacts, FactsError> {
        state
            .advanced()
            .facts()
            .get(self.fleet.registry(), self.router, state.unix_seconds())
            .await
    }
}

/// Whether `user` holds every one of `permissions` on `router`.
pub(crate) fn allowed(user: &CurrentUser, router: &str, permissions: &[Permission]) -> bool {
    permissions
        .iter()
        .all(|permission| registry::authorize(user.role(), *permission, router).is_ok())
}

/// A fragment shell in the user's locale.
pub(crate) const fn fragment_shell(locale: Locale) -> Shell {
    Shell::new(locale, Theme::System)
}

/// One execution as the audit log records it: field names only, never values.
pub(crate) struct Execution<'call> {
    /// Stable action id, such as `web.explorer_execute`.
    action: &'static str,
    /// Router profile id.
    router: &'call str,
    /// Catalog path, or a label for batches and raw lines.
    target: String,
    /// Redacted parameters.
    params: Value,
}

impl<'call> Execution<'call> {
    /// An execution of `target` on `router`.
    pub(crate) const fn new(action: &'static str, router: &'call str, target: String) -> Self {
        Self {
            action,
            router,
            target,
            params: Value::Null,
        }
    }

    /// Adds redacted parameters.
    pub(crate) fn with_params(mut self, params: Value) -> Self {
        self.params = params;
        self
    }

    /// Appends the execution with `outcome` to the audit log; a failed append is logged.
    // NOT cancel-safe: an abandoned append may still be written.
    pub(crate) async fn record(self, state: &WebState, user: &CurrentUser, outcome: &str) {
        let event = AuditEvent::new(
            state.unix_seconds(),
            Actor::new(ActorKind::Web, user.username().to_owned()),
            self.action.to_owned(),
        )
        .with_router(self.router.to_owned())
        .with_target(self.target)
        .with_params(self.params)
        .with_result(outcome.to_owned(), auth::request_id());
        if let Err(error) = state.audit().append(event).await {
            tracing::error!(%error, action = self.action, "advanced audit append failed");
        }
    }
}

/// The field names of a request body, as the audit log records them.
pub(crate) fn field_names(value: &Value) -> Vec<String> {
    let mut names = Vec::new();
    collect_names(value, "", &mut names);
    names
}

/// Collects the dotted member names of `value` below `prefix`.
fn collect_names(value: &Value, prefix: &str, names: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (name, member) in object {
                let path = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}.{name}")
                };
                if member.is_object() || member.is_array() {
                    collect_names(member, &path, names);
                } else {
                    names.push(path);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_names(item, prefix, names);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}
