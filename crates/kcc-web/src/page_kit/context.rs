//! Who asks, and about which router: the page shell around a request, and the router a
//! route parameter names, resolved and checked before a handler does anything else.
//!
//! The route table already requires the route's permission on the router of every
//! `/ui/r/{router}/...` path, scope included; [`target`] still validates the id and reads
//! the registry, so a malformed, unknown or invisible router answers 404, never 500.

use core::error::Error;

use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Response},
};
use kcc_app::{
    permissions::{Permission, Role},
    registry::{self, RegistryEntry},
};
use kcc_domain::RouterCtx;
use kcc_i18n::locale::Locale;

use super::facts::{FactsError, RouterFacts};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors::{self, Kind},
    fleet::Fleet,
    nav::Section,
    overview::{is_profile_id, masthead},
    page::{Shell, Theme},
    prefs,
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

    /// The full-page shell: the user's locale, the theme cookie, the CSRF token, `section`
    /// marked in the navigation and `router` selected in the fleet switcher.
    // cancel-safe: reads only.
    pub(crate) async fn shell(
        self,
        state: &WebState,
        section: Section,
        router: Option<&str>,
    ) -> Shell {
        prefs::shell_for_locale(self.headers, self.user.locale())
            .with_csrf_token(self.session.session().csrf_token().to_owned())
            .with_section(section)
            .with_fleet(masthead(state, self.user.role(), router).await, None)
    }
}

/// The shell of a fragment, such as a dialog, a table region or an outcome, in `locale`.
pub(crate) const fn fragment_shell(locale: Locale) -> Shell {
    Shell::new(locale, Theme::System)
}

/// A router the user may read, and the fleet services that reach it.
#[derive(Clone, Copy)]
pub(crate) struct Target<'state> {
    /// Fleet services.
    fleet: &'state Fleet,
    /// Router profile id.
    router: &'state str,
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

    /// The router's catalog facts, cached.
    ///
    /// # Errors
    ///
    /// Returns why the facts are unknown.
    // cancel-safe: detection only reads from the router.
    pub(crate) async fn facts(self, state: &WebState) -> Result<RouterFacts, FactsError> {
        state
            .facts()
            .get(self.fleet.registry(), self.router, state.unix_seconds())
            .await
    }

    /// The router's catalog facts and the domain context to read and plan with.
    ///
    /// # Errors
    ///
    /// Returns why the router cannot be used now.
    // cancel-safe: detection only reads from the router.
    pub(crate) async fn context(
        self,
        state: &WebState,
    ) -> Result<(RouterFacts, RouterCtx), FactsError> {
        let facts = self.facts(state).await?;
        let client = self
            .fleet
            .registry()
            .client(self.router)
            .await
            .map_err(|error| {
                tracing::warn!(%error, router = self.router, "router page: no router client");
                FactsError::Unreachable
            })?;
        let context = RouterCtx::new(client, facts.catalog().clone());
        Ok((facts, context))
    }
}

/// Why a request cannot use the router it names.
pub(crate) enum Refusal {
    /// The fleet services are not attached.
    Unavailable,
    /// The role lacks the permission the request needs on the router.
    Forbidden,
    /// The router does not exist or is outside the role's scope.
    Missing,
    /// The registry could not be read.
    Failed(Box<dyn Error + Send + Sync>),
}

impl Refusal {
    /// The error page of this refusal: 404 for an unavailable or missing router, 403, or
    /// the logged 500.
    pub(crate) fn page(self, shell: Shell) -> Response {
        match self {
            Self::Unavailable | Self::Missing => errors::response(Kind::NotFound, shell),
            Self::Forbidden => errors::response(Kind::Forbidden, shell),
            Self::Failed(error) => errors::internal(&error, shell),
        }
    }

    /// The bare status of this refusal, for fragments, actions and streams.
    pub(crate) fn status(self) -> Response {
        let status = match self {
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Missing => StatusCode::NOT_FOUND,
            Self::Failed(error) => {
                tracing::error!(%error, "router lookup failed");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        status.into_response()
    }
}

/// The router `router` when `user` may read it.
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
    match lookup(fleet, user.role(), router).await {
        Ok(Some(_entry)) => Ok(Target { fleet, router }),
        Ok(None) => Err(Refusal::Missing),
        Err(error) => Err(Refusal::Failed(error)),
    }
}

/// The profile `id` when `role` may manage it.
///
/// # Errors
///
/// Returns the refusal to answer with.
// cancel-safe: reads only.
pub(crate) async fn managed(
    fleet: &Fleet,
    role: &Role,
    id: &str,
) -> Result<RegistryEntry, Refusal> {
    if registry::authorize(role, Permission::ManageRouters, id).is_err() {
        return Err(Refusal::Forbidden);
    }
    match lookup(fleet, role, id).await {
        Ok(Some(entry)) => Ok(entry),
        Ok(None) => Err(Refusal::Missing),
        Err(error) => Err(Refusal::Failed(error)),
    }
}

/// The profile `id` when `role` may read it.
///
/// # Errors
///
/// Returns registry read failures.
// cancel-safe: reads only.
pub(crate) async fn lookup(
    fleet: &Fleet,
    role: &Role,
    id: &str,
) -> Result<Option<RegistryEntry>, Box<dyn Error + Send + Sync>> {
    Ok(fleet
        .visible(role)
        .await?
        .into_iter()
        .find(|entry| entry.profile.id == id))
}
