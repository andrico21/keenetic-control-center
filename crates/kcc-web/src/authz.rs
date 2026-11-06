//! Authenticated-session extraction and route-table authorization.

use axum::{
    extract::{FromRequestParts, Request, State},
    http::{Method, StatusCode, request::Parts},
    middleware::Next,
    response::{IntoResponse as _, Redirect, Response},
};
use kcc_app::{
    permissions::{Permission, Role},
    registry,
};
use kcc_i18n::locale::Locale;
use sha2::{Digest as _, Sha256};

use crate::{
    WebState,
    errors::{self, Kind},
    overview::masthead,
    prefs,
    session::{Session, SessionId, SessionStore},
};

/// The page a session must use while its account has to choose a new password.
pub(crate) const PASSWORD_CHANGE_PAGE: &str = "/ui/account";

/// Every path a session may open while its account has to choose a new password.
const PASSWORD_CHANGE_PATHS: [&str; 4] = [
    PASSWORD_CHANGE_PAGE,
    "/ui/account/password",
    "/ui/account/locale",
    "/ui/logout",
];

/// An authenticated session inserted by [`authentication_middleware`].
#[derive(Debug, Clone)]
pub(crate) struct CurrentSession {
    /// Server-side session id, kept out of URLs and logs.
    id: SessionId,
    /// Session snapshot for this request.
    session: Session,
}

/// Authenticated principal exposed to handlers.
#[derive(Debug, Clone)]
pub(crate) struct CurrentUser {
    /// Login name.
    username: String,
    /// Resolved role and router scope.
    role: Role,
    /// Account locale.
    locale: Locale,
}

impl CurrentSession {
    /// Server-side session id.
    #[inline]
    #[must_use]
    pub(crate) const fn id(&self) -> &SessionId {
        &self.id
    }

    /// Request session snapshot.
    #[inline]
    #[must_use]
    pub(crate) const fn session(&self) -> &Session {
        &self.session
    }

    /// The opaque key under which this session's event streams are counted: a hash of
    /// the session id, so the id itself never leaves the session store.
    #[must_use]
    pub(crate) fn stream_key(&self) -> String {
        Sha256::digest(self.id.as_str().as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .concat()
    }
}

impl CurrentUser {
    /// Login name.
    #[inline]
    #[must_use]
    pub(crate) const fn username(&self) -> &str {
        self.username.as_str()
    }

    /// Resolved role and router scope.
    #[inline]
    #[must_use]
    pub(crate) const fn role(&self) -> &Role {
        &self.role
    }

    /// Account locale.
    #[inline]
    #[must_use]
    pub(crate) const fn locale(&self) -> Locale {
        self.locale
    }

    /// Updates the request-local locale after persistence.
    #[inline]
    pub(crate) const fn set_locale(&mut self, locale: Locale) {
        self.locale = locale;
    }
}

impl FromRequestParts<WebState> for CurrentSession {
    type Rejection = Response;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "async is mandated by the axum extractor trait"
    )]
    async fn from_request_parts(
        parts: &mut Parts,
        _state: &WebState,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or_else(|| Redirect::to("/ui/login").into_response())
    }
}

impl FromRequestParts<WebState> for CurrentUser {
    type Rejection = Response;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "async is mandated by the axum extractor trait"
    )]
    async fn from_request_parts(
        parts: &mut Parts,
        _state: &WebState,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or_else(|| Redirect::to("/ui/login").into_response())
    }
}

/// Resolves the session cookie and redirects unauthenticated requests to login.
pub(crate) async fn authentication_middleware(
    State(state): State<WebState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(id) = SessionStore::id_from_headers(request.headers(), state.cookie_security()) else {
        return Redirect::to("/ui/login").into_response();
    };
    let Some(session) = state.sessions().get(&id).await else {
        return Redirect::to("/ui/login").into_response();
    };
    let (Some(username), Some(role)) = (
        session.username().map(str::to_owned),
        session.role().cloned(),
    ) else {
        return Redirect::to("/ui/login").into_response();
    };
    if session.password_change_required() && !PASSWORD_CHANGE_PATHS.contains(&request.uri().path())
    {
        return if matches!(*request.method(), Method::GET | Method::HEAD) {
            Redirect::to(PASSWORD_CHANGE_PAGE).into_response()
        } else {
            StatusCode::FORBIDDEN.into_response()
        };
    }
    let user = CurrentUser {
        username,
        role,
        locale: session.locale(),
    };
    drop(
        request
            .extensions_mut()
            .insert(CurrentSession { id, session }),
    );
    drop(request.extensions_mut().insert(user));
    next.run(request).await
}

/// Enforces the route table's permission and optional router scope.
pub(crate) async fn authorization_middleware(
    State(state): State<WebState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(user) = request.extensions().get::<CurrentUser>() else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !permits(&user.role, request.uri().path()) {
        let shell = prefs::shell_for_locale(request.headers(), user.locale)
            .with_csrf_token(
                request
                    .extensions()
                    .get::<CurrentSession>()
                    .map_or_else(String::new, |current| {
                        current.session.csrf_token().to_owned()
                    }),
            )
            .with_fleet(masthead(&state, &user.role, None).await, None);
        return errors::response(Kind::Forbidden, shell);
    }
    next.run(request).await
}

/// Whether `role` may open `path` under the route table, including its router scope.
pub(crate) fn permits(role: &Role, path: &str) -> bool {
    let requirement = requirement(path);
    role.grants(requirement.permission)
        && requirement
            .router
            .as_ref()
            .is_none_or(|router| registry::authorize(role, requirement.permission, router).is_ok())
}

/// One route-table authorization decision.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Requirement {
    /// Capability required by the route family.
    permission: Permission,
    /// Router path parameter when present.
    router: Option<String>,
}

/// Maps current and planned Web UI route families to application permissions.
fn requirement(path: &str) -> Requirement {
    let router = router_scope(path);
    let permission = match path {
        "/ui/admin" => Permission::Read,
        value if value.starts_with("/ui/admin/audit") => Permission::ViewAudit,
        value if value.starts_with("/ui/admin") => Permission::ManageUsers,
        value if value.starts_with("/ui/audit") => Permission::ViewAudit,
        value if value.starts_with("/ui/migration") => Permission::Migrate,
        value if value.starts_with("/ui/configuration") => Permission::Write,
        value if value.starts_with("/ui/advanced") => Permission::RawRci,
        value if value.starts_with("/ui/routers") => Permission::ManageRouters,
        value if router.is_some() && value.ends_with("/save") => Permission::Save,
        value if router_section(value) == Some("console") => Permission::RawRci,
        _ => Permission::Read,
    };
    Requirement { permission, router }
}

/// Extracts the router id from the `/ui/r/{router}/...` and `/ui/sse/r/{router}/...`
/// route families.
fn router_scope(path: &str) -> Option<String> {
    let mut segments = path.trim_start_matches('/').split('/');
    let ((Some("ui"), Some("r"), Some(router), _)
    | (Some("ui"), Some("sse"), Some("r"), Some(router))) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    )
    else {
        return None;
    };
    (!router.is_empty()).then(|| router.to_owned())
}

/// The route family after the router id in `/ui/r/{router}/{section}/...`, such as
/// `explorer` (route table: `Read`; executions re-check their risk) or `console`.
fn router_section(path: &str) -> Option<&str> {
    let mut segments = path.trim_start_matches('/').split('/');
    let (Some("ui"), Some("r"), Some(_router), Some(section)) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return None;
    };
    Some(section)
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_app::permissions::{Permission, Role};

    use super::{permits, requirement};

    #[test]
    fn admin_routes_map_to_their_permissions() {
        for (path, permission) in [
            ("/ui/admin", Permission::Read),
            ("/ui/admin/users", Permission::ManageUsers),
            ("/ui/admin/roles/new", Permission::ManageUsers),
            ("/ui/admin/api-keys", Permission::ManageUsers),
            ("/ui/admin/server", Permission::ManageUsers),
            ("/ui/admin/audit", Permission::ViewAudit),
            ("/ui/admin/audit/export", Permission::ViewAudit),
        ] {
            assert_eq!(requirement(path).permission, permission, "{path}");
        }
        let auditor = Role::new(
            "auditor".to_owned(),
            [Permission::Read, Permission::ViewAudit],
            vec!["*".to_owned()],
        );
        assert!(permits(&auditor, "/ui/admin/audit"), "audit log");
        assert!(permits(&auditor, "/ui/admin"), "admin landing");
        assert!(!permits(&auditor, "/ui/admin/users"), "user management");
    }
}
