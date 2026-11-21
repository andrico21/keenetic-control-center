//! Authenticated-session extraction and route-table authorization.

mod router_segment;

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

use self::router_segment::{RouterSegment, router_scope};
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

    /// A signed-in user for unit tests of code that takes one.
    #[cfg(test)]
    pub(crate) const fn signed_in(username: String, role: Role, locale: Locale) -> Self {
        Self {
            username,
            role,
            locale,
        }
    }
}

impl FromRequestParts<WebState> for CurrentSession {
    type Rejection = Response;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "async is mandated by the axum extractor trait"
    )]
    // cancel-safe: it has no await point.
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
    // cancel-safe: it has no await point.
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
// NOT cancel-safe: it awaits the rest of the request, whose handler may change the router or local
// state, or queue an audit entry, before the future is dropped.
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
    // The role's live definition, so a role reduced or removed since sign-in (in the Web
    // UI or by a SIGHUP reload) binds this request.
    let (Some(username), Some(role)) = (
        session.username().map(str::to_owned),
        session
            .role()
            .and_then(|signed_in| state.role(&signed_in.name)),
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
// NOT cancel-safe: it awaits the rest of the request, whose handler may change the router or local
// state, or queue an audit entry, before the future is dropped.
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
        && match &requirement.router {
            None => true,
            Some(RouterSegment::Id(router)) => {
                registry::authorize(role, requirement.permission, router).is_ok()
            }
            Some(RouterSegment::Undecodable) => false,
        }
}

/// One route-table authorization decision.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Requirement {
    /// Capability required by the route family.
    permission: Permission,
    /// Router path parameter when present.
    router: Option<RouterSegment>,
}

/// Maps current and planned Web UI route families to application permissions.
fn requirement(path: &str) -> Requirement {
    let router = router_scope(path);
    let permission = match path {
        "/ui/admin" => Permission::Read,
        value if value.starts_with("/ui/admin/audit") => Permission::ViewAudit,
        value if value.starts_with("/ui/admin/notifications") => Permission::ManageNotifications,
        value if value.starts_with("/ui/admin/scheduled") => Permission::ManageSchedules,
        value if value.starts_with("/ui/admin/mcp") => Permission::ManageMcp,
        value if value.starts_with("/ui/admin") => Permission::ManageUsers,
        value if value.starts_with("/ui/audit") => Permission::ViewAudit,
        value if value.starts_with("/ui/migrate") => Permission::Migrate,
        value if value.starts_with("/ui/configuration") => Permission::Write,
        value if value.starts_with("/ui/advanced") => Permission::RawRci,
        value if value.starts_with("/ui/routers") => Permission::ManageRouters,
        value if router.is_some() && value.ends_with("/save") => Permission::Save,
        value if router_section(value) == Some("console") => Permission::RawRci,
        _ => Permission::Read,
    };
    Requirement { permission, router }
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
            ("/ui/admin/notifications", Permission::ManageNotifications),
            (
                "/ui/admin/notifications/new",
                Permission::ManageNotifications,
            ),
            ("/ui/admin/scheduled", Permission::ManageSchedules),
            ("/ui/admin/scheduled/new", Permission::ManageSchedules),
            ("/ui/admin/mcp", Permission::ManageMcp),
            ("/ui/admin/mcp/connections", Permission::ManageMcp),
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

    /// Todo 3: a role holding `Read` and `ManageSchedules` reaches the scheduled page only.
    #[test]
    fn the_schedule_permission_opens_the_scheduled_page_only() {
        let scheduler = Role::new(
            "scheduler".to_owned(),
            [Permission::Read, Permission::ManageSchedules],
            vec!["*".to_owned()],
        );
        assert!(permits(&scheduler, "/ui/admin/scheduled"), "scheduled page");
        assert!(
            !permits(&scheduler, "/ui/admin/notifications"),
            "notifications"
        );
        assert!(!permits(&scheduler, "/ui/admin/users"), "user management");
    }
}
