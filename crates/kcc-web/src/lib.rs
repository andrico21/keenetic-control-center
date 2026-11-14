//! Web UI: server-rendered pages under `/ui`, merged into the rmcp-server-kit router.
//!
//! [`web_router`] builds the router `kcc` passes to `McpServerConfig::with_extra_router`.
//! The kit owns `/mcp`, `/healthz`, `/readyz`, `/version`, `/admin/status` and
//! `/.well-known/*` and panics on an exact overlap, so every Web UI route lives under
//! `/ui`; the one other route is `GET /`, a redirect to `/ui/`.
//!
//! - Pages are askama templates from `templates/` with HTML auto-escaping; every
//!   user-visible string comes from `kcc-i18n` through the templates' `t(...)` calls.
//! - Static assets are embedded, addressed by content hash under `/ui/static/` and served
//!   with an immutable cache policy; vendored files are pinned in `assets/ASSETS.lock`.
//! - [`csp::security_headers`] is the kit's security-header configuration: the Web UI
//!   Content-Security-Policy, and no kit `Cache-Control`, because the kit would overwrite
//!   the per-response value this router sets.
//! - Unknown paths under `/ui` render a generic, localized 404 page ([`errors`]).
//! - [`WebState::with_fleet`] attaches the router fleet ([`fleet::FleetServices`]): the
//!   fleet overview, the router dashboards and forms, and their live event streams.
//! - [`WebState::with_admin`] attaches the administration services
//!   ([`admin::AdminServices`]): users, roles, API keys, the audit log and the server
//!   summary under `/ui/admin`.
//! - [`WebState::with_jobs`] attaches the job runner that runs the command explorer's
//!   background commands.
// `dead_code_pub_in_binary` fires on the public API only in the lib unit-test
// binary; rustc accepts an expect for it at crate level alone.
#![cfg_attr(
    test,
    expect(
        dead_code_pub_in_binary,
        reason = "public API: unused inside the unit-test harness"
    )
)]

extern crate alloc;

/// Macro to generate trivial `Localize` impls.
///
/// Usage: `localized!(Type1, Type2, ...);`.
///
/// Generates: `impl Localize for Type { fn shell(&self) -> &Shell { &self.shell } }`.
macro_rules! localized {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl $crate::page::Localize for $ty {
                #[inline]
                fn shell(&self) -> &$crate::page::Shell {
                    &self.shell
                }
            }
        )+
    };
}

/// Macro to generate the record accessors of a wizard's `Flow` impl.
///
/// Usage: `record_fields!();` inside `impl Flow for Record`, where the record has the
/// fields `schema`, `id`, `owner`, `created_at`, `step`, `target`, `preview`, `run` and
/// `finished`, and `Moves` and `Run` are in scope.
macro_rules! record_fields {
    () => {
        fn schema(&self) -> u32 {
            self.schema
        }

        fn id(&self) -> &str {
            &self.id
        }

        fn owner(&self) -> &str {
            &self.owner
        }

        fn created_at(&self) -> u64 {
            self.created_at
        }

        fn step(&self) -> Self::Step {
            self.step
        }

        fn target(&self) -> Option<&str> {
            self.target.as_deref()
        }

        fn preview(&self) -> Option<&str> {
            self.preview.as_deref()
        }

        fn run(&self) -> Option<&Run> {
            self.run.as_ref()
        }

        fn finished(&self) -> Option<(Self::Finish, u64)> {
            self.finished
        }

        fn moves(&mut self) -> Moves<'_, Self> {
            Moves::new(
                &mut self.step,
                &mut self.preview,
                &mut self.run,
                &mut self.finished,
            )
        }
    };
}

pub mod admin;
pub mod brackets;
pub mod csp;
mod csrf;
pub mod errors;
pub mod fleet;
pub mod fleet_updates;
pub mod nav;
pub mod page;
pub mod session;
pub mod sse;
pub mod table;

mod advanced;
mod auth;
mod authz;

mod admin_audit;
mod admin_keys;
mod admin_roles;
mod admin_server;
mod admin_shared;
mod admin_users;

mod assets;
mod clients_pages;
mod config_page;
mod dashboard;
mod dns_vpn;
mod firewall_page;
mod gauge;
mod migrate_wizard;
mod nat_page;
mod net_change;
mod net_interface_actions;
mod net_interface_detail;
mod net_interface_edits;
mod net_interface_line;
mod net_interface_traffic;
mod net_interfaces;
mod net_internet;
mod net_internet_address;
mod net_internet_create;
mod net_internet_delete;
mod net_internet_edit;
mod net_internet_order;
mod net_internet_settings;
mod net_mesh;
mod net_pages;
mod net_settings;
mod net_wan;
mod net_wifi;
mod net_wifi_edit;
mod net_wifi_fields;
mod net_wifi_rows;
mod net_wifi_settings;
mod net_wifi_stations;
mod network;
mod overview;
mod page_kit;
mod pages;
mod prefs;
mod presets_page;
mod router_access;
mod router_check;
mod router_delete;
mod router_form;
mod routers;
mod routing_page;
mod save;
mod secret_pages;
mod system_general;
mod system_pages;
mod telemetry;
mod traffic;
mod view;
mod wizard;

use alloc::sync::Arc;
use core::{fmt, time::Duration};

use axum::{
    Router,
    http::{HeaderValue, header},
    middleware,
    routing::{get, post},
};
use kcc_app::{
    accounts::{AccountStore, Clock},
    audit::AuditLog,
    jobs::JobRunner,
    permissions::Role,
    role_source::RoleSource,
};
use kcc_i18n::locale::Locale;
use kcc_telemetry::logs::readers::LogFeeds;
use tower_http::{limit::RequestBodyLimitLayer, set_header::SetResponseHeaderLayer};

use crate::{
    admin::AdminServices,
    admin_shared::Admin,
    fleet::{Fleet, FleetServices},
    session::{CookieSecurity, SessionStore},
    sse::StreamLimiter,
};

/// Time limit for producing a response on every route except server-sent event streams
/// and requests that hold a router's fail-safe bracket ([`brackets`]).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Request body limit of every route except uploads, which set a larger one explicitly.
pub const BODY_LIMIT: usize = 1024 * 1024;

/// `Cache-Control` of every response that does not set its own: pages, redirects and
/// errors are never stored. Hash-addressed static assets set an immutable policy instead.
const NO_STORE: &str = "no-store, max-age=0";

/// Shared state of every Web UI handler.
#[derive(Clone)]
pub struct WebState {
    /// Locale used when neither the `kcc_lang` cookie nor `Accept-Language` selects one.
    default_locale: Locale,
    /// Open server-sent event streams per session.
    streams: StreamLimiter,
    /// Persistent account service.
    accounts: Arc<AccountStore>,
    /// In-memory browser sessions.
    sessions: SessionStore,
    /// Tamper-evident audit writer.
    audit: AuditLog,
    /// Built-in and custom roles; the role pages and reloads replace them while running.
    roles: RoleSource,
    /// Origins accepted for browser state-changing requests.
    allowed_origins: Arc<[String]>,
    /// Cookie policy selected from the actual listener transport.
    cookie_security: CookieSecurity,
    /// Wall clock shared with account lockout and audit timestamps.
    clock: Arc<dyn Clock>,
    /// Router fleet services, when attached with [`WebState::with_fleet`].
    fleet: Option<Arc<Fleet>>,
    /// Administration services, when attached with [`WebState::with_admin`].
    admin: Option<Arc<Admin>>,
    /// Command explorer and console services.
    advanced: Arc<advanced::Services>,
    /// The routers' catalog facts, shared by every page that validates a request.
    facts: Arc<page_kit::facts::FactsCache>,
    /// The router log collectors the log page follows instead of polling.
    log_feeds: LogFeeds,
}

impl fmt::Debug for WebState {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebState").finish_non_exhaustive()
    }
}

/// Security services and listener facts needed to build [`WebState`].
#[derive(Debug)]
#[expect(
    clippy::exhaustive_structs,
    reason = "application integration constructs the complete validated Web state"
)]
pub struct WebStateConfig {
    /// Locale used before login or when an account locale is invalid.
    pub default_locale: Locale,
    /// Persistent account service.
    pub accounts: Arc<AccountStore>,
    /// Tamper-evident audit writer.
    pub audit: AuditLog,
    /// Roles loaded from application state.
    pub roles: Vec<Role>,
    /// Session idle timeout.
    pub session_idle: Duration,
    /// Session absolute timeout.
    pub session_absolute: Duration,
    /// Origin allowlist derived by `Config::web_allowed_origins`.
    pub allowed_origins: Vec<String>,
    /// Cookie transport selected from the actual listener.
    pub cookie_security: CookieSecurity,
    /// Shared wall clock.
    pub clock: Arc<dyn Clock>,
}

impl WebState {
    /// Creates the state from validated application services and listener facts.
    #[inline]
    #[must_use]
    pub fn new(config: WebStateConfig) -> Self {
        let sessions = SessionStore::new(
            config.session_idle,
            config.session_absolute,
            config.default_locale,
            Arc::clone(&config.clock),
        );
        Self {
            default_locale: config.default_locale,
            streams: StreamLimiter::default(),
            accounts: config.accounts,
            sessions,
            audit: config.audit,
            roles: RoleSource::new(config.roles),
            allowed_origins: config.allowed_origins.into(),
            cookie_security: config.cookie_security,
            clock: config.clock,
            fleet: None,
            admin: None,
            advanced: Arc::new(advanced::Services::new(None)),
            facts: Arc::default(),
            log_feeds: LogFeeds::default(),
        }
    }

    /// Shares `roles` with the other front ends: a role change in the Web UI then
    /// reaches every holder of the source at once, and a reload of the source reaches the
    /// Web UI's next request.
    #[inline]
    #[must_use]
    pub fn with_role_source(mut self, roles: RoleSource) -> Self {
        self.roles = roles;
        self
    }

    /// Lets the log page follow the routers' log collectors (`[logs] enabled`) instead of
    /// reading the router per viewer.
    #[inline]
    #[must_use]
    pub fn with_log_feeds(mut self, feeds: LogFeeds) -> Self {
        self.log_feeds = feeds;
        self
    }

    /// The number of signed-in sessions that have not expired.
    // cancel-safe: one read of the session map.
    #[inline]
    pub async fn active_sessions(&self) -> usize {
        self.sessions.active().await
    }

    /// Attaches the router fleet: the overview, router dashboards and forms, and their
    /// live streams use these services. Without it those pages show a "not configured"
    /// notice and the streams answer `503`.
    #[inline]
    #[must_use]
    pub fn with_fleet(mut self, services: FleetServices) -> Self {
        self.fleet = Some(Arc::new(Fleet::new(services, Arc::clone(&self.clock))));
        self
    }

    /// Attaches the job runner: commands the catalog marks as background work run as
    /// its jobs, followed live in the explorer. Without it the explorer refuses them.
    #[inline]
    #[must_use]
    pub fn with_jobs(mut self, jobs: Arc<JobRunner>) -> Self {
        self.advanced = Arc::new(advanced::Services::new(Some(jobs)));
        self
    }

    /// Router fleet services, when attached.
    #[must_use]
    pub(crate) fn fleet(&self) -> Option<&Fleet> {
        self.fleet.as_deref()
    }

    /// Attaches the administration services: the user, role, API-key, audit-log and
    /// server pages under `/ui/admin` use them. Without it those pages show a "not
    /// configured" notice and their changes answer `503`.
    #[inline]
    #[must_use]
    pub fn with_admin(mut self, services: AdminServices) -> Self {
        let started_at = self.clock.unix_seconds();
        self.admin = Some(Arc::new(Admin::new(services, started_at)));
        self
    }

    /// Administration services, when attached.
    #[must_use]
    pub(crate) fn admin(&self) -> Option<&Admin> {
        self.admin.as_deref()
    }

    /// Every built-in and custom role.
    #[must_use]
    pub(crate) fn roles(&self) -> Arc<[Role]> {
        self.roles.current()
    }

    /// Replaces the roles after an administrator changed them.
    pub(crate) fn set_roles(&self, roles: Vec<Role>) {
        self.roles.replace(roles);
    }

    /// The router log collectors.
    #[must_use]
    pub(crate) const fn log_feeds(&self) -> &LogFeeds {
        &self.log_feeds
    }

    /// Command explorer and console services.
    #[must_use]
    pub(crate) fn advanced(&self) -> &advanced::Services {
        &self.advanced
    }

    /// The routers' catalog facts.
    #[must_use]
    pub(crate) fn facts(&self) -> &page_kit::facts::FactsCache {
        &self.facts
    }

    /// The locale used when a request does not select one.
    #[inline]
    #[must_use]
    pub const fn default_locale(&self) -> Locale {
        self.default_locale
    }

    /// The per-session limit on concurrent server-sent event streams.
    #[inline]
    #[must_use]
    pub const fn streams(&self) -> &StreamLimiter {
        &self.streams
    }

    /// Account service used by login and account settings.
    #[inline]
    #[must_use]
    pub(crate) const fn accounts(&self) -> &Arc<AccountStore> {
        &self.accounts
    }

    /// In-memory session store.
    #[inline]
    #[must_use]
    pub(crate) const fn sessions(&self) -> &SessionStore {
        &self.sessions
    }

    /// Audit writer for authentication events.
    #[inline]
    #[must_use]
    pub(crate) const fn audit(&self) -> &AuditLog {
        &self.audit
    }

    /// Resolves an account's persisted role name.
    #[must_use]
    pub(crate) fn role(&self, name: &str) -> Option<Role> {
        self.roles.find(name)
    }

    /// Origins accepted for state-changing browser requests.
    #[inline]
    #[must_use]
    pub(crate) fn allowed_origins(&self) -> &[String] {
        &self.allowed_origins
    }

    /// Session cookie policy for this listener.
    #[inline]
    #[must_use]
    pub(crate) const fn cookie_security(&self) -> CookieSecurity {
        self.cookie_security
    }

    /// Current Unix timestamp for audit records.
    #[inline]
    #[must_use]
    pub(crate) fn unix_seconds(&self) -> u64 {
        self.clock.unix_seconds()
    }
}

/// Builds the Web UI router for `McpServerConfig::with_extra_router`.
///
/// Layering contract for the routes later pages add:
///
/// - Every route runs as a task the server owns ([`brackets`]), so a request holding a
///   router's fail-safe bracket ends its bracket even when nobody waits any more.
/// - Request/response routes join `bounded`, under the [`REQUEST_TIMEOUT`] budget of
///   `brackets::budget`, which waits instead for a request holding a bracket.
/// - Server-sent event routes (`/ui/sse/...`) are merged after the timeout layer and
///   before the body limit, so the timeout never cuts a stream; [`WebState::streams`]
///   caps them per session. They pass the same CSRF, authentication and authorization
///   layers as pages.
/// - Upload routes are merged after the [`BODY_LIMIT`] layer, each with its own larger
///   `RequestBodyLimitLayer` and axum `DefaultBodyLimit`.
/// - The kit installs its JSON 404 after merging this router, so `/ui/{*rest}` is an
///   explicit route that renders the HTML 404 page for every unknown path.
#[inline]
pub fn web_router(state: WebState) -> Router {
    let pages = Router::new()
        .route("/", get(pages::to_ui))
        .route("/ui", get(pages::to_ui))
        .route("/ui/", get(overview::page))
        .route("/ui/r/{router}", get(dashboard::page))
        .route("/ui/r/{router}/save", post(save::save))
        .route(
            "/ui/routers/new",
            get(routers::new_page).post(routers::create),
        )
        .route("/ui/routers/test", post(router_check::test))
        .route(
            "/ui/routers/{id}/edit",
            get(routers::edit_page).post(routers::update),
        )
        .route(
            "/ui/routers/{id}/delete",
            get(router_delete::delete_dialog).post(router_delete::delete),
        )
        .route("/ui/account", get(auth::account_page))
        .route("/ui/account/password", post(auth::change_password))
        .route("/ui/account/locale", post(auth::change_locale))
        .route("/ui/logout", post(auth::logout))
        .merge(admin_routes())
        .merge(advanced::routes())
        .merge(system_general::routes())
        .merge(clients_pages::routes())
        .merge(net_pages::routes())
        .merge(dns_vpn::routes())
        .merge(system_pages::routes())
        .merge(routing_page::wiring::routes())
        .merge(nat_page::wiring::routes())
        .merge(firewall_page::wiring::routes())
        .merge(secret_pages::routes::routes())
        .route(
            "/ui/{*rest}",
            get(pages::section).fallback(pages::not_found),
        );
    let protected = protect(pages, &state);
    let streams = protect(
        Router::new()
            .route("/ui/sse/fleet", get(overview::stream))
            .route("/ui/sse/r/{router}/traffic", get(dashboard::stream))
            .merge(advanced::streams())
            .merge(net_pages::streams())
            .merge(system_pages::streams()),
        &state,
    );
    let public = Router::new()
        .route(assets::ROUTE, get(assets::serve))
        .route("/ui/login", get(auth::login_page).post(auth::login))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            csrf::middleware,
        ));
    let bounded = Router::new()
        .merge(public)
        .merge(protected)
        .layer(middleware::from_fn(brackets::budget));
    Router::new()
        .merge(bounded)
        .merge(streams)
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT))
        .merge(dns_vpn::uploads(&state))
        .merge(config_page::wiring::routes(&state))
        .merge(migrate_wizard::routes::router(&state))
        .merge(presets_page::routes::router(&state))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static(NO_STORE),
        ))
        .layer(middleware::from_fn(brackets::own))
        .with_state(state)
}

/// The administration routes under `/ui/admin`: users, roles, API keys, audit and server.
fn admin_routes() -> Router<WebState> {
    Router::new()
        .route("/ui/admin", get(admin_shared::landing))
        .route(
            "/ui/admin/users",
            get(admin_users::page).post(admin_users::create),
        )
        .route("/ui/admin/users/new", get(admin_users::new_dialog))
        .route(
            "/ui/admin/users/role",
            get(admin_users::role_dialog).post(admin_users::set_role),
        )
        .route("/ui/admin/users/disable", post(admin_users::disable))
        .route("/ui/admin/users/enable", post(admin_users::enable))
        .route("/ui/admin/users/unlock", post(admin_users::unlock))
        .route(
            "/ui/admin/users/delete",
            get(admin_users::delete_dialog).post(admin_users::delete),
        )
        .route(
            "/ui/admin/roles",
            get(admin_roles::page).post(admin_roles::create),
        )
        .route("/ui/admin/roles/new", get(admin_roles::new_dialog))
        .route(
            "/ui/admin/roles/edit",
            get(admin_roles::edit_dialog).post(admin_roles::update),
        )
        .route(
            "/ui/admin/roles/delete",
            get(admin_roles::delete_dialog).post(admin_roles::delete),
        )
        .route(
            "/ui/admin/api-keys",
            get(admin_keys::page).post(admin_keys::create),
        )
        .route("/ui/admin/api-keys/new", get(admin_keys::new_dialog))
        .route(
            "/ui/admin/api-keys/revoke",
            get(admin_keys::revoke_dialog).post(admin_keys::revoke),
        )
        .route("/ui/admin/audit", get(admin_audit::page))
        .route("/ui/admin/audit/export", get(admin_audit::export))
        .route("/ui/admin/server", get(admin_server::page))
}

/// Adds the CSRF, authentication and route-table authorization layers to `routes`.
fn protect(routes: Router<WebState>, state: &WebState) -> Router<WebState> {
    routes
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            authz::authorization_middleware,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            authz::authentication_middleware,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            csrf::middleware,
        ))
}
