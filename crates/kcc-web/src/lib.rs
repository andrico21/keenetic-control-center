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
//! - [`WebState::with_notify`] attaches the running Telegram notifier
//!   ([`admin_notify::NotifyControl`]) the notifications page reports on and tests.
//! - [`WebState::with_schedules`] attaches the running scheduler
//!   ([`admin_scheduled::ScheduleControl`]) the scheduled actions page checks schedules
//!   with and runs them through, and the dashboards name the next scheduled action of.
//! - [`WebState::with_jobs`] attaches the job runner that runs the command explorer's
//!   background commands.
//! - [`WebState::with_mcp_control`] attaches the running MCP listeners
//!   ([`admin::McpControl`]) the MCP settings page applies changes through.
//! - [`WebState::with_entware_ssh_timeouts`] bounds the Entware page's SSH connections,
//!   commands and reads; the page builds its SSH services over the fleet at first use.
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

/// Macro to let templates embed the rendered output of child templates as it is.
///
/// Usage: `fragment!(Type1, Type2, ...);` for askama templates only: askama escaped every
/// value they write, so their output is HTML that needs no second escape.
///
/// Generates: `impl askama::filters::HtmlSafe for Type where Type: askama::Template {}`.
macro_rules! fragment {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl ::askama::filters::HtmlSafe for $ty where $ty: ::askama::Template {}
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
pub mod admin_notify;
pub mod admin_scheduled;
pub mod brackets;
pub mod csp;
mod csrf;
pub mod errors;
pub mod fleet;
pub mod fleet_updates;
pub mod nav;
pub mod oauth;
pub mod page;
pub mod session;
pub mod sse;
pub(crate) mod table;

mod advanced;
mod auth;
mod authz;
mod blocking;

mod admin_audit;
mod admin_keys;
mod admin_mcp;
mod admin_mcp_connections;
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
mod job_status;
mod markup;
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
mod net_tables;
mod net_wan;
mod net_wifi;
mod net_wifi_edit;
mod net_wifi_fields;
mod net_wifi_rows;
mod net_wifi_settings;
mod net_wifi_stations;
mod net_wifi_tables;
mod network;
mod oauth_consent;
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
mod stream_session;
mod sync;
mod system_general;
mod system_pages;
mod telemetry;
mod traffic;
mod view;
mod wizard;

use alloc::{collections::BTreeMap, sync::Arc};
use core::{fmt, time::Duration};

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{HeaderValue, header},
    middleware,
    routing::{get, post},
};
use kcc_app::{
    accounts::{AccountStore, Clock, standing::AccountStanding},
    audit::AuditLog,
    jobs::JobRunner,
    permissions::Role,
    role_source::RoleSource,
};
use kcc_i18n::locale::Locale;
use kcc_ssh::transport::Timeouts;
use kcc_telemetry::logs::readers::LogFeeds;
use tower_http::{limit::RequestBodyLimitLayer, set_header::SetResponseHeaderLayer};

use crate::{
    admin::{AdminServices, McpControl},
    admin_notify::NotifyControl,
    admin_scheduled::ScheduleControl,
    admin_shared::Admin,
    fleet::{Fleet, FleetServices},
    oauth::OAuthServer,
    session::{CookieSecurity, SessionStore, account::StandingsError},
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
    /// The running notifier, when attached with [`WebState::with_notify`].
    notify: Option<Arc<dyn NotifyControl>>,
    /// The running scheduler, when attached with [`WebState::with_schedules`].
    schedules: Option<Arc<dyn ScheduleControl>>,
    /// The running MCP listeners, when attached with [`WebState::with_mcp_control`].
    mcp: Option<Arc<admin_mcp::Attached>>,
    /// kcc's authorization server, when attached with [`WebState::with_oauth`].
    oauth: Option<Arc<OAuthServer>>,
    /// Command explorer and console services.
    advanced: Arc<advanced::Services>,
    /// The routers' catalog facts, shared by every page that validates a request.
    facts: Arc<page_kit::facts::FactsCache>,
    /// The router log collectors the log page follows instead of polling.
    log_feeds: LogFeeds,
    /// The shared pollers of the routers' logs that no collector follows.
    polled_logs: Arc<system_pages::log_poller::PolledLogs>,
    /// The audit log as the audit page last verified it.
    audit_log: admin_audit::log::LogCache,
    /// The Entware page's SSH services and their bounds.
    entware_ssh: Arc<system_pages::entware_ssh::SshAccess>,
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
            notify: None,
            schedules: None,
            mcp: None,
            oauth: None,
            advanced: Arc::new(advanced::Services::new(None)),
            facts: Arc::default(),
            log_feeds: LogFeeds::default(),
            polled_logs: Arc::default(),
            audit_log: admin_audit::log::LogCache::default(),
            entware_ssh: Arc::default(),
        }
    }

    /// Bounds the Entware page's SSH work: `timeouts` for its connections and commands,
    /// and `read_limit` for every list, status or log it reads, which then answers that
    /// the router is busy instead of waiting for a running change.
    #[inline]
    #[must_use]
    pub fn with_entware_ssh_timeouts(mut self, timeouts: Timeouts, read_limit: Duration) -> Self {
        self.entware_ssh = Arc::new(system_pages::entware_ssh::SshAccess::new(
            timeouts, read_limit,
        ));
        self
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

    /// Re-reads every account and ends the signed-in sessions it no longer backs: the
    /// account is gone or disabled, holds another role, or has another password than the
    /// session signed in with. Sign-ins and own password changes wait while it runs.
    /// Returns the accounts read and the number of sessions ended.
    ///
    /// # Errors
    ///
    /// [`StandingsError`] when `users.json` cannot be read or parsed; no session ends.
    // cancel-safe: as `SessionStore::end_stale`.
    #[inline]
    pub async fn end_stale_sessions(
        &self,
    ) -> Result<(BTreeMap<String, AccountStanding>, usize), StandingsError> {
        let accounts = Arc::clone(&self.accounts);
        self.sessions.end_stale(move || accounts.standings()).await
    }

    /// Attaches the router fleet: the overview, router dashboards and forms, and their
    /// live streams use these services. Without it those pages show a "not configured"
    /// notice and the streams answer `503`.
    #[inline]
    #[must_use]
    pub fn with_fleet(mut self, services: FleetServices) -> Self {
        self.fleet = Some(Arc::new(Fleet::new(services)));
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

    /// Attaches the running Telegram notifier: the notifications page shows its status,
    /// sends test messages through it and asks it to reload after a change. Without it
    /// the page still edits the settings and says they apply at the next start.
    #[inline]
    #[must_use]
    pub fn with_notify(mut self, control: Arc<dyn NotifyControl>) -> Self {
        self.notify = Some(control);
        self
    }

    /// The running notifier, when attached.
    #[must_use]
    pub(crate) fn notify(&self) -> Option<&dyn NotifyControl> {
        self.notify.as_deref()
    }

    /// Attaches the running scheduler: the scheduled actions page checks new, edited and
    /// resumed schedules with it and runs them now through it, and the router dashboards
    /// name each router's next scheduled action. Without it the page lists, pauses and
    /// deletes schedules and says that they run only in `kcc serve`.
    #[inline]
    #[must_use]
    pub fn with_schedules(mut self, control: Arc<dyn ScheduleControl>) -> Self {
        self.schedules = Some(control);
        self
    }

    /// The running scheduler, when attached.
    #[must_use]
    pub(crate) fn schedules(&self) -> Option<&dyn ScheduleControl> {
        self.schedules.as_deref()
    }

    /// Attaches the running MCP listeners: the MCP settings page applies its changes
    /// through them and reports how they started. Without it the page shows the settings
    /// and says they change only while `kcc serve` runs.
    #[inline]
    #[must_use]
    pub fn with_mcp_control(mut self, control: Arc<dyn McpControl>) -> Self {
        self.mcp = Some(Arc::new(admin_mcp::Attached::new(control)));
        self
    }

    /// Serves kcc's authorization server (`None`: no issuer, every OAuth route answers
    /// 404); its routes answer 404 as well while no listener signs in with kcc.
    #[inline]
    #[must_use]
    pub fn with_oauth(mut self, server: Option<Arc<OAuthServer>>) -> Self {
        self.oauth = server;
        self
    }

    /// kcc's authorization server, when attached.
    #[must_use]
    pub(crate) fn oauth(&self) -> Option<Arc<OAuthServer>> {
        self.oauth.clone()
    }

    /// The running MCP listeners and the page's restart progress, when attached.
    #[must_use]
    pub(crate) const fn mcp(&self) -> Option<&Arc<admin_mcp::Attached>> {
        self.mcp.as_ref()
    }

    /// The Entware page's SSH services and their bounds.
    #[must_use]
    pub(crate) fn entware_ssh(&self) -> &system_pages::entware_ssh::SshAccess {
        &self.entware_ssh
    }

    /// The shared wall clock.
    #[must_use]
    pub(crate) fn clock(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.clock)
    }

    /// The audit page's verified log.
    #[must_use]
    pub(crate) const fn audit_log(&self) -> &admin_audit::log::LogCache {
        &self.audit_log
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

    /// The shared pollers of the routers' logs.
    #[must_use]
    pub(crate) const fn polled_logs(&self) -> &Arc<system_pages::log_poller::PolledLogs> {
        &self.polled_logs
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
        .route("/ui/oauth/consent/approve", post(oauth_consent::approve))
        .route("/ui/oauth/consent/deny", post(oauth_consent::deny))
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
        .route("/ui/oauth/consent", get(oauth_consent::page))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            csrf::middleware,
        ));
    let bounded = Router::new()
        .merge(public)
        .merge(protected)
        .merge(oauth::routes())
        .layer(middleware::from_fn(brackets::budget));
    Router::new()
        .merge(bounded)
        .merge(streams)
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT))
        .layer(middleware::from_fn(oauth::oversized))
        .merge(dns_vpn::uploads(&state))
        .merge(mcp_uploads(&state))
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

/// The administration routes under `/ui/admin`: users, roles, API keys, notifications,
/// scheduled actions, audit and server.
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
        .route(
            "/ui/admin/notifications",
            get(admin_notify::page::page).post(admin_notify::settings::save),
        )
        .route(
            "/ui/admin/notifications/token",
            post(admin_notify::token::save_token),
        )
        .route(
            "/ui/admin/notifications/token/clear",
            get(admin_notify::token::clear_dialog).post(admin_notify::token::clear_token),
        )
        .route(
            "/ui/admin/notifications/chats",
            post(admin_notify::chats::add_chat),
        )
        .route(
            "/ui/admin/notifications/chats/remove",
            post(admin_notify::chats::remove_chat),
        )
        .route(
            "/ui/admin/notifications/test",
            post(admin_notify::test_send::send_test),
        )
        .merge(scheduled_routes())
        .route("/ui/admin/audit", get(admin_audit::page))
        .route("/ui/admin/audit/export", get(admin_audit::export))
        .route("/ui/admin/server", get(admin_server::page))
        .route(
            "/ui/admin/mcp",
            get(admin_mcp::page::page).post(admin_mcp::save::save),
        )
        .route("/ui/admin/mcp/reset", post(admin_mcp::save::reset))
        .route("/ui/admin/mcp/status", get(admin_mcp::status::status))
        .route(
            "/ui/admin/mcp/certificate",
            get(admin_mcp::certificate::download),
        )
        .route(
            admin_mcp_connections::PAGE,
            get(admin_mcp_connections::page),
        )
        .route(
            "/ui/admin/mcp/connections/revoke",
            post(admin_mcp_connections::changes::revoke),
        )
        .route(
            "/ui/admin/mcp/connections/revoke-account",
            post(admin_mcp_connections::changes::revoke_account),
        )
        .route(
            "/ui/admin/mcp/clients",
            post(admin_mcp_connections::register::register),
        )
        .route(
            "/ui/admin/mcp/clients/delete",
            post(admin_mcp_connections::changes::delete_client),
        )
}

/// The MCP settings CA upload, with its own body limit.
fn mcp_uploads(state: &WebState) -> Router<WebState> {
    let route = Router::new()
        .route("/ui/admin/mcp/ca", post(admin_mcp::upload::upload))
        .route_layer(DefaultBodyLimit::disable())
        .route_layer(RequestBodyLimitLayer::new(admin_mcp::upload::BODY_LIMIT));
    protect(route, state).route_layer(middleware::from_fn(brackets::budget))
}

/// The scheduled actions routes under `/ui/admin/scheduled`.
fn scheduled_routes() -> Router<WebState> {
    Router::new()
        .route(
            "/ui/admin/scheduled",
            get(admin_scheduled::page::page).post(admin_scheduled::editor::create),
        )
        .route(
            "/ui/admin/scheduled/new",
            get(admin_scheduled::editor::new_dialog),
        )
        .route(
            "/ui/admin/scheduled/edit",
            get(admin_scheduled::editor::edit_dialog).post(admin_scheduled::editor::update),
        )
        .route(
            "/ui/admin/scheduled/pause",
            post(admin_scheduled::toggle::pause),
        )
        .route(
            "/ui/admin/scheduled/resume",
            post(admin_scheduled::toggle::resume),
        )
        .route(
            "/ui/admin/scheduled/delete",
            get(admin_scheduled::toggle::delete_dialog).post(admin_scheduled::toggle::delete),
        )
        .route(
            "/ui/admin/scheduled/run-now",
            get(admin_scheduled::run_now::run_dialog).post(admin_scheduled::run_now::run_now),
        )
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
