//! What the administration pages need from the application: the state directory, the
//! seam that applies API-key and role changes to the running MCP transport, and the
//! facts the server page reports.
//!
//! `kcc` attaches them with [`WebState::with_admin`](crate::WebState::with_admin). The
//! pages live under `/ui/admin`: users, roles and API keys (`ManageUsers`), Telegram
//! notifications (`ManageNotifications`), scheduled actions (`ManageSchedules`), the audit
//! log (`ViewAudit`) and the server summary (`ManageUsers`).

extern crate alloc;

pub(crate) mod issuer;
pub mod mcp_control;

use alloc::{collections::BTreeMap, sync::Arc};
use core::{fmt, pin::Pin, time::Duration};
use std::sync::{Mutex, MutexGuard, PoisonError};

use kcc_app::{
    api_keys::api_key_entries,
    mcp_settings::{Candidate, Effective, ListenerKind, McpBase},
    permissions::{Role, ToolSpec, load_roles, rbac_config},
    persist::StateStore,
    role_source::RoleSource,
    settings::Config,
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    format, keys,
    locale::Locale,
};
use rmcp_server_kit::{auth::ApiKeyEntry, rbac::RbacPolicy, transport::ReloadHandle};

use self::{
    issuer::Issuer,
    mcp_control::{McpRefusal, McpStatus, McpToolset},
};
use crate::page::{Shell, Theme};

/// The future of one MCP settings change: applied and saved, or why not.
pub type McpChange = Pin<Box<dyn Future<Output = Result<(), McpRefusal>> + Send + 'static>>;

/// The running MCP listeners as the MCP settings page sees them.
///
/// The page plans a change with `mcp_settings::McpBase::plan_update` and hands the
/// candidate over; the control applies it and writes `mcp_settings.json` itself, so a
/// refused or reverted change leaves the file as it was.
pub trait McpControl: fmt::Debug + Send + Sync {
    /// Applies `candidate`, which restarts no listener, to the running MCP server and
    /// saves it. The change is queued when this is called; dropping the future does not
    /// stop it.
    fn apply_live(&self, candidate: Candidate) -> McpChange;

    /// Restarts every listener `candidate` names with it as one unit, then applies and
    /// saves it; a failed step serves the previous listeners again. The change is queued
    /// when this is called; dropping the future does not stop it.
    fn restart(&self, candidate: Candidate) -> McpChange;

    /// Replaces the client CA of the client-certificate sign-in with `pem` in the same
    /// serialized section, then restarts every listener using it as one unit; a failed
    /// restart puts the previous CA back and serves the previous listeners again.
    /// `confirmed` says the actor re-entered the password: while a listener uses client
    /// certificates, an unconfirmed replacement is refused with
    /// [`mcp_control::McpRefusal::ConfirmationRequired`].
    /// The change is queued when this is called; dropping the future does not stop it.
    fn replace_client_ca(&self, pem: Vec<u8>, confirmed: bool) -> McpChange;

    /// How the listeners started; cheap, never waits.
    fn status(&self) -> McpStatus;

    /// Every toolset the MCP server offers, in documentation order.
    fn toolsets(&self) -> Vec<McpToolset>;
}

/// Applies API-key and role changes to the running MCP transport without a restart.
pub trait AuthReload: fmt::Debug + Send + Sync {
    /// Re-reads the API keys from the state directory and installs them.
    ///
    /// # Errors
    ///
    /// [`ReloadError::NotReady`] before the transport has started; [`ReloadError::Failed`]
    /// when the keys cannot be read or installed. The previous keys stay active.
    fn reload_keys(&self) -> Result<(), ReloadError>;

    /// Re-reads the roles and installs the RBAC policy derived from them.
    ///
    /// # Errors
    ///
    /// As [`AuthReload::reload_keys`].
    fn reload_rbac(&self) -> Result<(), ReloadError>;
}

/// Why a change did not reach the running MCP transport.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReloadError {
    /// The transport has not handed out its reload handle yet.
    #[error("the MCP transport is not running yet")]
    NotReady,
    /// Reading the state or installing it failed.
    #[error("reload failed: {0}")]
    Failed(String),
}

/// [`AuthReload`] over rmcp-server-kit's [`ReloadHandle`]s: every running kit server
/// hands its handle to `McpServerConfig::with_reload_callback` when it starts, and the
/// callback [`register`](TransportReload::register)s it under its listener.
///
/// Key and role reloads reach every registered server; with none registered they change
/// only the shared role source and succeed.
pub struct TransportReload {
    /// The registered handles and the tool list, behind one lock that serializes every
    /// reload, so a reload that read the state earlier cannot install it over a later
    /// one, and a server registering meanwhile gets the latest state.
    live: Mutex<Live>,
    /// State directory holding `api_keys.json` and `roles.json`.
    state: StateStore,
    /// The role set the MCP handlers and the Web UI authorize against.
    roles: Option<RoleSource>,
}

/// The running kit servers and the tools their RBAC allows per role.
struct Live {
    /// Each running server's handle, by listener.
    handles: BTreeMap<ListenerKind, ReloadHandle>,
    /// Every registered MCP tool, for the per-role tool allowlists.
    tools: Vec<ToolSpec>,
}

impl fmt::Debug for TransportReload {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let registered: Vec<ListenerKind> = self.live().handles.keys().copied().collect();
        f.debug_struct("TransportReload")
            .field("registered", &registered)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl TransportReload {
    /// A reload bridge reading `state` and allowing `tools` per role, with no server
    /// registered yet.
    #[inline]
    #[must_use]
    pub const fn new(state: StateStore, tools: Vec<ToolSpec>) -> Self {
        Self {
            live: Mutex::new(Live {
                handles: BTreeMap::new(),
                tools,
            }),
            state,
            roles: None,
        }
    }

    /// Also replaces `roles` whenever roles are installed, so the MCP handlers' own
    /// permission and scope checks follow the transport's RBAC.
    #[inline]
    #[must_use]
    pub fn with_role_source(mut self, roles: RoleSource) -> Self {
        self.roles = Some(roles);
        self
    }

    /// The state directory the keys and roles are read from.
    #[inline]
    #[must_use]
    pub const fn state(&self) -> &StateStore {
        &self.state
    }

    /// Registers the running server of `kind`, replacing the one registered before
    /// under that listener, and installs the current API keys and RBAC policy in it.
    ///
    /// # Errors
    ///
    /// [`ReloadError::Failed`] when the keys or roles cannot be read or the kit refuses
    /// the keys; the server is registered all the same and keeps the keys it started
    /// with until the next reload.
    #[inline]
    pub fn register(&self, kind: ListenerKind, handle: ReloadHandle) -> Result<(), ReloadError> {
        let mut live = self.live();
        let installed = api_key_entries(&self.state)
            .map_err(failed)
            .and_then(|keys| handle.try_reload_auth_keys(keys).map_err(failed))
            .and_then(|()| {
                let roles = load_roles(&self.state).map_err(failed)?;
                handle.reload_rbac(RbacPolicy::new(&rbac_config(&roles, &live.tools)));
                Ok(())
            });
        drop(live.handles.insert(kind, handle));
        installed
    }

    /// Stops delivering reloads to the server of `kind`.
    #[inline]
    pub fn unregister(&self, kind: ListenerKind) {
        drop(self.live().handles.remove(&kind));
    }

    /// Replaces the tool list the per-role allowlists are built from; the next role
    /// install uses it.
    #[inline]
    pub fn set_tools(&self, tools: Vec<ToolSpec>) {
        self.live().tools = tools;
    }

    /// Installs `roles`: every running server's RBAC policy, then the shared role source.
    #[inline]
    pub fn install_roles(&self, roles: Vec<Role>) {
        let live = self.live();
        for handle in live.handles.values() {
            handle.reload_rbac(RbacPolicy::new(&rbac_config(&roles, &live.tools)));
        }
        if let Some(source) = &self.roles {
            source.replace(roles);
        }
        drop(live);
    }

    /// The registered servers and the tool list, locked.
    fn live(&self) -> MutexGuard<'_, Live> {
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Installs `keys` in every server of `live`.
    ///
    /// # Errors
    ///
    /// The first [`ReloadError::Failed`], once every server was tried; the previous keys
    /// stay active in every server that refused them.
    fn install_keys_in(live: &Live, keys: &[ApiKeyEntry]) -> Result<(), ReloadError> {
        live.handles
            .values()
            .map(|handle| handle.try_reload_auth_keys(keys.to_vec()).map_err(failed))
            .fold(Ok(()), Result::and)
    }
}

impl AuthReload for TransportReload {
    #[inline]
    fn reload_keys(&self) -> Result<(), ReloadError> {
        let live = self.live();
        Self::install_keys_in(&live, &api_key_entries(&self.state).map_err(failed)?)
    }

    #[inline]
    fn reload_rbac(&self) -> Result<(), ReloadError> {
        self.install_roles(load_roles(&self.state).map_err(failed)?);
        Ok(())
    }
}

/// The services the administration pages need.
#[derive(Debug)]
#[expect(
    clippy::exhaustive_structs,
    reason = "application integration constructs the complete admin wiring"
)]
#[expect(
    clippy::module_name_repetitions,
    reason = "integrators read it as `AdminServices` beside `FleetServices`"
)]
pub struct AdminServices {
    /// State directory holding `roles.json`, `api_keys.json` and the audit log.
    pub state: StateStore,
    /// Applies key and role changes to the running MCP transport; without it they take
    /// effect at the next start and the pages say so.
    pub reload: Option<Arc<dyn AuthReload>>,
    /// What the server page reports about this process.
    pub server: ServerFacts,
    /// kcc.toml's `[mcp]` and the environment as read at start: the roles the MCP
    /// settings name cannot be deleted.
    pub mcp: McpBase,
}

/// The server page's facts: the version and a configuration summary that leaves out
/// every secret and credential path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerFacts {
    /// Release version of the running binary.
    version: String,
    /// Configuration summary rows: label and value.
    summary: Vec<(MessageKey, Fact)>,
    /// The Bot API address of notifications, `[notify.telegram] api_url`.
    telegram_api: Option<String>,
    /// The zone schedule forms start with, `[schedules] default_timezone`.
    default_timezone: String,
    /// How long a listener restart may take: `server.shutdown_timeout` plus 10 seconds.
    restart_window: Duration,
    /// The issuer kcc's own authorization server would use.
    issuer: Issuer,
}

/// One configuration summary value, localized when the page renders.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Fact {
    /// Text shown as is.
    Text(String),
    /// Text, or "None" when absent or empty.
    Optional(Option<String>),
    /// Enabled or disabled.
    Switch(bool),
    /// A duration.
    Span(Duration),
    /// A count.
    Count(u64),
    /// A list, or "None" when empty.
    List(Vec<String>),
    /// A language tag, shown as the language's own name.
    Language(String),
}

impl Fact {
    /// The value in `locale`.
    fn render(&self, locale: Locale) -> String {
        let none = || tr(locale, keys::WEB_ADMIN_SERVER_NONE, None);
        match self {
            Self::Text(text) => text.clone(),
            Self::Optional(value) => value.clone().unwrap_or_else(none),
            Self::Switch(on) => tr(
                locale,
                if *on {
                    keys::COMMON_ENABLED
                } else {
                    keys::COMMON_DISABLED
                },
                None,
            ),
            Self::Span(value) => format::duration(locale, value.as_secs()),
            Self::Count(value) => format::integer(locale, *value),
            Self::List(items) if items.is_empty() => none(),
            Self::List(items) => items.join(", "),
            Self::Language(tag) => Locale::from_tag(tag).map_or_else(
                || tag.clone(),
                |language| {
                    tr(
                        locale,
                        Shell::new(language, Theme::System).locale_label(),
                        None,
                    )
                },
            ),
        }
    }
}

impl ServerFacts {
    /// The facts of a process running `version` with `config` and the effective MCP
    /// settings `effective`.
    #[inline]
    #[must_use]
    pub fn from_config(version: String, config: &Config, effective: &Effective) -> Self {
        let server = &config.server;
        let web = &config.web;
        let mcp = effective.settings();
        let networks = config
            .outbound
            .allowed_networks
            .iter()
            .map(ToString::to_string)
            .collect();
        let routers = u64::try_from(config.routers.len()).unwrap_or(u64::MAX);
        let summary = vec![
            (
                keys::WEB_ADMIN_SERVER_LISTENER,
                Fact::Text(format!("{}:{}", server.listen_addr, server.listen_port)),
            ),
            (
                keys::WEB_ADMIN_SERVER_TLS,
                Fact::Switch(config.listener_tls()),
            ),
            (
                keys::WEB_ADMIN_SERVER_PUBLIC_URL,
                Fact::Optional(web.public_url.as_ref().map(ToString::to_string)),
            ),
            (
                keys::WEB_ADMIN_SERVER_LANGUAGE,
                Fact::Language(web.default_locale.clone()),
            ),
            (
                keys::WEB_ADMIN_SERVER_SESSION_IDLE,
                Fact::Span(web.session_idle),
            ),
            (
                keys::WEB_ADMIN_SERVER_SESSION_LIFETIME,
                Fact::Span(web.session_absolute),
            ),
            (
                keys::WEB_ADMIN_SERVER_LOCKOUT_FAILURES,
                Fact::Count(u64::from(web.login_max_failures)),
            ),
            (keys::WEB_ADMIN_SERVER_LOCKOUT, Fact::Span(web.lockout)),
            (
                keys::WEB_ADMIN_SERVER_MCP_HTTP,
                Fact::Switch(mcp.http_enabled),
            ),
            (
                keys::WEB_ADMIN_SERVER_MCP_STDIO,
                Fact::Switch(mcp.stdio_enabled),
            ),
            (
                keys::WEB_ADMIN_SERVER_MCP_READ_ONLY,
                Fact::Switch(mcp.read_only),
            ),
            (
                keys::WEB_ADMIN_SERVER_MCP_DESTRUCTIVE,
                Fact::Switch(mcp.allow_destructive),
            ),
            (
                keys::WEB_ADMIN_SERVER_TOOLSETS,
                Fact::List(mcp.toolsets.clone()),
            ),
            (keys::WEB_ADMIN_SERVER_ROUTERS, Fact::Count(routers)),
            (keys::WEB_ADMIN_SERVER_NETWORKS, Fact::List(networks)),
            (
                keys::WEB_ADMIN_SERVER_BACKUPS_KEEP,
                Fact::Count(u64::from(config.backups.keep_last)),
            ),
            (
                keys::WEB_ADMIN_SERVER_BACKUPS_AGE,
                Fact::Span(config.backups.max_age),
            ),
            (
                keys::WEB_ADMIN_SERVER_AUDIT_RETENTION,
                Fact::Span(config.audit.retention),
            ),
        ];
        let telegram_api = config
            .notify
            .telegram
            .api_url
            .as_ref()
            .map(ToString::to_string);
        let shutdown =
            humantime::parse_duration(&server.shutdown_timeout).unwrap_or(Duration::from_secs(30));
        Self {
            version,
            summary,
            telegram_api,
            default_timezone: config.schedules.default_timezone.clone(),
            restart_window: shutdown.saturating_add(Duration::from_secs(10)),
            issuer: Issuer::of(config),
        }
    }

    /// How long a listener restart may take.
    #[must_use]
    pub(crate) const fn restart_window(&self) -> Duration {
        self.restart_window
    }

    /// The issuer of kcc's own authorization server, or why it has none.
    #[must_use]
    pub(crate) const fn issuer(&self) -> &Issuer {
        &self.issuer
    }

    /// Release version of the running binary.
    #[must_use]
    pub(crate) fn version(&self) -> &str {
        &self.version
    }

    /// The Bot API address of notifications, shown read-only.
    #[must_use]
    pub(crate) fn telegram_api(&self) -> Option<&str> {
        self.telegram_api.as_deref()
    }

    /// The zone schedule forms start with.
    #[must_use]
    pub(crate) fn default_timezone(&self) -> &str {
        &self.default_timezone
    }

    /// The configuration summary as `(label, value)` pairs in `locale`.
    #[must_use]
    pub(crate) fn summary(&self, locale: Locale) -> Vec<(String, String)> {
        self.summary
            .iter()
            .map(|(label, fact)| (tr(locale, *label, None), fact.render(locale)))
            .collect()
    }
}

/// A reload failure as [`ReloadError::Failed`], keeping only the display text.
fn failed<E>(error: E) -> ReloadError
where
    E: fmt::Display,
{
    ReloadError::Failed(error.to_string())
}
