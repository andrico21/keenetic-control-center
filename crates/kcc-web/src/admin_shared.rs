//! Plumbing shared by the administration pages.
//!
//! The attached services and change lock, the privilege guards, the tab bar, pagination
//! and the administration audit records. Shells, typed-name confirmations, toasts and the
//! audit writer come from the page kit.

extern crate alloc;

pub(crate) mod roles;

use alloc::sync::Arc;
use core::time::Duration;
use std::time::UNIX_EPOCH;

use askama::Template;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Redirect, Response},
};
use fluent_bundle::FluentArgs;
use kcc_app::{
    mcp_settings::McpBase,
    permissions::{Permission, Role},
    persist::StateStore,
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use serde::Deserialize;
use serde_json::Value;
use tokio::{
    sync::{Mutex, MutexGuard},
    task::spawn_blocking,
};
use url::form_urlencoded;

use crate::{
    WebState,
    admin::{AdminServices, AuthReload, ReloadError, ServerFacts},
    authz::{CurrentSession, CurrentUser},
    errors::{self, Kind},
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::{
        audit::Record,
        context::{Caller, fragment_shell},
        outcome::Toast,
    },
};

/// Longest router-scope glob accepted for a custom role.
const MAX_GLOB_CHARS: usize = 64;

/// The attached administration services and the Web UI's administration state.
pub(crate) struct Admin {
    /// Services `kcc` attached.
    services: AdminServices,
    /// Serializes administrative changes, so each check sees the previous write.
    changes: Mutex<()>,
    /// Unix time the services were attached: the process start, for the uptime.
    started_at: u64,
}

impl Admin {
    /// Wraps `services` attached at `started_at`.
    pub(crate) fn new(services: AdminServices, started_at: u64) -> Self {
        Self {
            services,
            changes: Mutex::new(()),
            started_at,
        }
    }

    /// State directory with roles, API keys and the audit log.
    pub(crate) const fn state(&self) -> &StateStore {
        &self.services.state
    }

    /// The server page's facts.
    pub(crate) const fn server(&self) -> &ServerFacts {
        &self.services.server
    }

    /// kcc.toml's `[mcp]` and the environment as read at start.
    pub(crate) const fn mcp(&self) -> &McpBase {
        &self.services.mcp
    }

    /// Unix time the process started.
    pub(crate) const fn started_at(&self) -> u64 {
        self.started_at
    }

    /// Waits for the administrative change lock.
    // cancel-safe: it only waits for the administration lock.
    pub(crate) async fn lock(&self) -> MutexGuard<'_, ()> {
        self.changes.lock().await
    }

    /// Installs the stored API keys in the running MCP transport; a warning message
    /// when they did not reach it.
    // cancel-safe: the reload runs whole on a blocking thread even if the future is dropped; only
    // its warning is lost.
    pub(crate) async fn reload_keys(&self) -> Option<MessageKey> {
        self.reload(|bridge| bridge.reload_keys()).await
    }

    /// Installs the stored roles in the running MCP transport; a warning message when
    /// they did not reach it.
    // cancel-safe: the reload runs whole on a blocking thread even if the future is dropped; only
    // its warning is lost.
    pub(crate) async fn reload_rbac(&self) -> Option<MessageKey> {
        self.reload(|bridge| bridge.reload_rbac()).await
    }

    /// Runs one reload off the async executor and maps its outcome to a warning.
    // cancel-safe: the reload runs whole on a blocking thread even if the future is dropped; only
    // its warning is lost.
    async fn reload<F>(&self, apply: F) -> Option<MessageKey>
    where
        F: FnOnce(&dyn AuthReload) -> Result<(), ReloadError> + Send + 'static,
    {
        let Some(bridge) = self.services.reload.as_ref().map(Arc::clone) else {
            return Some(keys::WEB_ADMIN_RELOAD_PENDING);
        };
        match spawn_blocking(move || apply(bridge.as_ref())).await {
            Ok(Ok(())) => None,
            Ok(Err(ReloadError::NotReady)) => Some(keys::WEB_ADMIN_RELOAD_PENDING),
            Ok(Err(error)) => {
                tracing::error!(%error, "MCP authentication reload failed");
                Some(keys::WEB_ADMIN_RELOAD_FAILED)
            }
            Err(error) => {
                tracing::error!(%error, "MCP authentication reload task failed");
                Some(keys::WEB_ADMIN_RELOAD_FAILED)
            }
        }
    }
}

/// Whether `glob` is a router-scope glob under rmcp-server-kit's rules for router ids:
/// lowercase letters, digits, `-` and the `*` wildcard only (no `?` or `[...]`).
pub(crate) fn valid_glob(glob: &str) -> bool {
    (1..=MAX_GLOB_CHARS).contains(&glob.len())
        && glob
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-*".contains(&byte))
}

/// A table's page query: `?page=N`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListQuery {
    /// Requested page, from 1; anything else shows the first.
    page: Option<String>,
}

impl ListQuery {
    /// The requested page.
    pub(crate) fn page(&self) -> usize {
        self.page
            .as_deref()
            .and_then(|page| page.parse().ok())
            .unwrap_or(1)
    }
}

/// A dialog query naming its account, role or key: `?name=`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NameQuery {
    /// Account, role or key name.
    name: String,
}

impl NameQuery {
    /// Account, role or key name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}

/// A form naming an account, role or key.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NameForm {
    /// Account, role or key name.
    name: String,
}

impl NameForm {
    /// Account, role or key name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}

/// One page of the administration area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tab {
    /// Accounts.
    Users,
    /// Custom roles.
    Roles,
    /// MCP API keys.
    Keys,
    /// Telegram notifications.
    Notifications,
    /// Scheduled actions.
    Scheduled,
    /// The audit log.
    Audit,
    /// The server summary.
    Server,
}

impl Tab {
    /// Every page, in tab order.
    const ALL: [Self; 7] = [
        Self::Users,
        Self::Roles,
        Self::Keys,
        Self::Notifications,
        Self::Scheduled,
        Self::Audit,
        Self::Server,
    ];

    /// The page's URL.
    pub(crate) const fn href(self) -> &'static str {
        match self {
            Self::Users => "/ui/admin/users",
            Self::Roles => "/ui/admin/roles",
            Self::Keys => "/ui/admin/api-keys",
            Self::Notifications => "/ui/admin/notifications",
            Self::Scheduled => "/ui/admin/scheduled",
            Self::Audit => "/ui/admin/audit",
            Self::Server => "/ui/admin/server",
        }
    }

    /// The tab label, also the page title.
    pub(crate) const fn label(self) -> MessageKey {
        match self {
            Self::Users => keys::WEB_ADMIN_TAB_USERS,
            Self::Roles => keys::WEB_ADMIN_TAB_ROLES,
            Self::Keys => keys::WEB_ADMIN_TAB_KEYS,
            Self::Notifications => keys::WEB_ADMIN_NOTIFY_TAB,
            Self::Scheduled => keys::WEB_ADMIN_SCHEDULED_TAB,
            Self::Audit => keys::WEB_ADMIN_TAB_AUDIT,
            Self::Server => keys::WEB_ADMIN_TAB_SERVER,
        }
    }

    /// The permission the page needs.
    const fn permission(self) -> Permission {
        match self {
            Self::Audit => Permission::ViewAudit,
            Self::Notifications => Permission::ManageNotifications,
            Self::Scheduled => Permission::ManageSchedules,
            Self::Users | Self::Roles | Self::Keys | Self::Server => Permission::ManageUsers,
        }
    }
}

/// One link of the administration tab bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TabLink {
    /// The linked page.
    tab: Tab,
    /// Whether it is the page shown.
    current: bool,
}

impl TabLink {
    /// The page's URL.
    pub(crate) const fn href(self) -> &'static str {
        self.tab.href()
    }

    /// The tab label.
    pub(crate) const fn label(self) -> MessageKey {
        self.tab.label()
    }

    /// Whether it is the page shown (`aria-current="page"`).
    pub(crate) const fn current(self) -> bool {
        self.current
    }
}

/// The tabs `role` may open, marking `current`.
pub(crate) fn tabs(role: &Role, current: Tab) -> Vec<TabLink> {
    Tab::ALL
        .into_iter()
        .filter(|tab| role.grants(tab.permission()))
        .map(|tab| TabLink {
            tab,
            current: tab == current,
        })
        .collect()
}

/// `GET /ui/admin`: the first administration page the role may open, else 403.
// cancel-safe: it only reads local state to render the page.
pub(crate) async fn landing(
    State(state): State<WebState>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    match tabs(user.role(), Tab::Users).first() {
        Some(link) => Redirect::to(link.href()).into_response(),
        None => errors::response(
            Kind::Forbidden,
            Caller::new(&headers, &current, &user)
                .shell(&state, Section::Admin, None)
                .await,
        ),
    }
}

/// The page shown when `kcc` attached no administration services.
#[derive(Template)]
#[template(path = "pages/admin_unavailable.html")]
struct Unavailable {
    /// Page shell.
    shell: Shell,
}

localized!(Unavailable);

/// Answers a page request without administration services: a notice page, or `503`
/// for a change.
pub(crate) fn unavailable(page: Option<Shell>) -> Response {
    let mut response = page.map_or_else(
        || StatusCode::SERVICE_UNAVAILABLE.into_response(),
        |shell| errors::render(&Unavailable { shell }),
    );
    *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
    response
}

/// `base?name=<name>`, with `name` URL-encoded.
pub(crate) fn named(base: &str, name: &str) -> String {
    let query: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("name", name)
        .finish();
    format!("{base}?{query}")
}

/// A Unix time: UTC text in a `<time>` element that `app.js` shows in local time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Timestamp {
    /// RFC 3339 form, the `datetime` attribute.
    iso: String,
    /// UTC text shown before `app.js` localizes it.
    text: String,
}

impl Timestamp {
    /// The time `unix` seconds after the epoch, if representable, with its UTC text in
    /// `locale`.
    pub(crate) fn at(unix: u64, locale: Locale) -> Option<Self> {
        let time = UNIX_EPOCH.checked_add(Duration::from_secs(unix))?;
        let iso = humantime::format_rfc3339_seconds(time).to_string();
        let mut args = FluentArgs::new();
        args.set("time", iso.trim_end_matches('Z').replacen('T', " ", 1));
        let text = tr(locale, keys::WEB_TIME_UTC, Some(&args));
        Some(Self { iso, text })
    }

    /// RFC 3339 form, the `datetime` attribute.
    pub(crate) fn iso(&self) -> &str {
        &self.iso
    }

    /// UTC text.
    pub(crate) fn text(&self) -> &str {
        &self.text
    }
}

/// The toasts of a completed change: `done`, plus a warning when the MCP transport did
/// not take it.
pub(crate) fn done_toasts(
    locale: Locale,
    done: MessageKey,
    warning: Option<MessageKey>,
) -> Vec<Toast> {
    let mut toasts = vec![Toast::success(locale, done)];
    toasts.extend(warning.map(|key| Toast::warning(locale, key)));
    toasts
}

/// An administrative change as the audit log records it.
pub(crate) struct Change<'target> {
    /// Stable action id, such as `admin.user_create`.
    action: &'static str,
    /// The account, role or key changed.
    target: &'target str,
    /// Redacted parameters; never a password or key.
    params: Value,
    /// `success`, or why the change was refused.
    outcome: &'static str,
}

impl<'target> Change<'target> {
    /// A completed change.
    pub(crate) const fn done(action: &'static str, target: &'target str, params: Value) -> Self {
        Self {
            action,
            target,
            params,
            outcome: "success",
        }
    }

    /// A change refused with `outcome`, such as `forbidden` or `last_admin`.
    pub(crate) const fn refused(
        action: &'static str,
        target: &'target str,
        outcome: &'static str,
    ) -> Self {
        Self {
            action,
            target,
            params: Value::Null,
            outcome,
        }
    }
}

/// Appends `change` to the audit log; a failed append is logged, the change stands.
// NOT cancel-safe: an abandoned append may still be written.
pub(crate) async fn record(state: &WebState, user: &CurrentUser, change: Change<'_>) {
    Record::new(change.action, change.target.to_owned())
        .with_params(change.params)
        .append(state, user, change.outcome)
        .await;
}

/// A refused change: audited, then answered with the localized 403 page.
// NOT cancel-safe: the refusal's audit entry may be written after the future is dropped.
pub(crate) async fn forbidden(
    state: &WebState,
    user: &CurrentUser,
    change: Change<'_>,
) -> Response {
    record(state, user, change).await;
    errors::response(Kind::Forbidden, fragment_shell(user.locale()))
}
