//! Plumbing shared by the administration pages: the attached services and change lock,
//! the privilege guards, the tab bar, pagination, outcomes and audit records.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;
use std::time::UNIX_EPOCH;

use askama::Template;
use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse as _, Redirect, Response},
};
use fluent_bundle::FluentArgs;
use kcc_app::{
    audit::{Actor, ActorKind, AuditEvent},
    permissions::{Permission, Role, built_in_roles},
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
use url::{Url, form_urlencoded};

use crate::{
    WebState,
    admin::{AdminServices, AuthReload, ReloadError, ServerFacts},
    auth,
    authz::{CurrentSession, CurrentUser},
    errors::{self, Kind},
    nav::Section,
    overview::masthead,
    page::{Localize, Shell, Theme},
    prefs,
};

/// Rows per table page.
pub(crate) const PAGE_ROWS: usize = 50;

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

    /// Unix time the process started.
    pub(crate) const fn started_at(&self) -> u64 {
        self.started_at
    }

    /// Waits for the administrative change lock.
    pub(crate) async fn lock(&self) -> MutexGuard<'_, ()> {
        self.changes.lock().await
    }

    /// Installs the stored API keys in the running MCP transport; a warning message
    /// when they did not reach it.
    pub(crate) async fn reload_keys(&self) -> Option<MessageKey> {
        self.reload(|bridge| bridge.reload_keys()).await
    }

    /// Installs the stored roles in the running MCP transport; a warning message when
    /// they did not reach it.
    pub(crate) async fn reload_rbac(&self) -> Option<MessageKey> {
        self.reload(|bridge| bridge.reload_rbac()).await
    }

    /// Runs one reload off the async executor and maps its outcome to a warning.
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

/// Whether `actor` holds every permission of `target` and covers its whole router
/// scope, so granting or managing `target` cannot raise anyone above `actor`.
pub(crate) fn dominates(actor: &Role, target: &Role) -> bool {
    let everything = [String::from("*")];
    let scope = if target.router_scope.is_empty() {
        &everything[..]
    } else {
        &*target.router_scope
    };
    target
        .permissions
        .iter()
        .all(|permission| actor.grants(*permission))
        && scope.iter().all(|glob| covered(&actor.router_scope, glob))
}

/// Whether every router `glob` can match is matched by `scope`: a conservative check
/// on the kit's `*`-only globs (equal globs, `*`, or a literal prefix followed by `*`).
fn covered(scope: &[String], glob: &str) -> bool {
    scope.is_empty()
        || scope.iter().any(|outer| {
            outer == "*"
                || outer == glob
                || outer
                    .strip_suffix('*')
                    .is_some_and(|prefix| !prefix.contains('*') && glob.starts_with(prefix))
        })
}

/// Whether `glob` is a router-scope glob under rmcp-server-kit's rules for router ids:
/// lowercase letters, digits, `-` and the `*` wildcard only (no `?` or `[...]`).
pub(crate) fn valid_glob(glob: &str) -> bool {
    (1..=MAX_GLOB_CHARS).contains(&glob.len())
        && glob
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-*".contains(&byte))
}

/// Whether `name` is one of the three immutable built-in roles.
pub(crate) fn is_built_in(name: &str) -> bool {
    built_in_roles().iter().any(|role| role.name == name)
}

/// `roles` in display order: built-in roles in rising privilege, then custom roles by
/// name.
pub(crate) fn ordered(roles: &[Role]) -> Vec<Role> {
    let built_in = built_in_roles();
    let rank = |role: &Role| {
        built_in
            .iter()
            .position(|candidate| candidate.name == role.name)
            .unwrap_or(built_in.len())
    };
    let mut sorted = roles.to_vec();
    sorted.sort_by(|left, right| {
        rank(left)
            .cmp(&rank(right))
            .then_with(|| left.name.cmp(&right.name))
    });
    sorted
}

/// The roles `actor` may grant, in display order.
pub(crate) fn roles_for(roles: &[Role], actor: &Role) -> Vec<Role> {
    ordered(roles)
        .into_iter()
        .filter(|role| dominates(actor, role))
        .collect()
}

/// The display name of the role `name`: built-in roles are translated, custom roles
/// keep their name.
pub(crate) fn role_label(locale: Locale, name: &str) -> String {
    match name {
        "viewer" => tr(locale, keys::WEB_ADMIN_ROLE_VIEWER, None),
        "operator" => tr(locale, keys::WEB_ADMIN_ROLE_OPERATOR, None),
        "admin" => tr(locale, keys::WEB_ADMIN_ROLE_ADMIN, None),
        custom => custom.to_owned(),
    }
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

/// A typed-name confirmation: `confirm` must repeat `name`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConfirmForm {
    /// Account, role or key name.
    name: String,
    /// The name as typed by the user.
    confirm: String,
}

impl ConfirmForm {
    /// Account, role or key name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Whether the typed name matches.
    pub(crate) fn confirmed(&self) -> bool {
        self.confirm.trim() == self.name
    }
}

/// The typed-name confirmation of a destructive change.
#[derive(Template)]
#[template(path = "partials/admin_confirm.html")]
pub(crate) struct ConfirmDialog {
    /// Locale carrier.
    shell: Shell,
    /// Question naming the object.
    title: String,
    /// What the change does.
    text: MessageKey,
    /// "Type <name> to confirm."
    help: String,
    /// Form target.
    action: &'static str,
    /// The object's name.
    name: String,
    /// Mismatch or refusal message.
    error: String,
    /// The confirming button's label.
    button: MessageKey,
}

impl Localize for ConfirmDialog {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

impl ConfirmDialog {
    /// The confirmation posting `name` to `action`, with the `(title, text)` messages;
    /// the title may use `$name`.
    pub(crate) fn new(
        shell: Shell,
        action: &'static str,
        name: &str,
        (title, text): (MessageKey, MessageKey),
    ) -> Self {
        let mut args = FluentArgs::new();
        args.set("name", name.to_owned());
        let locale = shell.locale();
        Self {
            title: tr(locale, title, Some(&args)),
            help: tr(locale, keys::WEB_ADMIN_CONFIRM_HELP, Some(&args)),
            shell,
            text,
            action,
            name: name.to_owned(),
            error: String::new(),
            button: keys::COMMON_DELETE,
        }
    }

    /// Labels the confirming button with `button`.
    pub(crate) const fn with_button(mut self, button: MessageKey) -> Self {
        self.button = button;
        self
    }

    /// Shows `error` under the typed name.
    pub(crate) fn set_error(&mut self, error: String) {
        self.error = error;
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
    /// The audit log.
    Audit,
    /// The server summary.
    Server,
}

impl Tab {
    /// Every page, in tab order.
    const ALL: [Self; 5] = [
        Self::Users,
        Self::Roles,
        Self::Keys,
        Self::Audit,
        Self::Server,
    ];

    /// The page's URL.
    pub(crate) const fn href(self) -> &'static str {
        match self {
            Self::Users => "/ui/admin/users",
            Self::Roles => "/ui/admin/roles",
            Self::Keys => "/ui/admin/api-keys",
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
            Self::Audit => keys::WEB_ADMIN_TAB_AUDIT,
            Self::Server => keys::WEB_ADMIN_TAB_SERVER,
        }
    }

    /// The permission the page needs.
    const fn permission(self) -> Permission {
        match self {
            Self::Audit => Permission::ViewAudit,
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
            page_shell(&state, &headers, &current, &user).await,
        ),
    }
}

/// The full-page shell of an administration page.
pub(crate) async fn page_shell(
    state: &WebState,
    headers: &HeaderMap,
    current: &CurrentSession,
    user: &CurrentUser,
) -> Shell {
    prefs::shell_for_locale(headers, user.locale())
        .with_csrf_token(current.session().csrf_token().to_owned())
        .with_section(Section::Admin)
        .with_fleet(masthead(state, user.role(), None).await, None)
}

/// The shell of a fragment: a dialog body or a table region.
pub(crate) const fn fragment_shell(user: &CurrentUser) -> Shell {
    Shell::new(user.locale(), Theme::System)
}

/// The page shown when `kcc` attached no administration services.
#[derive(Template)]
#[template(path = "pages/admin_unavailable.html")]
struct Unavailable {
    /// Page shell.
    shell: Shell,
}

impl Localize for Unavailable {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

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

/// One page of a table, with links to its neighbours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pager {
    /// Shown page, from 1.
    current: usize,
    /// Number of pages, at least 1.
    total: usize,
    /// Path of the table's page.
    path: &'static str,
    /// Query parameters other than `page`, kept in the links.
    query: Vec<(String, String)>,
}

impl Pager {
    /// Cuts the `requested` page (clamped to the last) out of `rows`.
    pub(crate) fn paginate<T>(
        rows: Vec<T>,
        requested: usize,
        path: &'static str,
        query: Vec<(String, String)>,
    ) -> (Vec<T>, Self) {
        let total = rows.len().div_ceil(PAGE_ROWS).max(1);
        let current = requested.clamp(1, total);
        let skip = current.saturating_sub(1).saturating_mul(PAGE_ROWS);
        let page = rows.into_iter().skip(skip).take(PAGE_ROWS).collect();
        (
            page,
            Self {
                current,
                total,
                path,
                query,
            },
        )
    }

    /// Whether the table has more than one page.
    pub(crate) const fn multiple(&self) -> bool {
        self.total > 1
    }

    /// The previous page's link.
    pub(crate) fn previous(&self) -> Option<String> {
        (self.current > 1).then(|| self.href(self.current.saturating_sub(1)))
    }

    /// The next page's link.
    pub(crate) fn next(&self) -> Option<String> {
        (self.current < self.total).then(|| self.href(self.current.saturating_add(1)))
    }

    /// "Page 2 of 3" in `locale`.
    pub(crate) fn status(&self, locale: Locale) -> String {
        let mut args = FluentArgs::new();
        args.set("current", self.current);
        args.set("total", self.total);
        tr(locale, keys::WEB_ADMIN_PAGE_STATUS, Some(&args))
    }

    /// The link to `page` with the other query parameters.
    fn href(&self, page: usize) -> String {
        let mut query = form_urlencoded::Serializer::new(String::new());
        for (name, value) in &self.query {
            let _: &mut form_urlencoded::Serializer<'_, String> = query.append_pair(name, value);
        }
        let _: &mut form_urlencoded::Serializer<'_, String> =
            query.append_pair("page", &page.to_string());
        format!("{}?{}", self.path, query.finish())
    }
}

/// The page number the browser shows: `page` from htmx's `HX-Current-URL`, else 1.
pub(crate) fn shown_page(headers: &HeaderMap) -> usize {
    headers
        .get("hx-current-url")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Url::parse(value).ok())
        .and_then(|url| {
            url.query_pairs()
                .find_map(|(name, value)| (name == "page").then(|| value.parse().ok()))
                .flatten()
        })
        .unwrap_or(1)
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
    /// The time `unix` seconds after the epoch, if representable.
    pub(crate) fn at(unix: u64) -> Option<Self> {
        let time = UNIX_EPOCH.checked_add(Duration::from_secs(unix))?;
        let iso = humantime::format_rfc3339_seconds(time).to_string();
        let text = format!("{} UTC", iso.trim_end_matches('Z').replacen('T', " ", 1));
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

/// A toast sent with a change's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Toast {
    /// `success`, `warning` or `error`.
    tone: &'static str,
    /// The localized message.
    message: String,
}

impl Toast {
    /// A success toast with `key` in `locale`.
    pub(crate) fn success(locale: Locale, key: MessageKey) -> Self {
        Self {
            tone: "success",
            message: tr(locale, key, None),
        }
    }

    /// A warning toast with `key` in `locale`.
    pub(crate) fn warning(locale: Locale, key: MessageKey) -> Self {
        Self {
            tone: "warning",
            message: tr(locale, key, None),
        }
    }

    /// An error toast with `key` in `locale`.
    pub(crate) fn error(locale: Locale, key: MessageKey) -> Self {
        Self {
            tone: "error",
            message: tr(locale, key, None),
        }
    }

    /// The toast tone.
    pub(crate) const fn tone(&self) -> &'static str {
        self.tone
    }

    /// The localized message.
    pub(crate) fn message(&self) -> &str {
        &self.message
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

/// Answers a change with `region` (which carries its table and toasts out of band) and
/// `status`. A change made from the dialog closes it and leaves its content unswapped.
pub(crate) fn respond<T>(region: &T, status: StatusCode, from_dialog: bool) -> Response
where
    T: Template + Localize,
{
    let mut response = errors::render(region);
    *response.status_mut() = status;
    if from_dialog {
        let headers = response.headers_mut();
        drop(headers.insert("hx-reswap", HeaderValue::from_static("none")));
        drop(headers.insert(
            "hx-trigger-after-swap",
            HeaderValue::from_static("kcc:dialog-close"),
        ));
    }
    response
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
    let event = AuditEvent::new(
        state.unix_seconds(),
        Actor::new(ActorKind::Web, user.username().to_owned()),
        change.action.to_owned(),
    )
    .with_target(change.target.to_owned())
    .with_params(change.params)
    .with_result(change.outcome.to_owned(), auth::request_id());
    if let Err(error) = state.audit().append(event).await {
        tracing::error!(%error, action = change.action, "administration audit failed");
    }
}

/// A refused change: audited, then answered with the localized 403 page.
pub(crate) async fn forbidden(
    state: &WebState,
    user: &CurrentUser,
    change: Change<'_>,
) -> Response {
    record(state, user, change).await;
    errors::response(Kind::Forbidden, fragment_shell(user))
}
