//! Custom roles at `/ui/admin/roles` (`ManageUsers`).
//!
//! Built-in roles are listed read-only. A custom role is a name, permission checkboxes
//! and router-scope globs under rmcp-server-kit's `*`-only rules. Nobody creates or
//! edits a role above their own, edits or deletes the role they hold, shadows a
//! built-in name, or deletes a role an account or API key still uses. A change rewrites
//! `roles.json`, refreshes the Web UI's roles, ends the sessions holding the role and
//! installs the new RBAC policy in the running MCP transport.

extern crate alloc;

mod form;
mod table;

use alloc::collections::BTreeSet;
use core::error::Error;

use askama::Template;
use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_app::{
    mcp_settings::{McpBase, SettingsError},
    permissions::{
        KCC_ACCOUNT_ROLE, Permission, Role, RolesDocument,
        assignment::{holder_counts, remove_unheld},
        load_roles,
    },
    persist::StateStore,
};
use kcc_domain::labels;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use serde_json::{Value, json};
use tokio::task::spawn_blocking;

use self::form::{RoleForm, checkboxes};
use crate::{
    WebState,
    admin_shared::{
        Change, ListQuery, NameQuery, Tab, TabLink, done_toasts, forbidden, named, record,
        roles::{is_built_in, ordered, role_label},
        tabs, unavailable, valid_glob,
    },
    authz::{CurrentSession, CurrentUser},
    errors,
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::{
        confirm::{Dialog, TypedNameForm},
        context::{Caller, fragment_shell},
        outcome::Toast,
        respond,
    },
    table::{
        pager::{Pager, shown_page},
        view::TableView,
    },
};

/// Most router-scope globs per custom role.
const MAX_GLOBS: usize = 16;

/// Longest custom role name.
const MAX_NAME_CHARS: usize = 32;

/// One role row.
struct RoleRow {
    /// Display name.
    label: String,
    /// Whether it is a built-in role.
    built_in: bool,
    /// The granted permissions, translated.
    permissions: String,
    /// The router-scope globs.
    scope: String,
    /// Accounts and API keys holding it.
    holders: usize,
    /// Whether the signed-in user may edit it.
    editable: bool,
    /// Whether the signed-in user may delete it now.
    deletable: bool,
    /// The edit dialog.
    edit_url: String,
    /// The delete dialog.
    delete_url: String,
}

/// The roles table.
#[derive(Template)]
#[template(path = "partials/admin_roles_region.html")]
struct RolesRegion {
    /// Locale carrier.
    shell: Shell,
    /// The shown page of roles.
    table: TableView,
    /// Table pagination.
    pager: Pager,
    /// Whether this is an out-of-band update.
    oob: bool,
    /// Outcome toasts of the change.
    toasts: Vec<Toast>,
}

localized!(RolesRegion);
fragment!(RolesRegion);

/// The roles page.
#[derive(Template)]
#[template(path = "pages/admin_roles.html")]
struct RolesPage {
    /// Page shell.
    shell: Shell,
    /// Administration tabs.
    tabs: Vec<TabLink>,
    /// The roles table.
    region: RolesRegion,
}

localized!(RolesPage);

/// One permission checkbox.
struct PermissionCheck {
    /// Form field name.
    field: &'static str,
    /// Label.
    label: MessageKey,
    /// Whether it is ticked.
    checked: bool,
    /// Whether the signed-in user holds it and may grant it.
    grantable: bool,
}

/// The create and edit dialog.
#[derive(Template)]
#[template(path = "partials/admin_role_form.html")]
struct RoleDialog {
    /// Locale carrier.
    shell: Shell,
    /// Dialog title.
    title: String,
    /// Form target.
    action: &'static str,
    /// Whether an existing role is edited (its name is fixed).
    editing: bool,
    /// Role name.
    role_name: String,
    /// Permission checkboxes.
    checks: Vec<PermissionCheck>,
    /// Router-scope globs as typed.
    scope: String,
    /// Name error.
    name_error: String,
    /// Permissions error.
    permissions_error: String,
    /// Router-scope error.
    scope_error: String,
}

localized!(RoleDialog);

/// `GET /ui/admin/roles`.
// cancel-safe: it only reads the role store on a blocking thread.
pub(crate) async fn page(
    State(state): State<WebState>,
    Query(query): Query<ListQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Admin, None)
        .await;
    if state.admin().is_none() {
        return unavailable(Some(shell));
    }
    match region(&state, &user, query.page(), Vec::new(), false).await {
        Ok(region) => errors::render(&RolesPage {
            tabs: tabs(user.role(), Tab::Roles),
            shell,
            region,
        }),
        Err(error) => errors::internal(&error, shell),
    }
}

/// `GET /ui/admin/roles/new`: the create dialog.
// cancel-safe: it has no await point.
pub(crate) async fn new_dialog(user: CurrentUser) -> Response {
    let scope = if user
        .role()
        .dominates(&Role::new(String::new(), [], vec!["*".to_owned()]))
    {
        "*".to_owned()
    } else {
        user.role().router_scope.join(", ")
    };
    let read = BTreeSet::from([Permission::Read]);
    errors::render(&dialog(&user, None, String::new(), &read, scope))
}

/// `POST /ui/admin/roles`: adds a custom role.
// NOT cancel-safe: the role file is written on a blocking thread that finishes even if the future
// is dropped, leaving the role set not reloaded and the change unaudited.
pub(crate) async fn create(
    State(state): State<WebState>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let _changes = admin.lock().await;
    let form = RoleForm::parse(pairs);
    let role = match validate(&state, &user, &form, None).await {
        Ok(role) => role,
        Err(response) => return *response,
    };
    let edit = Edit::Create(role.clone());
    match persist(&state, &user, edit).await {
        Ok(Persisted::Done) => {}
        Ok(Persisted::Exists) => {
            let mut page = form_dialog(&user, None, &form);
            page.name_error = tr(user.locale(), keys::WEB_ADMIN_ERROR_ROLE_EXISTS, None);
            return respond::unprocessable(&page);
        }
        Ok(Persisted::Missing | Persisted::InUse) => {
            return StatusCode::CONFLICT.into_response();
        }
        Err(response) => return *response,
    }
    let warning = admin.reload_rbac().await;
    record(
        &state,
        &user,
        Change::done("admin.role_create", &role.name, params(&role)),
    )
    .await;
    let toasts = done_toasts(user.locale(), keys::WEB_ADMIN_ROLE_CREATED, warning);
    finish(&state, &user, &headers, toasts).await
}

/// `GET /ui/admin/roles/edit?name=`: the edit dialog.
// NOT cancel-safe: a refusal queues an audit entry that may be written after the future is dropped;
// otherwise it only reads.
pub(crate) async fn edit_dialog(
    State(state): State<WebState>,
    Query(query): Query<NameQuery>,
    user: CurrentUser,
) -> Response {
    match editable(&state, &user, query.name(), "admin.role_update").await {
        Ok(role) => errors::render(&dialog(
            &user,
            Some(&role.name),
            role.name.clone(),
            &role.permissions,
            role.router_scope.join(", "),
        )),
        Err(response) => *response,
    }
}

/// `POST /ui/admin/roles/edit`: replaces a custom role's permissions and scope.
// NOT cancel-safe: the role file is written on a blocking thread that finishes even if the future
// is dropped, leaving the role's sessions alive, the role set not reloaded and the change
// unaudited.
pub(crate) async fn update(
    State(state): State<WebState>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let _changes = admin.lock().await;
    let form = RoleForm::parse(pairs);
    let previous = match editable(&state, &user, form.name(), "admin.role_update").await {
        Ok(role) => role,
        Err(response) => return *response,
    };
    let role = match validate(&state, &user, &form, Some(&previous.name)).await {
        Ok(role) => role,
        Err(response) => return *response,
    };
    match persist(&state, &user, Edit::Update(role.clone())).await {
        Ok(Persisted::Done) => {}
        Ok(Persisted::Missing) => return StatusCode::NOT_FOUND.into_response(),
        Ok(Persisted::Exists | Persisted::InUse) => {
            return StatusCode::CONFLICT.into_response();
        }
        Err(response) => return *response,
    }
    state.sessions().invalidate_role(&role.name).await;
    let warning = admin.reload_rbac().await;
    record(
        &state,
        &user,
        Change::done("admin.role_update", &role.name, params(&role)),
    )
    .await;
    let toasts = done_toasts(user.locale(), keys::WEB_ADMIN_ROLE_UPDATED, warning);
    finish(&state, &user, &headers, toasts).await
}

/// `GET /ui/admin/roles/delete?name=`: the typed-name confirmation.
// NOT cancel-safe: a refusal queues an audit entry that may be written after the future is dropped;
// otherwise it only reads.
pub(crate) async fn delete_dialog(
    State(state): State<WebState>,
    Query(query): Query<NameQuery>,
    user: CurrentUser,
) -> Response {
    match editable(&state, &user, query.name(), "admin.role_delete").await {
        Ok(role) => errors::render(&confirmation(&user, &role.name)),
        Err(response) => *response,
    }
}

/// `POST /ui/admin/roles/delete`: removes an unused custom role once its name is typed.
// NOT cancel-safe: the role file is written on a blocking thread that finishes even if the future
// is dropped, leaving the role's sessions alive, the role set not reloaded and the deletion
// unaudited.
pub(crate) async fn delete(
    State(state): State<WebState>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<TypedNameForm>,
) -> Response {
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let _changes = admin.lock().await;
    let role = match editable(&state, &user, form.name(), "admin.role_delete").await {
        Ok(role) => role,
        Err(response) => return *response,
    };
    let mut confirm = confirmation(&user, &role.name);
    if !form.confirmed() {
        confirm.set_error(tr(user.locale(), keys::WEB_ADMIN_ERROR_CONFIRM, None));
        return respond::unprocessable(&confirm);
    }
    match persist(&state, &user, Edit::Delete(role.name.clone())).await {
        Ok(Persisted::Done) => {}
        Ok(Persisted::InUse) => {
            confirm.set_error(tr(user.locale(), keys::WEB_ADMIN_ERROR_ROLE_IN_USE, None));
            return respond::unprocessable(&confirm);
        }
        Ok(Persisted::Missing) => return StatusCode::NOT_FOUND.into_response(),
        Ok(Persisted::Exists) => return StatusCode::CONFLICT.into_response(),
        Err(response) => return *response,
    }
    state.sessions().invalidate_role(&role.name).await;
    let warning = admin.reload_rbac().await;
    record(
        &state,
        &user,
        Change::done("admin.role_delete", &role.name, params(&role)),
    )
    .await;
    let toasts = done_toasts(user.locale(), keys::WEB_ADMIN_ROLE_DELETED, warning);
    finish(&state, &user, &headers, toasts).await
}

/// The custom role `name` when `user` may edit or delete it: it exists, it is not a
/// built-in role or the role `user` holds, and `user` holds everything it grants.
///
/// # Errors
///
/// The 404 or the audited 403 response.
// NOT cancel-safe: a refusal queues an audit entry that may be written after the future is dropped;
// otherwise it only reads.
async fn editable(
    state: &WebState,
    user: &CurrentUser,
    name: &str,
    action: &'static str,
) -> Result<Role, Box<Response>> {
    let Some(role) = state.role(name) else {
        return Err(Box::new(StatusCode::NOT_FOUND.into_response()));
    };
    if is_built_in(name) || user.role().name == name || !user.role().dominates(&role) {
        let refusal = forbidden(state, user, Change::refused(action, name, "forbidden")).await;
        return Err(Box::new(refusal));
    }
    Ok(role)
}

/// The role the form describes, when it is valid and within `user`'s own grants;
/// `existing` is the edited role's name.
///
/// # Errors
///
/// The dialog with its field errors (`422`), or the audited 403 response when the role
/// would grant more than `user` holds.
// NOT cancel-safe: a refusal queues an audit entry that may be written after the future is dropped;
// otherwise it only reads.
async fn validate(
    state: &WebState,
    user: &CurrentUser,
    form: &RoleForm,
    existing: Option<&str>,
) -> Result<Role, Box<Response>> {
    let locale = user.locale();
    let mut page = form_dialog(user, existing, form);
    let name = existing.unwrap_or_else(|| form.name()).to_owned();
    let name_error = match existing {
        None if !valid_name(&name) => Some(keys::WEB_ADMIN_ERROR_ROLE_NAME),
        None if is_built_in(&name) || name == KCC_ACCOUNT_ROLE => {
            Some(keys::WEB_ADMIN_ERROR_ROLE_BUILT_IN)
        }
        None if state.role(&name).is_some() => Some(keys::WEB_ADMIN_ERROR_ROLE_EXISTS),
        Some(_) | None => None,
    };
    if let Some(key) = name_error {
        page.name_error = tr(locale, key, None);
    }
    let permissions = form.permissions();
    let permissions_error = if form.names_unknown() {
        Some(keys::WEB_ADMIN_ERROR_PERMISSION_UNKNOWN)
    } else if permissions.is_empty() {
        Some(keys::WEB_ADMIN_ERROR_PERMISSIONS)
    } else {
        None
    };
    if let Some(key) = permissions_error {
        page.permissions_error = tr(locale, key, None);
    }
    let scope = form.scope();
    if scope.is_empty() || scope.len() > MAX_GLOBS || !scope.iter().all(|glob| valid_glob(glob)) {
        page.scope_error = tr(locale, keys::WEB_ADMIN_ERROR_SCOPE, None);
    }
    if !(page.name_error.is_empty()
        && page.permissions_error.is_empty()
        && page.scope_error.is_empty())
    {
        return Err(Box::new(respond::unprocessable(&page)));
    }
    let role = Role::new(name, permissions.iter().copied(), scope);
    if !user.role().dominates(&role) {
        let action = if existing.is_some() {
            "admin.role_update"
        } else {
            "admin.role_create"
        };
        let change = Change::refused(action, &role.name, "forbidden");
        return Err(Box::new(forbidden(state, user, change).await));
    }
    Ok(role)
}

/// Whether `name` is a custom role name: a lowercase letter, then up to 31 lowercase
/// letters, digits, `-` or `_`.
fn valid_name(name: &str) -> bool {
    name.len() <= MAX_NAME_CHARS
        && name
            .bytes()
            .next()
            .is_some_and(|first| first.is_ascii_lowercase())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_".contains(&byte))
}

/// One change to `roles.json`.
enum Edit {
    /// Adds a role.
    Create(Role),
    /// Replaces the role with the same name.
    Update(Role),
    /// Removes the named role.
    Delete(String),
}

/// What happened to an [`Edit`].
enum Persisted {
    /// Written.
    Done,
    /// A role with the name already exists.
    Exists,
    /// No role has the name.
    Missing,
    /// An account, an API key or the MCP settings still hold the role.
    InUse,
}

/// Writes `edit` under the `roles.json` lock, then reloads the Web UI's roles.
///
/// # Errors
///
/// The 503 response without administration services, or the localized 500 page for a
/// storage or blocking-task failure.
// NOT cancel-safe: the role file update runs on a blocking thread and completes even if the future
// is dropped.
async fn persist(
    state: &WebState,
    user: &CurrentUser,
    edit: Edit,
) -> Result<Persisted, Box<Response>> {
    let Some((store, mcp)) = state
        .admin()
        .map(|admin| (admin.state().clone(), admin.mcp().clone()))
    else {
        return Err(Box::new(unavailable(None)));
    };
    let outcome = spawn_blocking(
        move || -> Result<(Persisted, Vec<Role>), Box<dyn Error + Send + Sync>> {
            let persisted = store
                .update(|document: &mut RolesDocument| apply((&store, &mcp), document, edit))??;
            Ok((persisted, load_roles(&store)?))
        },
    )
    .await;
    match outcome {
        Ok(Ok((persisted, roles))) => {
            state.set_roles(roles);
            Ok(persisted)
        }
        Ok(Err(error)) => Err(Box::new(errors::internal(
            &error,
            fragment_shell(user.locale()),
        ))),
        Err(error) => Err(Box::new(errors::internal(
            &error,
            fragment_shell(user.locale()),
        ))),
    }
}

/// Applies `edit` to the locked `document`; deleting first counts the role's holders
/// (accounts and API keys under their locks, and the MCP settings `mcp` names).
///
/// # Errors
///
/// A state error while reading the accounts, API keys or MCP settings.
fn apply(
    (store, mcp): (&StateStore, &McpBase),
    document: &mut RolesDocument,
    edit: Edit,
) -> Result<Persisted, SettingsError> {
    let position = |name: &str| document.roles.iter().position(|role| role.name == name);
    match edit {
        Edit::Create(role) => {
            if position(&role.name).is_some() {
                return Ok(Persisted::Exists);
            }
            document.roles.push(role);
        }
        Edit::Update(role) => {
            let Some(index) = position(&role.name) else {
                return Ok(Persisted::Missing);
            };
            if let Some(slot) = document.roles.get_mut(index) {
                *slot = role;
            }
        }
        Edit::Delete(name) => {
            if position(&name).is_none() {
                return Ok(Persisted::Missing);
            }
            let held = mcp.held_roles(store)?;
            if !remove_unheld(store, document, &name, &held)? {
                return Ok(Persisted::InUse);
            }
        }
    }
    Ok(Persisted::Done)
}

/// The roles table on `page`, with `toasts`.
///
/// # Errors
///
/// Storage or blocking-task failures.
// cancel-safe: it only reads role holders on a blocking thread.
async fn region(
    state: &WebState,
    user: &CurrentUser,
    page: usize,
    toasts: Vec<Toast>,
    oob: bool,
) -> Result<RolesRegion, Box<dyn Error + Send + Sync>> {
    let (store, mcp) = state
        .admin()
        .map(|admin| (admin.state().clone(), admin.mcp().clone()))
        .ok_or("administration services are not attached")?;
    let counts = spawn_blocking(move || -> Result<_, Box<dyn Error + Send + Sync>> {
        let held = mcp.held_roles(&store)?;
        Ok(holder_counts(&store, &held)?)
    })
    .await??;
    let locale = user.locale();
    let all: Vec<RoleRow> = ordered(&state.roles())
        .iter()
        .map(|role| {
            let holders = counts.get(&role.name).copied().unwrap_or(0);
            let editable = !is_built_in(&role.name)
                && user.role().name != role.name
                && user.role().dominates(role);
            RoleRow {
                label: role_label(locale, &role.name),
                built_in: is_built_in(&role.name),
                permissions: permission_list(locale, &role.permissions),
                scope: role.router_scope.join(", "),
                holders,
                editable,
                deletable: editable && holders == 0,
                edit_url: named("/ui/admin/roles/edit", &role.name),
                delete_url: named("/ui/admin/roles/delete", &role.name),
            }
        })
        .collect();
    let (rows, pager) = Pager::paginate(all, page, Tab::Roles.href().to_owned(), Vec::new());
    Ok(RolesRegion {
        shell: fragment_shell(user.locale()),
        table: table::roles(&rows, user.locale()),
        pager,
        oob,
        toasts,
    })
}

/// Answers a completed change from the dialog with the refreshed table and `toasts`.
// cancel-safe: it only reads the role store to render the region.
async fn finish(
    state: &WebState,
    user: &CurrentUser,
    headers: &HeaderMap,
    toasts: Vec<Toast>,
) -> Response {
    match region(state, user, shown_page(headers), toasts, true).await {
        Ok(region) => respond::region(&region, StatusCode::OK, true),
        Err(error) => errors::internal(&error, fragment_shell(user.locale())),
    }
}

/// The permissions in display order, translated and comma-separated.
pub(crate) fn permission_list(locale: Locale, permissions: &BTreeSet<Permission>) -> String {
    labels::permissions(|permission| permissions.contains(&permission))
        .map(|label| tr(locale, label, None))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The create (`existing` is `None`) or edit dialog with the given values.
fn dialog(
    user: &CurrentUser,
    existing: Option<&str>,
    name: String,
    permissions: &BTreeSet<Permission>,
    scope: String,
) -> RoleDialog {
    let locale = user.locale();
    let title = existing.map_or_else(
        || tr(locale, keys::WEB_ADMIN_ROLE_ADD, None),
        |role| {
            let mut args = FluentArgs::new();
            args.set("name", role.to_owned());
            tr(locale, keys::WEB_ADMIN_ROLE_EDIT_TITLE, Some(&args))
        },
    );
    RoleDialog {
        shell: fragment_shell(user.locale()),
        title,
        action: if existing.is_some() {
            "/ui/admin/roles/edit"
        } else {
            "/ui/admin/roles"
        },
        editing: existing.is_some(),
        role_name: name,
        checks: checkboxes()
            .map(|(permission, field, label)| PermissionCheck {
                field,
                label,
                checked: permissions.contains(&permission),
                grantable: user.role().grants(permission),
            })
            .collect(),
        scope,
        name_error: String::new(),
        permissions_error: String::new(),
        scope_error: String::new(),
    }
}

/// The dialog re-rendered from a submitted form.
fn form_dialog(user: &CurrentUser, existing: Option<&str>, form: &RoleForm) -> RoleDialog {
    dialog(
        user,
        existing,
        existing.unwrap_or_else(|| form.name()).to_owned(),
        form.permissions(),
        form.scope_text().to_owned(),
    )
}

/// The typed-name delete confirmation for `name`.
fn confirmation(user: &CurrentUser, name: &str) -> Dialog {
    Dialog::typed_name(
        user.locale(),
        "/ui/admin/roles/delete".to_owned(),
        name,
        (
            keys::WEB_ADMIN_ROLE_DELETE_TITLE,
            keys::WEB_ADMIN_ROLE_DELETE_TEXT,
        ),
    )
}

/// The audited parameters of a role.
fn params(role: &Role) -> Value {
    json!({ "permissions": role.permissions, "router_scope": role.router_scope })
}
