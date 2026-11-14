//! MCP API keys at `/ui/admin/api-keys` (`ManageUsers`).
//!
//! A new key's plaintext is shown once, in a read-only field of the response to the
//! create form, and never again: kcc stores only its Argon2id hash, and the plaintext is
//! never put in a URL, a log or the audit log. Creating and revoking a key installs the
//! stored keys in the running MCP transport at once. Nobody creates a key with a role
//! above their own or revokes a key whose role is above their own.

mod table;

use core::{error::Error, fmt};

use askama::Template;
use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use kcc_app::{
    api_keys::{ApiKeyError, ApiKeysDocument, CreatedApiKey, create_api_key, expose_created_key},
    permissions::{Permission, Role},
    persist::StateStore,
};
use kcc_i18n::{bundle::tr, keys};
use serde::Deserialize;
use serde_json::json;
use tokio::task::spawn_blocking;

use crate::{
    WebState,
    admin_shared::{
        Change, ListQuery, NameQuery, Tab, TabLink, Timestamp, dominates, done_toasts, forbidden,
        named, record, role_label, roles_for, tabs, unavailable,
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

/// Longest API key name.
const MAX_NAME_CHARS: usize = 64;

/// The create form.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NewKeyForm {
    /// Key name, the MCP principal.
    name: String,
    /// Granted role.
    role: String,
}

/// One key row.
struct KeyRow {
    /// Key name.
    name: String,
    /// Role label.
    role: String,
    /// Creation time.
    created: Option<Timestamp>,
    /// Last successful use, if recorded.
    last_used: Option<Timestamp>,
    /// Whether the signed-in user may revoke it.
    revocable: bool,
    /// The revoke dialog.
    revoke_url: String,
}

/// The keys table.
#[derive(Template)]
#[template(path = "partials/admin_keys_region.html")]
struct KeysRegion {
    /// Locale carrier.
    shell: Shell,
    /// The shown page of keys.
    table: TableView,
    /// Table pagination.
    pager: Pager,
    /// Whether this is an out-of-band update.
    oob: bool,
    /// Outcome toasts of the change.
    toasts: Vec<Toast>,
}

localized!(KeysRegion);

/// The API keys page.
#[derive(Template)]
#[template(path = "pages/admin_keys.html")]
struct KeysPage {
    /// Page shell.
    shell: Shell,
    /// Administration tabs.
    tabs: Vec<TabLink>,
    /// The keys table.
    region: KeysRegion,
}

localized!(KeysPage);

/// One choice of the role select.
struct RoleOption {
    /// Role name.
    name: String,
    /// Display label.
    label: String,
    /// Whether it is selected.
    selected: bool,
}

/// The create dialog.
#[derive(Template)]
#[template(path = "partials/admin_key_new.html")]
struct NewKeyDialog {
    /// Locale carrier.
    shell: Shell,
    /// Re-rendered key name.
    key_name: String,
    /// Roles the signed-in user may grant.
    roles: Vec<RoleOption>,
    /// Name error.
    name_error: String,
    /// Role error.
    role_error: String,
}

localized!(NewKeyDialog);

/// The one-time display of a new key, with the refreshed table out of band.
#[derive(Template)]
#[template(path = "partials/admin_key_created.html")]
struct CreatedDialog {
    /// Locale carrier.
    shell: Shell,
    /// The new key and its stored record.
    created: CreatedApiKey,
    /// The refreshed table and toasts, sent out of band.
    region: KeysRegion,
}

impl CreatedDialog {
    /// The plaintext key, written once into the response.
    fn plaintext(&self) -> &str {
        expose_created_key(&self.created)
    }
}

localized!(CreatedDialog);

/// `GET /ui/admin/api-keys`.
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
        Ok(region) => errors::render(&KeysPage {
            tabs: tabs(user.role(), Tab::Keys),
            shell,
            region,
        }),
        Err(error) => errors::internal(&error, shell),
    }
}

/// `GET /ui/admin/api-keys/new`: the create dialog.
pub(crate) async fn new_dialog(State(state): State<WebState>, user: CurrentUser) -> Response {
    errors::render(&new_key_dialog(&state, &user, String::new(), "viewer"))
}

/// `POST /ui/admin/api-keys`: creates a key and shows its plaintext once.
pub(crate) async fn create(
    State(state): State<WebState>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<NewKeyForm>,
) -> Response {
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let _changes = admin.lock().await;
    let locale = user.locale();
    let mut dialog = new_key_dialog(&state, &user, form.name.clone(), &form.role);
    if !valid_name(&form.name) {
        dialog.name_error = tr(locale, keys::WEB_ADMIN_ERROR_KEY_NAME, None);
        return respond::unprocessable(&dialog);
    }
    let Some(role) = state.role(&form.role) else {
        dialog.role_error = tr(locale, keys::WEB_ADMIN_ERROR_ROLE, None);
        return respond::unprocessable(&dialog);
    };
    if !dominates(user.role(), &role) {
        let change = Change::refused("admin.api_key_create", &form.name, "forbidden");
        return forbidden(&state, &user, change).await;
    }
    let store = admin.state().clone();
    let now = state.unix_seconds();
    let name = form.name.clone();
    let role_name = role.name.clone();
    let created = match spawn_blocking(move || create_api_key(&store, name, role_name, now)).await {
        Ok(Ok(created)) => created,
        Ok(Err(ApiKeyError::DuplicateName)) => {
            dialog.name_error = tr(locale, keys::WEB_ADMIN_ERROR_KEY_EXISTS, None);
            return respond::unprocessable(&dialog);
        }
        Ok(Err(error)) => return internal(&error),
        Err(error) => return internal(&error),
    };
    let warning = admin.reload_keys().await;
    let params = json!({ "role": role.name });
    record(
        &state,
        &user,
        Change::done("admin.api_key_create", &form.name, params),
    )
    .await;
    let toasts = warning
        .map(|key| Toast::warning(locale, key))
        .into_iter()
        .collect();
    let refreshed = match region(&state, &user, shown_page(&headers), toasts, true).await {
        Ok(refreshed) => refreshed,
        Err(error) => return internal(&error),
    };
    let mut response = errors::render(&CreatedDialog {
        shell: fragment_shell(user.locale()),
        created,
        region: refreshed,
    });
    drop(response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    ));
    response
}

/// `GET /ui/admin/api-keys/revoke?name=`: the typed-name confirmation.
pub(crate) async fn revoke_dialog(
    State(state): State<WebState>,
    Query(query): Query<NameQuery>,
    user: CurrentUser,
) -> Response {
    match revocable(&state, &user, query.name()).await {
        Ok(()) => errors::render(&confirmation(&user, query.name())),
        Err(response) => *response,
    }
}

/// `POST /ui/admin/api-keys/revoke`: deletes a key once its name is typed; MCP requests
/// with it fail from then on.
pub(crate) async fn revoke(
    State(state): State<WebState>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<TypedNameForm>,
) -> Response {
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let _changes = admin.lock().await;
    if let Err(response) = revocable(&state, &user, form.name()).await {
        return *response;
    }
    if !form.confirmed() {
        let mut dialog = confirmation(&user, form.name());
        dialog.set_error(tr(user.locale(), keys::WEB_ADMIN_ERROR_CONFIRM, None));
        return respond::unprocessable(&dialog);
    }
    let store = admin.state().clone();
    let name = form.name().to_owned();
    let removed = spawn_blocking(move || {
        store.update(|document: &mut ApiKeysDocument| {
            let before = document.keys.len();
            document.keys.retain(|key| key.name != name);
            document.keys.len() != before
        })
    })
    .await;
    match removed {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => return StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => return internal(&error),
        Err(error) => return internal(&error),
    }
    let warning = admin.reload_keys().await;
    record(
        &state,
        &user,
        Change::done("admin.api_key_revoke", form.name(), json!({})),
    )
    .await;
    let toasts = done_toasts(user.locale(), keys::WEB_ADMIN_KEY_REVOKED, warning);
    match region(&state, &user, shown_page(&headers), toasts, true).await {
        Ok(refreshed) => respond::region(&refreshed, StatusCode::OK, true),
        Err(error) => internal(&error),
    }
}

/// Whether `user` may revoke the key `name`: it exists and `user` holds everything its
/// role grants (an unknown role counts as everything).
///
/// # Errors
///
/// The 404, the audited 403 or the 500 response.
async fn revocable(state: &WebState, user: &CurrentUser, name: &str) -> Result<(), Box<Response>> {
    let keys = match stored(state).await {
        Ok(keys) => keys,
        Err(error) => return Err(Box::new(internal(&error))),
    };
    let Some(key) = keys.keys.into_iter().find(|key| key.name == name) else {
        return Err(Box::new(StatusCode::NOT_FOUND.into_response()));
    };
    if !manages(state, user.role(), &key.role) {
        let change = Change::refused("admin.api_key_revoke", name, "forbidden");
        return Err(Box::new(forbidden(state, user, change).await));
    }
    Ok(())
}

/// Whether `actor` may manage a key holding `role`; an unknown role counts as holding
/// every permission on every router.
fn manages(state: &WebState, actor: &Role, role: &str) -> bool {
    let target = state
        .role(role)
        .unwrap_or_else(|| Role::new(String::new(), Permission::ALL, vec!["*".to_owned()]));
    dominates(actor, &target)
}

/// The stored keys, read off the async executor.
///
/// # Errors
///
/// Missing administration services, state or blocking-task failures.
async fn stored(state: &WebState) -> Result<ApiKeysDocument, Box<dyn Error + Send + Sync>> {
    let store: StateStore = state
        .admin()
        .map(|admin| admin.state().clone())
        .ok_or("administration services are not attached")?;
    Ok(spawn_blocking(move || store.read::<ApiKeysDocument>())
        .await??
        .unwrap_or_default())
}

/// The keys table on `page`, with `toasts`.
///
/// # Errors
///
/// State or blocking-task failures.
async fn region(
    state: &WebState,
    user: &CurrentUser,
    page: usize,
    toasts: Vec<Toast>,
    oob: bool,
) -> Result<KeysRegion, Box<dyn Error + Send + Sync>> {
    let mut stored_keys = stored(state).await?.keys;
    stored_keys.sort_by(|left, right| left.name.cmp(&right.name));
    let locale = user.locale();
    let all = stored_keys
        .into_iter()
        .map(|key| KeyRow {
            role: role_label(locale, &key.role),
            created: Timestamp::at(key.created_at),
            last_used: key.last_used_at.and_then(Timestamp::at),
            revocable: manages(state, user.role(), &key.role),
            revoke_url: named("/ui/admin/api-keys/revoke", &key.name),
            name: key.name,
        })
        .collect();
    let (rows, pager) = Pager::paginate(all, page, Tab::Keys.href().to_owned(), Vec::new());
    Ok(KeysRegion {
        shell: fragment_shell(user.locale()),
        table: table::keys(&rows, locale),
        pager,
        oob,
        toasts,
    })
}

/// Whether `name` is a key name: 1 to 64 lowercase letters, digits, `.`, `-` or `_`.
fn valid_name(name: &str) -> bool {
    (1..=MAX_NAME_CHARS).contains(&name.len())
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

/// The create dialog with `name` and `selected` filled in.
fn new_key_dialog(
    state: &WebState,
    user: &CurrentUser,
    key_name: String,
    selected: &str,
) -> NewKeyDialog {
    NewKeyDialog {
        shell: fragment_shell(user.locale()),
        key_name,
        roles: roles_for(&state.roles(), user.role())
            .into_iter()
            .map(|role| RoleOption {
                label: role_label(user.locale(), &role.name),
                selected: role.name == selected,
                name: role.name,
            })
            .collect(),
        name_error: String::new(),
        role_error: String::new(),
    }
}

/// The typed-name revoke confirmation for `name`.
fn confirmation(user: &CurrentUser, name: &str) -> Dialog {
    Dialog::typed_name(
        user.locale(),
        "/ui/admin/api-keys/revoke".to_owned(),
        name,
        (
            keys::WEB_ADMIN_KEY_REVOKE_TITLE,
            keys::WEB_ADMIN_KEY_REVOKE_TEXT,
        ),
    )
    .with_button(keys::WEB_ADMIN_KEY_REVOKE)
}

/// Logs `error` and answers `500`.
fn internal<E>(error: &E) -> Response
where
    E: fmt::Display + ?Sized,
{
    tracing::error!(%error, "API key administration failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}
