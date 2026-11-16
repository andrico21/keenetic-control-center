//! Account administration at `/ui/admin/users` (`ManageUsers`).
//!
//! Administrators create accounts with an initial password the user must replace at the
//! first sign-in, change roles, disable and enable sign-in, clear lockouts and delete
//! accounts. Every change re-checks the guards: nobody acts on their own account, on an
//! account whose role is above their own, or grants a role above their own; the last
//! enabled administrator stays (enforced by `AccountStore` under the file lock). A changed
//! account's sessions end at once.

extern crate alloc;

mod table;

use alloc::sync::Arc;
use core::{error::Error, fmt};

use askama::Template;
use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_app::{
    accounts::{AccountChange, AccountError, AccountSummary, NewAccount},
    permissions::{Permission, Role, assignment::GrantError},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::json;
use tokio::task::spawn_blocking;

use crate::{
    WebState,
    admin_shared::{
        Change, ListQuery, NameForm, NameQuery, Tab, TabLink, forbidden, named, record, role_label,
        roles_for, tabs, unavailable,
    },
    authz::{CurrentSession, CurrentUser},
    errors,
    nav::Section,
    page::{LocaleOption, Localize as _, Shell, Theme},
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

/// The add-account form.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NewUserForm {
    /// Login name.
    username: String,
    /// Initial password, moved into a `SecretString` at once and never rendered.
    password: String,
    /// Granted role.
    role: String,
    /// Preferred language tag.
    locale: String,
}

/// The change-role form.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RoleForm {
    /// Account to change.
    name: String,
    /// Role to grant.
    role: String,
}

/// How the signed-in user relates to an account row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relation {
    /// The signed-in user's own account: no actions.
    Own,
    /// An account the signed-in user may change.
    Managed,
    /// An account whose role is above the signed-in user's: no actions.
    Other,
}

/// A state flag shown after an account's status.
struct Flag {
    /// `warning` or `info`.
    tone: &'static str,
    /// Label.
    label: MessageKey,
}

/// One account row.
struct UserRow {
    /// Login name.
    username: String,
    /// Role label.
    role: String,
    /// Whether sign-in is disabled.
    disabled: bool,
    /// Lockout and pending-password flags.
    flags: Vec<Flag>,
    /// Whether failed sign-ins were counted, so Unlock has something to clear.
    unlock: bool,
    /// How the signed-in user relates to the account.
    relation: Relation,
    /// The change-role dialog.
    role_url: String,
    /// The delete dialog.
    delete_url: String,
}

impl UserRow {
    /// Whether this is the signed-in user's account.
    fn is_self(&self) -> bool {
        self.relation == Relation::Own
    }

    /// Whether the signed-in user may change this account.
    fn manageable(&self) -> bool {
        self.relation == Relation::Managed
    }
}

/// The accounts table, rendered in the page and sent out of band after each change.
#[derive(Template)]
#[template(path = "partials/admin_users_region.html")]
struct UsersRegion {
    /// Locale carrier.
    shell: Shell,
    /// The shown page of accounts.
    table: TableView,
    /// Table pagination.
    pager: Pager,
    /// Whether this is an out-of-band update.
    oob: bool,
    /// Outcome toasts of the change.
    toasts: Vec<Toast>,
}

localized!(UsersRegion);

/// The users page.
#[derive(Template)]
#[template(path = "pages/admin_users.html")]
struct UsersPage {
    /// Page shell.
    shell: Shell,
    /// Administration tabs.
    tabs: Vec<TabLink>,
    /// The accounts table.
    region: UsersRegion,
}

localized!(UsersPage);

/// One choice of a role select.
struct RoleOption {
    /// Role name, the option value.
    name: String,
    /// Display label.
    label: String,
    /// Whether it is selected.
    selected: bool,
}

/// The add-account dialog.
#[derive(Template)]
#[template(path = "partials/admin_user_new.html")]
struct NewUserDialog {
    /// Locale carrier.
    shell: Shell,
    /// Re-rendered login name.
    username: String,
    /// Roles the signed-in user may grant.
    roles: Vec<RoleOption>,
    /// Language choices, the selected one marked current.
    languages: [LocaleOption; 6],
    /// Login name error.
    username_error: String,
    /// Password error.
    password_error: String,
    /// Role error.
    role_error: String,
}

localized!(NewUserDialog);

/// The change-role dialog.
#[derive(Template)]
#[template(path = "partials/admin_user_role.html")]
struct RoleDialog {
    /// Locale carrier.
    shell: Shell,
    /// Dialog title naming the account.
    title: String,
    /// Account to change.
    username: String,
    /// Roles the signed-in user may grant.
    roles: Vec<RoleOption>,
    /// Refusal or validation message.
    error: String,
}

localized!(RoleDialog);

/// `GET /ui/admin/users`.
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
        Ok(region) => errors::render(&UsersPage {
            tabs: tabs(user.role(), Tab::Users),
            shell,
            region,
        }),
        Err(error) => errors::internal(&error, shell),
    }
}

/// `GET /ui/admin/users/new`: the add-account dialog.
pub(crate) async fn new_dialog(State(state): State<WebState>, user: CurrentUser) -> Response {
    let dialog = NewUserDialog {
        shell: fragment_shell(user.locale()),
        username: String::new(),
        roles: options(&state, &user, "viewer"),
        languages: languages(state.default_locale()),
        username_error: String::new(),
        password_error: String::new(),
        role_error: String::new(),
    };
    errors::render(&dialog)
}

/// `POST /ui/admin/users`: creates an account that must change its password at the
/// first sign-in.
pub(crate) async fn create(
    State(state): State<WebState>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<NewUserForm>,
) -> Response {
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let _changes = admin.lock().await;
    let locale = user.locale();
    let language = Locale::from_tag(&form.locale).unwrap_or_else(|| state.default_locale());
    let mut dialog = NewUserDialog {
        shell: fragment_shell(user.locale()),
        username: form.username.clone(),
        roles: options(&state, &user, &form.role),
        languages: languages(language),
        username_error: String::new(),
        password_error: String::new(),
        role_error: String::new(),
    };
    let username = form.username.clone();
    let role = form.role.clone();
    let account = NewAccount::new(form.username, SecretString::from(form.password), form.role)
        .with_locale(language.tag().to_owned())
        .with_must_change_password(true);
    let accounts = Arc::clone(state.accounts());
    let actor = user.role().clone();
    match spawn_blocking(move || accounts.create(&actor, account)).await {
        Ok(Ok(())) => {}
        Ok(Err(AccountError::Grant(GrantError::UnknownRole { name: _ }))) => {
            dialog.role_error = tr(locale, keys::WEB_ADMIN_ERROR_ROLE, None);
            return respond::unprocessable(&dialog);
        }
        Ok(Err(AccountError::Grant(GrantError::Forbidden))) => {
            let change = Change::refused("admin.user_create", &username, "forbidden");
            return forbidden(&state, &user, change).await;
        }
        Ok(Err(AccountError::InvalidUsername)) => {
            dialog.username_error = tr(locale, keys::WEB_ADMIN_ERROR_USERNAME, None);
            return respond::unprocessable(&dialog);
        }
        Ok(Err(AccountError::DuplicateAccount)) => {
            dialog.username_error = tr(locale, keys::WEB_ADMIN_ERROR_USER_EXISTS, None);
            return respond::unprocessable(&dialog);
        }
        Ok(Err(AccountError::InvalidPasswordLength)) => {
            dialog.password_error = tr(locale, keys::WEB_ADMIN_ERROR_PASSWORD_LENGTH, None);
            return respond::unprocessable(&dialog);
        }
        Ok(Err(AccountError::PasswordEqualsUsername)) => {
            dialog.password_error = tr(locale, keys::WEB_ADMIN_ERROR_PASSWORD_USERNAME, None);
            return respond::unprocessable(&dialog);
        }
        Ok(Err(error)) => return errors::internal(&error, fragment_shell(user.locale())),
        Err(error) => return errors::internal(&error, fragment_shell(user.locale())),
    }
    let params = json!({
        "role": role,
        "locale": language.tag(),
        "first_login_change": true,
    });
    record(
        &state,
        &user,
        Change::done("admin.user_create", &username, params),
    )
    .await;
    let toasts = vec![Toast::success(locale, keys::WEB_ADMIN_USER_CREATED)];
    finish(&state, &user, &headers, toasts, true).await
}

/// `GET /ui/admin/users/role?name=`: the change-role dialog.
pub(crate) async fn role_dialog(
    State(state): State<WebState>,
    Query(query): Query<NameQuery>,
    user: CurrentUser,
) -> Response {
    let target = match managed(&state, &user, query.name()).await {
        Ok(target) => target,
        Err(response) => return *response,
    };
    errors::render(&role_dialog_for(
        &state,
        &user,
        &target.username,
        &target.role,
    ))
}

/// `POST /ui/admin/users/role`: grants another role and ends the account's sessions.
pub(crate) async fn set_role(
    State(state): State<WebState>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<RoleForm>,
) -> Response {
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let _changes = admin.lock().await;
    let target = match managed(&state, &user, &form.name).await {
        Ok(target) => target,
        Err(response) => return *response,
    };
    let mut dialog = role_dialog_for(&state, &user, &target.username, &form.role);
    let Some(role) = state.role(&form.role) else {
        dialog.error = tr(user.locale(), keys::WEB_ADMIN_ERROR_ROLE, None);
        return respond::unprocessable(&dialog);
    };
    if !user.role().dominates(&role) {
        let change = Change::refused("admin.user_role", &target.username, "forbidden");
        return forbidden(&state, &user, change).await;
    }
    match administer(
        &state,
        &target.username,
        AccountChange::Role(role.name.clone()),
    )
    .await
    {
        Ok(()) => {}
        Err(Failure::LastAdmin) => {
            let change = Change::refused("admin.user_role", &target.username, "last_admin");
            record(&state, &user, change).await;
            dialog.error = tr(user.locale(), keys::WEB_ADMIN_ERROR_LAST_ADMIN, None);
            return respond::unprocessable(&dialog);
        }
        Err(Failure::Other(response)) => return *response,
    }
    state.sessions().invalidate_user(&target.username).await;
    let params = json!({ "from": target.role, "to": role.name });
    record(
        &state,
        &user,
        Change::done("admin.user_role", &target.username, params),
    )
    .await;
    let toasts = vec![Toast::success(
        user.locale(),
        keys::WEB_ADMIN_USER_ROLE_CHANGED,
    )];
    finish(&state, &user, &headers, toasts, true).await
}

/// `POST /ui/admin/users/disable`: blocks sign-in and ends the account's sessions.
pub(crate) async fn disable(
    State(state): State<WebState>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<NameForm>,
) -> Response {
    let action = Action {
        id: "admin.user_disable",
        change: AccountChange::Disabled(true),
        done: keys::WEB_ADMIN_USER_DISABLED,
        signs_out: true,
    };
    toggle(&state, &headers, &user, form.name(), action).await
}

/// `POST /ui/admin/users/enable`: allows sign-in again.
pub(crate) async fn enable(
    State(state): State<WebState>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<NameForm>,
) -> Response {
    let action = Action {
        id: "admin.user_enable",
        change: AccountChange::Disabled(false),
        done: keys::WEB_ADMIN_USER_ENABLED,
        signs_out: false,
    };
    toggle(&state, &headers, &user, form.name(), action).await
}

/// `POST /ui/admin/users/unlock`: clears failed sign-ins and any lockout.
pub(crate) async fn unlock(
    State(state): State<WebState>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<NameForm>,
) -> Response {
    let action = Action {
        id: "admin.user_unlock",
        change: AccountChange::Unlock,
        done: keys::WEB_ADMIN_USER_UNLOCKED,
        signs_out: false,
    };
    toggle(&state, &headers, &user, form.name(), action).await
}

/// `GET /ui/admin/users/delete?name=`: the typed-name confirmation.
pub(crate) async fn delete_dialog(
    State(state): State<WebState>,
    Query(query): Query<NameQuery>,
    user: CurrentUser,
) -> Response {
    match managed(&state, &user, query.name()).await {
        Ok(target) => errors::render(&delete_confirmation(&user, &target.username)),
        Err(response) => *response,
    }
}

/// `POST /ui/admin/users/delete`: removes the account once its name is typed.
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
    let target = match managed(&state, &user, form.name()).await {
        Ok(target) => target,
        Err(response) => return *response,
    };
    let mut dialog = delete_confirmation(&user, &target.username);
    if !form.confirmed() {
        dialog.set_error(tr(user.locale(), keys::WEB_ADMIN_ERROR_CONFIRM, None));
        return respond::unprocessable(&dialog);
    }
    match administer(&state, &target.username, AccountChange::Delete).await {
        Ok(()) => {}
        Err(Failure::LastAdmin) => {
            let change = Change::refused("admin.user_delete", &target.username, "last_admin");
            record(&state, &user, change).await;
            dialog.set_error(tr(user.locale(), keys::WEB_ADMIN_ERROR_LAST_ADMIN, None));
            return respond::unprocessable(&dialog);
        }
        Err(Failure::Other(response)) => return *response,
    }
    state.sessions().invalidate_user(&target.username).await;
    let params = json!({ "role": target.role });
    record(
        &state,
        &user,
        Change::done("admin.user_delete", &target.username, params),
    )
    .await;
    let toasts = vec![Toast::success(user.locale(), keys::WEB_ADMIN_USER_DELETED)];
    finish(&state, &user, &headers, toasts, true).await
}

/// One table-row action.
struct Action {
    /// Audit action id.
    id: &'static str,
    /// The account change.
    change: AccountChange,
    /// Success message.
    done: MessageKey,
    /// Whether the account's sessions end.
    signs_out: bool,
}

/// Applies a table-row action and answers with the table and a toast.
async fn toggle(
    state: &WebState,
    headers: &HeaderMap,
    user: &CurrentUser,
    name: &str,
    action: Action,
) -> Response {
    let Some(admin) = state.admin() else {
        return unavailable(None);
    };
    let _changes = admin.lock().await;
    let target = match managed(state, user, name).await {
        Ok(target) => target,
        Err(response) => return *response,
    };
    match administer(state, &target.username, action.change).await {
        Ok(()) => {}
        Err(Failure::LastAdmin) => {
            record(
                state,
                user,
                Change::refused(action.id, &target.username, "last_admin"),
            )
            .await;
            let toasts = vec![Toast::error(
                user.locale(),
                keys::WEB_ADMIN_ERROR_LAST_ADMIN,
            )];
            return finish_with(
                state,
                user,
                headers,
                toasts,
                StatusCode::UNPROCESSABLE_ENTITY,
            )
            .await;
        }
        Err(Failure::Other(response)) => return *response,
    }
    if action.signs_out {
        state.sessions().invalidate_user(&target.username).await;
    }
    record(
        state,
        user,
        Change::done(action.id, &target.username, json!({})),
    )
    .await;
    let toasts = vec![Toast::success(user.locale(), action.done)];
    finish(state, user, headers, toasts, false).await
}

/// Why an account change did not happen.
enum Failure {
    /// It would leave no enabled administrator.
    LastAdmin,
    /// The account vanished or storage failed; the response says which.
    Other(Box<Response>),
}

/// Applies `change` to `username` off the async executor.
///
/// # Errors
///
/// [`Failure::LastAdmin`], or the response for a vanished account or a storage failure.
async fn administer(
    state: &WebState,
    username: &str,
    change: AccountChange,
) -> Result<(), Failure> {
    let accounts = Arc::clone(state.accounts());
    let name = username.to_owned();
    match spawn_blocking(move || accounts.administer(&name, &change)).await {
        Ok(Ok(Some(_before))) => Ok(()),
        Ok(Ok(None)) => Err(Failure::Other(Box::new(
            StatusCode::NOT_FOUND.into_response(),
        ))),
        Ok(Err(AccountError::LastAdmin)) => Err(Failure::LastAdmin),
        Ok(Err(error)) => Err(Failure::Other(Box::new(internal(&error)))),
        Err(error) => Err(Failure::Other(Box::new(internal(&error)))),
    }
}

/// The account `name` when `user` may manage it: it exists, it is not `user`, and
/// `user` holds everything its role grants.
///
/// # Errors
///
/// The 404, 403 (audited) or 500 response to answer with.
async fn managed(
    state: &WebState,
    user: &CurrentUser,
    name: &str,
) -> Result<AccountSummary, Box<Response>> {
    let accounts = Arc::clone(state.accounts());
    let summaries = match spawn_blocking(move || accounts.list()).await {
        Ok(Ok(summaries)) => summaries,
        Ok(Err(error)) => return Err(Box::new(internal(&error))),
        Err(error) => return Err(Box::new(internal(&error))),
    };
    let Some(target) = summaries
        .into_iter()
        .find(|summary| summary.username == name)
    else {
        return Err(Box::new(StatusCode::NOT_FOUND.into_response()));
    };
    if target.username == user.username() || !manages(state, user.role(), &target.role) {
        let change = Change::refused("admin.user_manage", name, "forbidden");
        return Err(Box::new(forbidden(state, user, change).await));
    }
    Ok(target)
}

/// Whether `actor` may manage an account holding the role `role`; an unknown role is
/// treated as holding everything.
fn manages(state: &WebState, actor: &Role, role: &str) -> bool {
    let target = state
        .role(role)
        .unwrap_or_else(|| Role::new(String::new(), Permission::ALL, vec!["*".to_owned()]));
    actor.dominates(&target)
}

/// The accounts table on `page`, with `toasts`.
///
/// # Errors
///
/// Account storage or blocking-task failures.
async fn region(
    state: &WebState,
    user: &CurrentUser,
    page: usize,
    toasts: Vec<Toast>,
    oob: bool,
) -> Result<UsersRegion, Box<dyn Error + Send + Sync>> {
    let accounts = Arc::clone(state.accounts());
    let mut summaries = spawn_blocking(move || accounts.list()).await??;
    summaries.sort_by(|left, right| left.username.cmp(&right.username));
    let now = state.unix_seconds();
    let locale = user.locale();
    let all = summaries
        .into_iter()
        .map(|summary| {
            let relation = if summary.username == user.username() {
                Relation::Own
            } else if manages(state, user.role(), &summary.role) {
                Relation::Managed
            } else {
                Relation::Other
            };
            let mut flags = Vec::new();
            if summary.lockout_until.is_some_and(|until| now < until) {
                flags.push(Flag {
                    tone: "warning",
                    label: keys::WEB_ADMIN_USER_LOCKED,
                });
            }
            if summary.must_change_password {
                flags.push(Flag {
                    tone: "info",
                    label: keys::WEB_ADMIN_USER_MUST_CHANGE,
                });
            }
            UserRow {
                role: role_label(locale, &summary.role),
                disabled: summary.disabled,
                flags,
                unlock: summary.failure_count > 0 || summary.lockout_until.is_some(),
                relation,
                role_url: named("/ui/admin/users/role", &summary.username),
                delete_url: named("/ui/admin/users/delete", &summary.username),
                username: summary.username,
            }
        })
        .collect();
    let (rows, pager) = Pager::paginate(all, page, Tab::Users.href().to_owned(), Vec::new());
    Ok(UsersRegion {
        shell: fragment_shell(user.locale()),
        table: table::accounts(&rows, user.locale()),
        pager,
        oob,
        toasts,
    })
}

/// Answers a completed change with the refreshed table and `toasts`.
async fn finish(
    state: &WebState,
    user: &CurrentUser,
    headers: &HeaderMap,
    toasts: Vec<Toast>,
    from_dialog: bool,
) -> Response {
    match region(state, user, shown_page(headers), toasts, true).await {
        Ok(region) => respond::region(&region, StatusCode::OK, from_dialog),
        Err(error) => internal(&error),
    }
}

/// Answers a refused table-row change with the table, `toasts` and `status`.
async fn finish_with(
    state: &WebState,
    user: &CurrentUser,
    headers: &HeaderMap,
    toasts: Vec<Toast>,
    status: StatusCode,
) -> Response {
    match region(state, user, shown_page(headers), toasts, true).await {
        Ok(region) => respond::region(&region, status, false),
        Err(error) => internal(&error),
    }
}

/// The change-role dialog for `username`, with `selected` chosen.
fn role_dialog_for(
    state: &WebState,
    user: &CurrentUser,
    username: &str,
    selected: &str,
) -> RoleDialog {
    let mut args = FluentArgs::new();
    args.set("name", username.to_owned());
    RoleDialog {
        title: tr(user.locale(), keys::WEB_ADMIN_USER_ROLE_TITLE, Some(&args)),
        shell: fragment_shell(user.locale()),
        username: username.to_owned(),
        roles: options(state, user, selected),
        error: String::new(),
    }
}

/// The typed-name delete confirmation for `username`.
fn delete_confirmation(user: &CurrentUser, username: &str) -> Dialog {
    Dialog::typed_name(
        user.locale(),
        "/ui/admin/users/delete".to_owned(),
        username,
        (
            keys::WEB_ADMIN_USER_DELETE_TITLE,
            keys::WEB_ADMIN_USER_DELETE_TEXT,
        ),
    )
}

/// The roles `user` may grant, `selected` chosen.
fn options(state: &WebState, user: &CurrentUser, selected: &str) -> Vec<RoleOption> {
    roles_for(&state.roles(), user.role())
        .into_iter()
        .map(|role| RoleOption {
            label: role_label(user.locale(), &role.name),
            selected: role.name == selected,
            name: role.name,
        })
        .collect()
}

/// The language choices with `locale` selected.
fn languages(locale: Locale) -> [LocaleOption; 6] {
    Shell::new(locale, Theme::System).locales()
}

/// Logs `error` and answers `500`.
fn internal<E>(error: &E) -> Response
where
    E: fmt::Display + ?Sized,
{
    tracing::error!(%error, "account administration failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}
