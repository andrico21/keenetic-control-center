//! Building the add and edit dialog: the routers the role sees, the lists read from the
//! chosen router, and the dialog shown again with its messages.

use axum::response::Response;
use fluent_bundle::FluentArgs;
use kcc_app::permissions::Role;
use kcc_i18n::{bundle::tr, keys};

use super::{
    choices::Choices,
    form::{Editor, Errors, Typed},
    page::Failure,
};
use crate::{
    WebState,
    authz::CurrentUser,
    overview::masthead,
    page_kit::{context::fragment_shell, respond},
};

/// The dialog with `typed` and `errors`, as 422.
// NOT cancel-safe: as `new_dialog`.
pub(super) async fn shown(
    state: &WebState,
    user: &CurrentUser,
    shown_with: (Vec<String>, Typed),
    errors: Errors,
) -> Response {
    respond::unprocessable(&editor(state, user, shown_with, errors).await)
}

/// The dialog for `user` with `typed` among `routers`, showing `errors`.
// NOT cancel-safe: as `new_dialog`.
pub(super) async fn editor(
    state: &WebState,
    user: &CurrentUser,
    (routers, typed): (Vec<String>, Typed),
    errors: Errors,
) -> Editor {
    let locale = user.locale();
    let title = if typed.id().is_empty() {
        tr(locale, keys::WEB_ADMIN_SCHEDULED_NEW_TITLE, None)
    } else {
        let mut args = FluentArgs::new();
        args.set("name", typed.name().to_owned());
        tr(locale, keys::WEB_ADMIN_SCHEDULED_EDIT_TITLE, Some(&args))
    };
    let choices = if routers.iter().any(|router| router == typed.router()) {
        Choices::read(state, user, typed.router(), typed.kind()).await
    } else {
        Choices::default()
    };
    let shell = fragment_shell(locale).with_fleet(masthead(state, user.role(), None).await, None);
    let mut editor = Editor::new(shell, title, (routers, typed), choices);
    editor.refuse_all(errors);
    editor
}

/// The ids of the routers `role` sees; none without the fleet.
///
/// # Errors
///
/// Registry read failures.
// cancel-safe: it only reads the registry on a blocking thread.
pub(super) async fn router_ids(state: &WebState, role: &Role) -> Result<Vec<String>, Failure> {
    let Some(fleet) = state.fleet() else {
        return Ok(Vec::new());
    };
    Ok(fleet
        .visible(role)
        .await?
        .into_iter()
        .map(|entry| entry.profile.id)
        .collect())
}
