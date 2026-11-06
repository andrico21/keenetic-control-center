//! Delete on the internet page: the connection leaves the running configuration once its
//! name was typed.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_domain::wan;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_rci::ObjectName;

use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    net_change::{Params, Planned, finish, missing},
    net_pages::{Call, Tab},
    page_kit::{
        action::Operation,
        context::fragment_shell,
        respond::{self, Answer},
        typed_name::{TypedNameDialog, TypedNameForm},
    },
};

/// Deleting a connection, audited as `web.wan_delete`.
const DELETE: Operation = Operation::write(&wan::DESCRIPTOR, "delete", "web.wan_delete");

/// The typed-name confirmation deleting `name` on `router` in `locale`.
fn delete_dialog(router: &str, name: &str, locale: Locale) -> TypedNameDialog {
    TypedNameDialog::new(
        fragment_shell(locale),
        format!("/ui/r/{router}/internet/delete"),
        name,
        (
            keys::WEB_INTERNET_DELETE_TITLE,
            keys::WEB_INTERNET_DELETE_TEXT,
        ),
    )
}

/// `GET /ui/r/{router}/internet/delete?name=`: the Delete confirmation.
///
/// # Errors
///
/// Answers 404 for a missing connection name, and what the kit answers when the router or
/// the permission is missing.
pub(crate) async fn delete_confirmation(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let name = Params::new(query, Vec::new()).object("name")?;
    let action = DELETE.open(&state, &user, &router).await?;
    Ok(respond::in_dialog(errors::render(&delete_dialog(
        &router,
        name.as_str(),
        action.locale(),
    ))))
}

/// `POST /ui/r/{router}/internet/delete`: deletes the connection once its name was typed.
///
/// # Errors
///
/// Answers the dialog with its error (422) when the typed name does not match, 404 for a
/// name that is not an interface name, and what the kit answers when the router or the
/// permission is missing.
pub(crate) async fn delete(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<TypedNameForm>,
) -> Result<Response, Answer> {
    let name = ObjectName::try_from(form.name().to_owned()).map_err(|_error| missing())?;
    let action = DELETE.open(&state, &user, &router).await?;
    if !form.confirmed() {
        action.abandon("validation_failed").await;
        let mut dialog = delete_dialog(&router, name.as_str(), user.locale());
        dialog.set_error(tr(user.locale(), keys::WEB_ADMIN_ERROR_CONFIRM, None));
        return Err(respond::in_dialog(respond::unprocessable(&dialog)).into());
    }
    let domain = action.context().await?;
    let change = wan::plan_delete(&domain, &name)
        .and_then(|operation| Ok((wan::change_request(&name, &operation)?, operation.risk)));
    let call = Call::new(&state, &user, &router, &headers).on(Tab::Internet);
    let answered = finish(call, action, Planned::new(domain, change)).await;
    Ok(respond::retarget(answered, "#page-outcome"))
}
