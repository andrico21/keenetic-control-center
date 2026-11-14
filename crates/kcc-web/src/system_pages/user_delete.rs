//! Deleting a router account.
//!
//! The account's name is typed into the kit's typed-name dialog, which also confirms the
//! management change; the deletion then runs inside the router's fail-safe timer. The
//! account kcc signs in with is refused before anything is sent.

use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};
use kcc_domain::router_users;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::{
    shared::{profile_login, value},
    user_forms::{find, refusal_message},
    users::Viewer,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page_kit::{
        action::Operation,
        change::Change,
        confirm::{Confirmation, Resubmit},
        context::fragment_shell,
        request::{missing, shown_query},
        respond::{self, Answer, changed},
        typed_name::{TypedNameDialog, TypedNameForm},
    },
};

/// Deleting an account, audited as `web.router_user_delete`.
const DELETE: Operation = Operation::write(
    &router_users::DESCRIPTOR,
    "delete",
    "web.router_user_delete",
);

/// The typed-name dialog deleting the account `name` of `router`.
fn confirmation(router: &str, locale: Locale, name: &str) -> TypedNameDialog {
    TypedNameDialog::new(
        fragment_shell(locale),
        format!("/ui/r/{router}/system/users/delete"),
        name,
        (
            keys::WEB_SYSTEM_USERS_DELETE_TITLE,
            keys::WEB_SYSTEM_USERS_DELETE_TEXT,
        ),
    )
}

/// `GET /ui/r/{router}/system/users/delete?name=`: the typed-name dialog.
///
/// # Errors
///
/// Answers 404 for an unknown account, and what the kit answers when the router or the
/// permission is missing.
pub(crate) async fn delete_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(query): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let action = DELETE.open(&state, &user, &router).await?;
    let domain = action.context().await?;
    let name = value(&query, "name").unwrap_or_default();
    let account = find(&domain, name).await.ok_or_else(missing)?;
    Ok(errors::render(&confirmation(
        &router,
        action.locale(),
        account.name(),
    )))
}

/// `POST /ui/r/{router}/system/users/delete`: deletes the account once its name was
/// typed; a mismatch or a refusal comes back into the dialog, the outcome lands in the
/// page's outcome region.
///
/// # Errors
///
/// Answers the dialog with its error (422), and what the kit answers when the router or
/// the permission is missing.
pub(crate) async fn delete(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<TypedNameForm>,
) -> Result<Response, Answer> {
    let action = DELETE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let mut dialog = confirmation(&router, locale, form.name());
    if !form.confirmed() {
        action.abandon("confirmation_mismatch").await;
        dialog.set_error(tr(locale, keys::WEB_ADMIN_ERROR_CONFIRM, None));
        return Err(respond::unprocessable(&dialog).into());
    }
    let domain = action.context().await?;
    let login = profile_login(&state, &user, &router)
        .await
        .unwrap_or_default();
    let planned = router_users::plan_delete(&domain, form.name(), &login)
        .and_then(|operation| Ok((router_users::change_request(&operation)?, operation.risk)));
    let (request, risk) = match planned {
        Ok(found) => found,
        Err(error) => {
            action.abandon("validation_failed").await;
            dialog.set_error(refusal_message(&error, locale));
            return Err(respond::unprocessable(&dialog).into());
        }
    };
    let typed = Confirmation::new(Some("yes"), None);
    let resubmit = Resubmit::new(
        format!("/ui/r/{router}/system/users/delete"),
        "#page-outcome",
    );
    if let Some(prompt) = action.confirm(risk, &typed, resubmit) {
        return Ok(prompt);
    }
    let outcome = action.run(risk, Change::Cli(request)).await;
    let refreshed = if outcome.succeeded() {
        Viewer::new(&user, &router, shown_query(&headers))
            .refreshed(&state, &domain)
            .await
    } else {
        None
    };
    Ok(respond::retarget(
        changed(outcome, refreshed, None, locale),
        "#page-outcome",
    ))
}
