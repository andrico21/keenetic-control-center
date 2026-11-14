//! Deleting a router account.
//!
//! The account's name is typed into the kit's typed-name dialog, which also confirms the
//! management change; the deletion then runs inside the router's fail-safe timer. The
//! account kcc signs in with is refused before anything is sent.

use core::future::ready;

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
        confirm::{Dialog, Resubmit, TypedNameForm},
        outcome::Failure,
        request::{Params, missing, shown_query},
        respond::{self, Answer},
        submit::{self, Invalid, Planned, Submission, unplanned::Unplanned},
    },
};

/// Deleting an account, audited as `web.router_user_delete`.
const DELETE: Operation = Operation::write(
    &router_users::DESCRIPTOR,
    "delete",
    "web.router_user_delete",
);

/// The typed-name dialog deleting the account `name` of `router`.
fn confirmation(router: &str, locale: Locale, name: &str) -> Dialog {
    Dialog::typed_name(
        locale,
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
    let login = profile_login(&state, &user, &router)
        .await
        .unwrap_or_default();
    let typed = Params::of(vec![("confirm".to_owned(), "yes".to_owned())]);
    let resubmit = Resubmit::new(
        format!("/ui/r/{router}/system/users/delete"),
        "#page-outcome",
    );
    let viewer = Viewer::new(&user, &router, shown_query(&headers));
    Ok(Submission::new(action, &typed, Deleting(dialog))
        .confirming_planned(resubmit)
        .landing_run_in("#page-outcome")
        .submit(
            |_typed| Ok(()),
            async |(), ctx| {
                let operation = router_users::plan_delete(ctx, form.name(), &login)?;
                let request = router_users::change_request(&operation)?;
                Ok(Planned::of(&[operation], Change::Cli(request)))
            },
            async |ctx| viewer.refreshed(&state, ctx).await,
        )
        .await)
}

/// The typed-name dialog as the form of a delete: a refusal comes back into it.
struct Deleting(Dialog);

impl submit::Form for Deleting {
    fn answer_invalid(self, _invalid: Invalid, _locale: Locale) -> Response {
        respond::unprocessable(&self.0)
    }

    fn answer_refused(mut self, failure: Failure, _locale: Locale) -> Response {
        self.0.set_error(failure.message().to_owned());
        respond::unprocessable(&self.0)
    }

    fn answer_unplanned(
        mut self,
        unplanned: Unplanned<'_>,
        locale: Locale,
    ) -> impl Future<Output = Response> {
        self.0.set_error(refusal_message(unplanned.error(), locale));
        ready(respond::unprocessable(&self.0))
    }
}
