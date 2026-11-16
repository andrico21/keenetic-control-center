//! Delete on the internet page: the connection leaves the running configuration once its
//! name was typed.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_catalog::Risk;
use kcc_domain::wan;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_rci::ObjectName;

use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    net_change::refreshed,
    net_pages::{Call, Tab},
    page_kit::{
        action::Operation,
        change::Change,
        confirm::{Dialog, Resubmit, TypedNameForm},
        request::{Params, missing},
        respond,
        respond::Answer,
        submit::{self, Invalid, Planned, Submission},
    },
};

/// Deleting a connection, audited as `web.wan_delete`.
const DELETE: Operation = Operation::write(&wan::DESCRIPTOR, "delete", "web.wan_delete");

/// The typed-name confirmation deleting `name` on `router` in `locale`.
fn delete_dialog(router: &str, name: &str, locale: Locale) -> Dialog {
    Dialog::typed_name(
        locale,
        format!("/ui/r/{router}/internet/delete"),
        name,
        (
            keys::WEB_INTERNET_DELETE_TITLE,
            keys::WEB_INTERNET_DELETE_TEXT,
        ),
    )
}

/// The typed-name confirmation, as the form of the deletion: a mistyped name is shown
/// in it.
struct DeleteForm(Dialog);

impl submit::Form for DeleteForm {
    fn answer_invalid(self, invalid: Invalid, locale: Locale) -> Response {
        let Self(mut dialog) = self;
        for (_field, rule) in invalid.into_findings() {
            dialog.set_error(tr(locale, rule, None));
        }
        respond::in_dialog(respond::unprocessable(&dialog))
    }
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
    let dialog = DeleteForm(delete_dialog(&router, name.as_str(), action.locale()));
    let params = Params::of(Vec::new());
    let call = Call::new(&state, &user, &router, &headers).on(Tab::Internet);
    let resubmit = Resubmit::new(format!("/ui/r/{router}/internet/delete"), "#page-outcome");
    Ok(Submission::new(action, &params, dialog, resubmit)
        .confirmed_by_page(Risk::Destructive)
        .landing_in("#page-outcome")
        .submit(
            |_params| {
                form.confirmed()
                    .ok_or_else(|| Invalid::at("confirm_name", keys::WEB_ADMIN_ERROR_CONFIRM))
            },
            async |(), domain| {
                let operation = wan::plan_delete(domain, &name).await?;
                let request = wan::change_request(&name, &operation)?;
                Ok(Planned::of(&[operation], Change::Cli(request)))
            },
            async |domain| refreshed(call, domain).await,
        )
        .await)
}
